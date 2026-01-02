//! recursor-bootstrap
//!
//! Bootstrap helper for:
//!  - Root hints (IANA "named.root")
//!  - DNSSEC root trust anchor file ("trusted-key.key") for Hickory Recursor
//!
//! References:
//!  - IANA Root Hints (named.root): https://www.internic.net/domain/named.root
//!  - IANA Trust Anchors (root-anchors.xml, signatures, cert bundle): https://www.iana.org/dnssec/files
//!  - Hickory Recursor manual (root.hints + trusted-key.key): https://hickory-dns.org/book/hickory/recursive_resolver.html
//!  - RFC 9718 (trust anchor publication): https://www.rfc-editor.org/rfc/rfc9718.html
//!
//! NOTE: Hickory's manual shows `trusted-key.key` as *DNSKEY* lines copied from a DNS response.
//! This tool generates that file by querying `DNSKEY .` from a configurable resolver (default 1.1.1.1:53).
//!
//! Build deps you likely need in Cargo.toml:
//!   clap = { version = "4", features = ["derive"] }
//!   anyhow = "1"
//!   tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
//!   reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "gzip"] }
//!   quick-xml = "0.31"
//!   hickory-resolver = "0.25.2"
//!   hickory-proto = "0.25.2"

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::xfer::Protocol;
use hickory_resolver::config::{
    NameServerConfig, NameServerConfigGroup, ResolverConfig, ResolverOpts,
};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;
use quick_xml::events::Event;
use quick_xml::Reader;
use std::fs;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

const IANA_NAMED_ROOT_URL: &str = "https://www.internic.net/domain/named.root";
const IANA_ROOT_ANCHORS_INDEX_URL: &str = "https://data.iana.org/root-anchors/"; // directory listing
const IANA_ROOT_ANCHORS_XML_URL: &str = "https://data.iana.org/root-anchors/root-anchors.xml";

#[derive(Parser, Debug)]
#[command(
    name = "recursor-bootstrap",
    version,
    about = "Bootstrap roots + DNSSEC trust anchor for a Hickory-based recursor"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Download IANA root hints file (named.root)
    FetchRoots {
        /// Output file path (e.g. /etc/rustdns/root.hints)
        #[arg(long)]
        out: PathBuf,

        /// Optional override URL (default: internic named.root)
        #[arg(long, default_value = IANA_NAMED_ROOT_URL)]
        url: String,
    },

    /// Extract root server IPs from a named.root-style file.
    ///
    /// This is useful if your config uses `roots = ["198.41.0.4", ...]` instead of a root.hints path.
    ExtractRootIps {
        /// Input root hints file (named.root / root.hints)
        #[arg(long)]
        input: PathBuf,

        /// Write as a TOML array into this file (otherwise prints to stdout)
        #[arg(long)]
        out_toml: Option<PathBuf>,
    },

    /// Generate Hickory trusted-key.key by querying `DNSKEY .` from a resolver
    ///
    /// Default resolver is 1.1.1.1:53 (Cloudflare). You can set multiple --resolver flags.
    MakeTrustAnchor {
        /// Output file path (e.g. /etc/rustdns/trusted-key.key)
        #[arg(long)]
        out: PathBuf,

        /// Resolver(s) to query for DNSKEY . (IP[:PORT] or [IPv6]:PORT). Can repeat.
        #[arg(long = "resolver")]
        resolvers: Vec<String>,

        /// Also fetch and parse the IANA root-anchors.xml (for diagnostics/logging).
        /// This does NOT replace the DNS query output format that Hickory expects.
        #[arg(long)]
        inspect_iana_xml: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::FetchRoots { out, url } => fetch_roots(&url, &out).await,
        Cmd::ExtractRootIps { input, out_toml } => extract_root_ips(&input, out_toml.as_deref()),
        Cmd::MakeTrustAnchor {
            out,
            resolvers,
            inspect_iana_xml,
        } => {
            if inspect_iana_xml {
                if let Err(e) = inspect_root_anchors_xml().await {
                    eprintln!(
                        "WARN: no pude inspeccionar root-anchors.xml ({e:#}). Fuente: {IANA_ROOT_ANCHORS_INDEX_URL}"
                    );
                }
            }
            make_trusted_key(&out, &resolvers).await
        }
    }
}

async fn fetch_roots(url: &str, out: &Path) -> Result<()> {
    let client = reqwest::Client::builder()
        .user_agent("recursor-bootstrap/1.0")
        .build()
        .context("reqwest client")?;

    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("descargando root hints desde {url}"))?;

    if !resp.status().is_success() {
        return Err(anyhow!("HTTP {} al descargar {}", resp.status(), url));
    }

    let body = resp.bytes().await.context("leyendo respuesta")?;
    write_atomic(out, &body)?;
    eprintln!("OK: roots guardados en {}", out.display());
    Ok(())
}

fn extract_root_ips(input: &Path, out_toml: Option<&Path>) -> Result<()> {
    let txt = fs::read_to_string(input).with_context(|| format!("leyendo {}", input.display()))?;

    // Parse conservatively for:
    // "<name> <ttl> A <ipv4>" or "<name> <ttl> AAAA <ipv6>"
    let mut ips: Vec<IpAddr> = Vec::new();

    for line in txt.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        let line = line.split(';').next().unwrap_or("").trim();

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let rtype = parts[2].to_ascii_uppercase();
        if rtype == "A" || rtype == "AAAA" {
            if let Ok(ip) = parts[3].parse::<IpAddr>() {
                ips.push(ip);
            }
        }
    }

    ips.sort();
    ips.dedup();

    if ips.is_empty() {
        return Err(anyhow!(
            "no pude extraer IPs desde {} (¿formato inesperado?)",
            input.display()
        ));
    }

    let toml = format!(
        "roots = [{}]\n",
        ips.iter()
            .map(|ip| format!("{:?}", ip.to_string()))
            .collect::<Vec<_>>()
            .join(", ")
    );

    match out_toml {
        Some(path) => {
            write_atomic(path, toml.as_bytes())?;
            eprintln!("OK: TOML escrito en {}", path.display());
        }
        None => {
            print!("{toml}");
        }
    }

    Ok(())
}

async fn make_trusted_key(out: &Path, resolvers: &[String]) -> Result<()> {
    let resolvers = if resolvers.is_empty() {
        vec!["1.1.1.1:53".to_string()]
    } else {
        resolvers.to_vec()
    };

    let mut last_err: Option<anyhow::Error> = None;
    for r in resolvers {
        match query_dnskey_root(&r).await {
            Ok(dnskey_lines) => {
                write_atomic(out, dnskey_lines.as_bytes())?;
                eprintln!("OK: trusted-key.key escrito en {}", out.display());
                return Ok(());
            }
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow!("falló MakeTrustAnchor por razón desconocida")))
}

// UDP -> si truncado -> TCP
async fn query_dnskey_root(resolver: &str) -> Result<String> {
    let resolver_str = resolver.to_string();
    let sa = parse_socket_addr(resolver)
        .with_context(|| format!("resolver inválido: {resolver_str}"))?;

    match query_dnskey_with_protocol(sa, Protocol::Udp).await {
        Ok(s) => Ok(s),
        Err(e) => {
            let msg = format!("{e:#}").to_lowercase();
            if msg.contains("truncated") || msg.contains("truncat") {
                return query_dnskey_with_protocol(sa, Protocol::Tcp)
                    .await
                    .with_context(|| {
                        format!("fallback TCP luego de truncation usando {resolver_str}")
                    });
            }
            Err(e).with_context(|| format!("lookup DNSKEY . (UDP) usando {resolver_str}"))
        }
    }
}

async fn query_dnskey_with_protocol(sa: SocketAddr, proto: Protocol) -> Result<String> {
    let mut ns_group = NameServerConfigGroup::new();
    ns_group.push(NameServerConfig {
        socket_addr: sa,
        protocol: proto,
        tls_dns_name: None,
        trust_negative_responses: true,
        bind_addr: None,
        http_endpoint: None,
    });

    let cfg = ResolverConfig::from_parts(None, vec![], ns_group);
    let _opts = ResolverOpts::default();

    let resolver: TokioResolver =
        TokioResolver::builder_with_config(cfg, TokioConnectionProvider::default()).build();

    let name = Name::from_str(".").expect("root name");
    let resp = resolver
        .lookup(name, RecordType::DNSKEY)
        .await
        .context("lookup DNSKEY .")?;

    let mut out = String::new();
    for rec in resp.record_iter() {
        if rec.record_type() != RecordType::DNSKEY {
            continue;
        }
        let ttl = rec.ttl();
        let rdata = rec.data();
        let rdata_txt = format!("{rdata}");
        out.push_str(&format!(". {ttl} IN {rdata_txt}\n"));
    }

    if out.trim().is_empty() {
        return Err(anyhow!("respuesta sin DNSKEY en ANSWER"));
    }

    Ok(out)
}

fn parse_socket_addr(s: &str) -> Result<SocketAddr> {
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Ok(sa);
    }
    let ip = s
        .parse::<IpAddr>()
        .map_err(|e| anyhow!("IP inválida: {s} ({e})"))?;
    Ok(SocketAddr::new(ip, 53))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creando dir {}", parent.display()))?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f =
            fs::File::create(&tmp).with_context(|| format!("creando tmp {}", tmp.display()))?;
        f.write_all(bytes).context("escribiendo tmp")?;
        f.sync_all().ok();
    }
    fs::rename(&tmp, path)
        .with_context(|| format!("renombrando {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

async fn inspect_root_anchors_xml() -> Result<()> {
    let client = reqwest::Client::builder()
        .user_agent("recursor-bootstrap/1.0")
        .build()
        .context("reqwest client")?;

    let resp = client
        .get(IANA_ROOT_ANCHORS_XML_URL)
        .send()
        .await
        .with_context(|| format!("descargando {IANA_ROOT_ANCHORS_XML_URL}"))?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "HTTP {} al descargar {}",
            resp.status(),
            IANA_ROOT_ANCHORS_XML_URL
        ));
    }

    let body = resp.bytes().await.context("leyendo xml")?;

    let mut reader = Reader::from_reader(body.as_ref());
    reader.trim_text(true);

    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => break,
            Err(e) => return Err(anyhow!("xml parse error: {e}")),
            _ => {}
        }
        buf.clear();
    }

    Ok(())
}

