use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use tempfile::TempDir;
use tokio::net::UdpSocket;

use rust_dns_recursor::{
    cache,
    config::AppConfig,
    filters,
    forwarder,
    handler::DnsHandler,
    zones,
};

fn write_test_config(dir: &TempDir) -> anyhow::Result<PathBuf> {
    let cfg_path = dir.path().join("test.toml");
    let zones_dir = dir.path().join("zones");
    std::fs::create_dir_all(&zones_dir)?;

    // Nota:
    // - upstreams se parsea como SocketAddr => "IP:PUERTO"
    // - AppConfig exige que exista [recursor] completo aunque estemos en modo forwarder.
    let toml = r#"
listen_udp = "127.0.0.1:0"
listen_tcp = "127.0.0.1:0"

# Modo FORWARDER (SocketAddr => IP:PUERTO)
upstreams = ["1.1.1.1:53"]

[zones]
zones_dir = "zones"

[filters]
allowlist_domains = []
blocklist_domains = ["ads.example", "tracking.example"]
deny_nets = [
  "127.0.0.0/8",
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "::1/128",
  "fc00::/7",
  "::/0"
]
allow_nets = []

[cache]
answer_cache_size = 20000
negative_cache_size = 5000
min_ttl = 5
max_ttl = 86400
negative_ttl = 300

# AppConfig exige estos campos aunque no usemos recursor en forwarder
[recursor]
ns_cache_size = 4096
record_cache_size = 32768
recursion_limit = 32
ns_recursion_limit = 16
timeout_ms = 1500
attempts = 2
case_randomization = true
dnssec = "off"
"#;

    std::fs::write(&cfg_path, toml)?;
    Ok(cfg_path)
}

async fn start_server_from_cfg(
    cfg_path: &PathBuf,
) -> anyhow::Result<((SocketAddr, SocketAddr), tokio::task::JoinHandle<anyhow::Result<()>>)> {
    let cfg = AppConfig::load(cfg_path.to_str().unwrap())?;

    let zones = zones::ZoneStore::load_dir(&cfg.zones.zones_dir)?;
    let filters = filters::Filters::from_config(&cfg.filters)?;
    let caches = cache::DnsCaches::new(&cfg.cache);

    let ups = cfg
        .upstreams
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("test: falta upstreams en config"))?;

    let fwd = forwarder::build_forwarder(ups).await?;
    let handler = DnsHandler::new(cfg, zones, filters, caches, Some(fwd), None);

    // UDP en puerto aleatorio
    let udp_socket =
        UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?;
    let udp_addr = udp_socket.local_addr()?;

    // TCP también en puerto aleatorio (DISTINTO al de UDP)
    let tcp_listener =
        tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?;
    let tcp_addr = tcp_listener.local_addr()?;

    let join = tokio::spawn(async move {
        use hickory_server::ServerFuture;

        let mut server = ServerFuture::new(handler);
        server.register_socket(udp_socket);
        server.register_listener(tcp_listener, Duration::from_secs(10));
        server.block_until_done().await?;
        Ok(())
    });

    Ok(((udp_addr, tcp_addr), join))
}

fn dig_udp(server: SocketAddr, name: &str, rtype: &str) -> anyhow::Result<String> {
    // OJO: según flags/versión, parte del header puede ir por stderr.
    let out = std::process::Command::new("dig")
        .arg(format!("@{}", server.ip()))
        .arg("-p")
        .arg(server.port().to_string())
        .arg(name)
        .arg(rtype)
        .arg("+time=2")
        .arg("+tries=1")
        .arg("+nocmd")
        .arg("+noquestion")
        .arg("+nostats")
        .output()?;

    anyhow::ensure!(out.status.success(), "dig UDP falló: {:?}", out.status);

    let mut s = String::new();
    s.push_str(&String::from_utf8_lossy(&out.stdout));
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok(s)
}

fn dig_tcp(server: SocketAddr, name: &str, rtype: &str) -> anyhow::Result<String> {
    let out = std::process::Command::new("dig")
        .arg(format!("@{}", server.ip()))
        .arg("-p")
        .arg(server.port().to_string())
        .arg("+tcp")
        .arg(name)
        .arg(rtype)
        .arg("+time=2")
        .arg("+tries=1")
        .arg("+nocmd")
        .arg("+noquestion")
        .arg("+nostats")
        .output()?;

    anyhow::ensure!(out.status.success(), "dig TCP falló: {:?}", out.status);

    let mut s = String::new();
    s.push_str(&String::from_utf8_lossy(&out.stdout));
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok(s)
}

fn dig_status(output: &str) -> Option<String> {
    // Busca "status: NOERROR" dentro del header
    for line in output.lines() {
        if line.contains("status:") {
            if let Some(idx) = line.find("status:") {
                let tail = &line[idx + "status:".len()..];
                return Some(tail.split(',').next()?.trim().to_string());
            }
        }
    }
    None
}

fn dig_answer_count(output: &str) -> usize {
    // Cuenta RR en la salida (dig imprime líneas con "\tIN\t...")
    output.lines().filter(|l| l.contains("\tIN\t")).count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwarder_a_noerror() -> anyhow::Result<()> {
    let tmp = TempDir::new()?;
    let cfg_path = write_test_config(&tmp)?;
    let ((udp_addr, _tcp_addr), _) = start_server_from_cfg(&cfg_path).await?;

    let out = dig_udp(udp_addr, "google.com.", "A")?;
    let status = dig_status(&out);

    if status.is_none() {
        eprintln!("---- dig output (A) ----\n{out}\n------------------------");
    }

    assert_eq!(status.as_deref(), Some("NOERROR"));
    assert!(dig_answer_count(&out) > 0);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwarder_blocklist_refused() -> anyhow::Result<()> {
    let tmp = TempDir::new()?;
    let cfg_path = write_test_config(&tmp)?;
    let ((udp_addr, _tcp_addr), _) = start_server_from_cfg(&cfg_path).await?;

    let out = dig_udp(udp_addr, "ads.example.", "A")?;
    let status = dig_status(&out);

    if status.is_none() {
        eprintln!("---- dig output (blocklist) ----\n{out}\n-------------------------------");
    }

    assert_eq!(status.as_deref(), Some("REFUSED"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwarder_cache_cold_vs_warm_positive() -> anyhow::Result<()> {
    let tmp = TempDir::new()?;
    let cfg_path = write_test_config(&tmp)?;
    let ((udp_addr, _tcp_addr), _) = start_server_from_cfg(&cfg_path).await?;

    // Cold
    let t1 = Instant::now();
    let out1 = dig_udp(udp_addr, "example.com.", "A")?;
    let cold = t1.elapsed();
    assert_eq!(dig_status(&out1).as_deref(), Some("NOERROR"));
    assert!(dig_answer_count(&out1) > 0);

    // Warm
    let t2 = Instant::now();
    let out2 = dig_udp(udp_addr, "example.com.", "A")?;
    let warm = t2.elapsed();
    assert_eq!(dig_status(&out2).as_deref(), Some("NOERROR"));
    assert!(dig_answer_count(&out2) > 0);

    assert!(
        warm < cold,
        "esperaba warm < cold (cold={:?}, warm={:?})",
        cold,
        warm
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwarder_resolves_aaaa_mx_txt() -> anyhow::Result<()> {
    let tmp = TempDir::new()?;
    let cfg_path = write_test_config(&tmp)?;
    let ((udp_addr, _tcp_addr), _) = start_server_from_cfg(&cfg_path).await?;

    // AAAA
    let out_aaaa = dig_udp(udp_addr, "google.com.", "AAAA")?;
    assert_eq!(dig_status(&out_aaaa).as_deref(), Some("NOERROR"));
    assert!(dig_answer_count(&out_aaaa) > 0);

    // MX
    let out_mx = dig_udp(udp_addr, "gmail.com.", "MX")?;
    assert_eq!(dig_status(&out_mx).as_deref(), Some("NOERROR"));
    assert!(dig_answer_count(&out_mx) > 0);

    // TXT
    let out_txt = dig_udp(udp_addr, "google.com.", "TXT")?;
    assert_eq!(dig_status(&out_txt).as_deref(), Some("NOERROR"));
    assert!(dig_answer_count(&out_txt) > 0);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwarder_tcp_noerror() -> anyhow::Result<()> {
    let tmp = TempDir::new()?;
    let cfg_path = write_test_config(&tmp)?;
    let ((_udp_addr, tcp_addr), _) = start_server_from_cfg(&cfg_path).await?;

    let out = dig_tcp(tcp_addr, "example.com.", "A")?;
    let status = dig_status(&out);
    if status.is_none() {
        eprintln!("---- dig output (TCP) ----\n{out}\n--------------------------");
    }

    assert_eq!(status.as_deref(), Some("NOERROR"));
    assert!(dig_answer_count(&out) > 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwarder_nxdomain_and_negative_cache() -> anyhow::Result<()> {
    let tmp = TempDir::new()?;
    let cfg_path = write_test_config(&tmp)?;
    let ((udp_addr, _tcp_addr), _) = start_server_from_cfg(&cfg_path).await?;

    // Usamos un nombre aleatorio para minimizar chance de existir.
    //let name = format!("no-existe-{}-{}.example.com.", std::process::id(), 123456u32);
    let name = format!("no-existe-{}-{}.invalid.", std::process::id(), 123456u32);


    // Cold (NXDOMAIN)
    let t1 = Instant::now();
    let out1 = dig_udp(udp_addr, &name, "A")?;
    let cold = t1.elapsed();
    assert_eq!(dig_status(&out1).as_deref(), Some("NXDOMAIN"));
    assert_eq!(dig_answer_count(&out1), 0);

    // Warm (NXDOMAIN) - debería pegar a caché negativa
    let t2 = Instant::now();
    let out2 = dig_udp(udp_addr, &name, "A")?;
    let warm = t2.elapsed();
    assert_eq!(dig_status(&out2).as_deref(), Some("NXDOMAIN"));
    assert_eq!(dig_answer_count(&out2), 0);

    assert!(
        warm < cold,
        "esperaba warm < cold en caché negativa (cold={:?}, warm={:?})",
        cold,
        warm
    );

    Ok(())
}
