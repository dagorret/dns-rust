// Integration tests for DNS server.
// - Forwarder mode (with upstreams): deterministic wire tests via `dig`.
// - Iterative recursor mode (no upstreams): real-network tests (ignored by default).
//
// Run default (forwarder) tests:
//   cargo test --test dns_integration -- --nocapture
//
// Run iterative recursor tests (requires Internet + UDP/53):
//   cargo test --test dns_integration -- --nocapture --ignored

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
    recursor_engine,
    zones,
};

fn write_test_config_forwarder(dir: &TempDir) -> anyhow::Result<PathBuf> {
    let cfg_path = dir.path().join("test_forwarder.toml");
    let zones_dir = dir.path().join("zones");
    std::fs::create_dir_all(&zones_dir)?;

    // upstreams parse as SocketAddr => "IP:PORT"
    let toml = r#"
listen_udp = "127.0.0.1:0"
listen_tcp = "127.0.0.1:0"

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

# AppConfig requires a full [recursor] block even in forwarder mode
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

fn write_test_config_recursor(dir: &TempDir) -> anyhow::Result<PathBuf> {
    let cfg_path = dir.path().join("test_recursor.toml");
    let zones_dir = dir.path().join("zones");
    std::fs::create_dir_all(&zones_dir)?;

    // IMPORTANT: In this project, `roots` are parsed as IPs (no port).
    // The recursor will use port 53 internally.
    let toml = r#"
listen_udp = "127.0.0.1:0"
listen_tcp = "127.0.0.1:0"

roots = [
  "198.41.0.4",
  "199.9.14.201",
  "192.33.4.12",
  "199.7.91.13",
  "192.203.230.10",
  "192.5.5.241",
  "192.112.36.4",
  "198.97.190.53",
  "192.36.148.17",
  "192.58.128.30",
  "193.0.14.129",
  "199.7.83.42",
  "202.12.27.33"
]

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

    let forwarder = if let Some(ups) = cfg.upstreams.clone() {
        Some(forwarder::build_forwarder(&ups).await?)
    } else {
        None
    };

    let recursor = if forwarder.is_none() {
        Some(recursor_engine::RecursorEngine::new(&cfg).await?)
    } else {
        None
    };

    let handler = DnsHandler::new(cfg, zones, filters, caches, forwarder, recursor);

    // UDP on random port
    let udp_socket =
        UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?;
    let udp_addr = udp_socket.local_addr()?;

    // TCP on a different random port
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

fn dig_udp(server: SocketAddr, name: &str, rtype: &str, time_s: u32, tries: u32) -> anyhow::Result<String> {
    let out = std::process::Command::new("dig")
        .arg(format!("@{}", server.ip()))
        .arg("-p")
        .arg(server.port().to_string())
        .arg(name)
        .arg(rtype)
        .arg(format!("+time={}", time_s))
        .arg(format!("+tries={}", tries))
        .arg("+nocmd")
        .arg("+noquestion")
        .arg("+nostats")
        .output()?;

    anyhow::ensure!(out.status.success(), "dig UDP failed: {:?}", out.status);

    let mut s = String::new();
    s.push_str(&String::from_utf8_lossy(&out.stdout));
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok(s)
}

fn dig_udp_fast(server: SocketAddr, name: &str, rtype: &str) -> anyhow::Result<String> {
    dig_udp(server, name, rtype, 2, 1)
}

fn dig_udp_slow(server: SocketAddr, name: &str, rtype: &str) -> anyhow::Result<String> {
    // For iterative recursor: allow more time/retries.
    dig_udp(server, name, rtype, 5, 2)
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

    anyhow::ensure!(out.status.success(), "dig TCP failed: {:?}", out.status);

    let mut s = String::new();
    s.push_str(&String::from_utf8_lossy(&out.stdout));
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok(s)
}

fn dig_status(output: &str) -> Option<String> {
    for line in output.lines() {
        if let Some(idx) = line.find("status:") {
            let tail = &line[idx + "status:".len()..];
            return Some(tail.split(',').next()?.trim().to_string());
        }
    }
    None
}

fn dig_answer_count(output: &str) -> usize {
    output.lines().filter(|l| l.contains("\tIN\t")).count()
}

fn dig_has_ra(output: &str) -> bool {
    // dig prints: ;; flags: qr rd ra; QUERY: 1, ANSWER: ...
    output.lines().any(|l| l.contains("flags:") && l.contains(" ra"))
}

fn median_duration(mut xs: Vec<Duration>) -> Duration {
    xs.sort_unstable();
    xs[xs.len() / 2]
}

#[allow(dead_code)]
async fn measure_query_times_udp_fast(
    server: SocketAddr,
    name: &str,
    rtype: &str,
    reps: usize,
) -> anyhow::Result<Vec<Duration>> {
    let mut times = Vec::with_capacity(reps);
    for _ in 0..reps {
        let t = Instant::now();
        let out = dig_udp_fast(server, name, rtype)?;
        anyhow::ensure!(
            dig_status(&out).as_deref() == Some("NXDOMAIN") || dig_status(&out).as_deref() == Some("NOERROR"),
            "unexpected status in timing probe: {:?}\n{}",
            dig_status(&out),
            out
        );
        times.push(t.elapsed());
    }
    Ok(times)
}

async fn measure_query_times_udp_slow(
    server: SocketAddr,
    name: &str,
    rtype: &str,
    reps: usize,
) -> anyhow::Result<Vec<Duration>> {
    let mut times = Vec::with_capacity(reps);
    for _ in 0..reps {
        let t = Instant::now();
        let out = dig_udp_slow(server, name, rtype)?;
        anyhow::ensure!(
            dig_status(&out).as_deref() == Some("NOERROR"),
            "unexpected status in timing probe: {:?}\n{}",
            dig_status(&out),
            out
        );
        times.push(t.elapsed());
    }
    Ok(times)
}

//
// ========================
// FORWARDER (deterministic)
// ========================
//
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwarder_a_noerror() -> anyhow::Result<()> {
    let tmp = TempDir::new()?;
    let cfg_path = write_test_config_forwarder(&tmp)?;
    let ((udp_addr, _), _) = start_server_from_cfg(&cfg_path).await?;

    let out = dig_udp_fast(udp_addr, "google.com.", "A")?;
    assert_eq!(dig_status(&out).as_deref(), Some("NOERROR"));
    assert!(dig_answer_count(&out) > 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwarder_sets_ra_flag() -> anyhow::Result<()> {
    let tmp = TempDir::new()?;
    let cfg_path = write_test_config_forwarder(&tmp)?;
    let ((udp_addr, _), _) = start_server_from_cfg(&cfg_path).await?;

    let out = dig_udp_fast(udp_addr, "example.com.", "A")?;
    assert_eq!(dig_status(&out).as_deref(), Some("NOERROR"));
    assert!(dig_has_ra(&out), "expected RA flag in dig output:\n{out}");
    Ok(())
}


#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwarder_blocklist_refused() -> anyhow::Result<()> {
    let tmp = TempDir::new()?;
    let cfg_path = write_test_config_forwarder(&tmp)?;
    let ((udp_addr, _), _) = start_server_from_cfg(&cfg_path).await?;

    let out = dig_udp_fast(udp_addr, "ads.example.", "A")?;
    assert_eq!(dig_status(&out).as_deref(), Some("REFUSED"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwarder_cache_cold_vs_warm_positive() -> anyhow::Result<()> {
    let tmp = TempDir::new()?;
    let cfg_path = write_test_config_forwarder(&tmp)?;
    let ((udp_addr, _), _) = start_server_from_cfg(&cfg_path).await?;

    // Cold
    let t1 = Instant::now();
    let out1 = dig_udp_fast(udp_addr, "example.com.", "A")?;
    let cold = t1.elapsed();
    assert_eq!(dig_status(&out1).as_deref(), Some("NOERROR"));

    // Warm (median over multiple runs to reduce flakiness)
    let warm_times = measure_query_times_udp_slowish_forwarder(udp_addr, "example.com.", "A", 5).await?;
    let warm_med = median_duration(warm_times);

    assert!(
        warm_med < cold,
        "expected warm median < cold (cold={:?}, warm_med={:?})",
        cold,
        warm_med
    );
    Ok(())
}

async fn measure_query_times_udp_slowish_forwarder(
    server: SocketAddr,
    name: &str,
    rtype: &str,
    reps: usize,
) -> anyhow::Result<Vec<Duration>> {
    // Forwarder is typically fast; still, we measure multiple times and take median.
    let mut times = Vec::with_capacity(reps);
    for _ in 0..reps {
        let t = Instant::now();
        let out = dig_udp_fast(server, name, rtype)?;
        anyhow::ensure!(dig_status(&out).as_deref() == Some("NOERROR"));
        times.push(t.elapsed());
    }
    Ok(times)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwarder_resolves_aaaa_mx_txt() -> anyhow::Result<()> {
    let tmp = TempDir::new()?;
    let cfg_path = write_test_config_forwarder(&tmp)?;
    let ((udp_addr, _), _) = start_server_from_cfg(&cfg_path).await?;

    let out_aaaa = dig_udp_fast(udp_addr, "google.com.", "AAAA")?;
    assert_eq!(dig_status(&out_aaaa).as_deref(), Some("NOERROR"));
    assert!(dig_answer_count(&out_aaaa) > 0);

    let out_mx = dig_udp_fast(udp_addr, "gmail.com.", "MX")?;
    assert_eq!(dig_status(&out_mx).as_deref(), Some("NOERROR"));
    assert!(dig_answer_count(&out_mx) > 0);

    let out_txt = dig_udp_fast(udp_addr, "google.com.", "TXT")?;
    assert_eq!(dig_status(&out_txt).as_deref(), Some("NOERROR"));
    assert!(dig_answer_count(&out_txt) > 0);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwarder_tcp_noerror() -> anyhow::Result<()> {
    let tmp = TempDir::new()?;
    let cfg_path = write_test_config_forwarder(&tmp)?;
    let ((_, tcp_addr), _) = start_server_from_cfg(&cfg_path).await?;

    let out = dig_tcp(tcp_addr, "example.com.", "A")?;
    assert_eq!(dig_status(&out).as_deref(), Some("NOERROR"));
    assert!(dig_answer_count(&out) > 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwarder_nxdomain_and_negative_cache() -> anyhow::Result<()> {
    let tmp = TempDir::new()?;
    let cfg_path = write_test_config_forwarder(&tmp)?;
    let ((udp_addr, _), _) = start_server_from_cfg(&cfg_path).await?;

    let name = format!("no-such-name-{}-{}.invalid.", std::process::id(), 42u32);

    // Ensure NXDOMAIN
    let out = dig_udp_fast(udp_addr, &name, "A")?;
    assert_eq!(dig_status(&out).as_deref(), Some("NXDOMAIN"));
    assert_eq!(dig_answer_count(&out), 0);

    // Cold timing: first NXDOMAIN
    let t1 = Instant::now();
    let out1 = dig_udp_fast(udp_addr, &name, "A")?;
    let cold = t1.elapsed();
    assert_eq!(dig_status(&out1).as_deref(), Some("NXDOMAIN"));

    // Warm timing: median over multiple runs to reduce jitter
    let warm_times = measure_query_times_nxdomain(udp_addr, &name, "A", 7).await?;
    let warm_med = median_duration(warm_times);

    assert!(
        warm_med < cold,
        "expected negative-cache warm median < cold (cold={:?}, warm_med={:?})",
        cold,
        warm_med
    );
    Ok(())
}

async fn measure_query_times_nxdomain(
    server: SocketAddr,
    name: &str,
    rtype: &str,
    reps: usize,
) -> anyhow::Result<Vec<Duration>> {
    let mut times = Vec::with_capacity(reps);
    for _ in 0..reps {
        let t = Instant::now();
        let out = dig_udp_fast(server, name, rtype)?;
        anyhow::ensure!(dig_status(&out).as_deref() == Some("NXDOMAIN"));
        times.push(t.elapsed());
    }
    Ok(times)
}

//
// ========================
// RECURSOR ITERATIVE (real network) - ignored by default
// ========================
//
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn recursor_iterative_resolves_a() -> anyhow::Result<()> {
    let tmp = TempDir::new()?;
    let cfg_path = write_test_config_recursor(&tmp)?;
    let ((udp_addr, _), _) = start_server_from_cfg(&cfg_path).await?;

    let out = dig_udp_slow(udp_addr, "example.com.", "A")?;
    assert_eq!(dig_status(&out).as_deref(), Some("NOERROR"));
    assert!(dig_answer_count(&out) > 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn recursor_sets_ra_flag() -> anyhow::Result<()> {
    let tmp = TempDir::new()?;
    let cfg_path = write_test_config_recursor(&tmp)?;
    let ((udp_addr, _), _) = start_server_from_cfg(&cfg_path).await?;

    let out = dig_udp_slow(udp_addr, "example.com.", "A")?;
    assert_eq!(dig_status(&out).as_deref(), Some("NOERROR"));
    assert!(dig_has_ra(&out), "expected RA flag in dig output:\n{out}");
    Ok(())
}


#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn recursor_iterative_resolves_aaaa() -> anyhow::Result<()> {
    let tmp = TempDir::new()?;
    let cfg_path = write_test_config_recursor(&tmp)?;
    let ((udp_addr, _), _) = start_server_from_cfg(&cfg_path).await?;

    let out = dig_udp_slow(udp_addr, "google.com.", "AAAA")?;
    assert_eq!(dig_status(&out).as_deref(), Some("NOERROR"));
    assert!(dig_answer_count(&out) > 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn recursor_iterative_cache_cold_vs_warm() -> anyhow::Result<()> {
    let tmp = TempDir::new()?;
    let cfg_path = write_test_config_recursor(&tmp)?;
    let ((udp_addr, _), _) = start_server_from_cfg(&cfg_path).await?;

    // Use a relatively stable domain for iterative recursion.
    let domain = "example.com.";

    // Cold: one full resolution
    let t1 = Instant::now();
    let out1 = dig_udp_slow(udp_addr, domain, "A")?;
    let cold = t1.elapsed();
    assert_eq!(dig_status(&out1).as_deref(), Some("NOERROR"));
    assert!(dig_answer_count(&out1) > 0);

    // Warm: median over multiple runs (still with slow dig settings)
    let warm_times = measure_query_times_udp_slow(udp_addr, domain, "A", 5).await?;
    let warm_med = median_duration(warm_times);

    assert!(
        warm_med < cold,
        "expected warm median < cold (cold={:?}, warm_med={:?})",
        cold,
        warm_med
    );
    Ok(())
}
