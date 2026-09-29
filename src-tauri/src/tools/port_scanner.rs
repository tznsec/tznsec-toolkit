use serde_json::json;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

const MAX_PORTS: usize = 4096;
const CONCURRENCY: usize = 256;
const TIMEOUT_MS: u64 = 800;

fn parse_ports(spec: Option<&str>) -> Result<Vec<u16>, String> {
    let ports = match spec {
        None => (1..=1024).collect::<Vec<u16>>(),
        Some(s) if s.trim().is_empty() => (1..=1024).collect::<Vec<u16>>(),
        Some(s) => {
            let mut out = Vec::new();
            for part in s.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                if let Some((a, b)) = part.split_once('-') {
                    let a: u16 = a.trim().parse().map_err(|_| format!("zły zakres: {}", part))?;
                    let b: u16 = b.trim().parse().map_err(|_| format!("zły zakres: {}", part))?;
                    if a > b || b == 0 {
                        return Err(format!("zakres poza 1-65535: {}", part));
                    }
                    out.extend(a..=b);
                } else {
                    let p: u16 = part.parse().map_err(|_| format!("zły port: {}", part))?;
                    if p == 0 {
                        return Err("port 0 jest nieprawidłowy".into());
                    }
                    out.push(p);
                }
            }
            out
        }
    };

    if ports.is_empty() {
        return Err("nie podano żadnych portów".into());
    }
    if ports.len() > MAX_PORTS {
        return Err(format!("maksymalnie {} portów naraz", MAX_PORTS));
    }
    Ok(ports)
}

fn service_name(port: u16) -> Option<&'static str> {
    Some(match port {
        20 => "ftp-data", 21 => "ftp", 22 => "ssh", 23 => "telnet", 25 => "smtp",
        53 => "dns", 67 | 68 => "dhcp", 69 => "tftp", 80 => "http", 110 => "pop3",
        111 => "rpcbind", 123 => "ntp", 135 => "msrpc", 139 => "netbios-ssn",
        143 => "imap", 161 => "snmp", 389 => "ldap", 443 => "https", 445 => "smb",
        465 => "smtps", 587 => "submission", 636 => "ldaps", 993 => "imaps",
        995 => "pop3s", 1433 => "mssql", 1521 => "oracle", 1723 => "pptp",
        2049 => "nfs", 2375 | 2376 => "docker", 3000 => "dev-http", 3306 => "mysql",
        3389 => "rdp", 5432 => "postgres", 5900 => "vnc", 6379 => "redis",
        8000 | 8080 | 8443 => "http-alt", 9200 => "elasticsearch", 27017 => "mongodb",
        _ => return None,
    })
}

pub async fn scan_ports(target: &str, ports: Option<&str>) -> serde_json::Value {
    let target = target.trim();
    if target.is_empty() {
        return json!({ "error": "Podaj adres IP lub domenę" });
    }

    let port_list = match parse_ports(ports) {
        Ok(p) => p,
        Err(e) => return json!({ "error": e }),
    };

    // rozwiązanie nazwy (bez wstrzykiwania do stringa)
    let resolved: Vec<SocketAddr> = match target.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, 0)],
        Err(_) => match (target, 0u16).to_socket_addrs() {
            Ok(it) => it.collect(),
            Err(e) => return json!({ "error": format!("Nie można rozwiązać '{}': {}", target, e) }),
        },
    };

    if resolved.is_empty() {
        return json!({ "error": format!("Brak adresów dla '{}'", target) });
    }

    let ip = resolved[0].ip();
    let start = std::time::Instant::now();
    let mut open: Vec<(u16, Option<&'static str>)> = Vec::new();
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(CONCURRENCY));
    let total = port_list.len();

    let mut tasks = Vec::with_capacity(total);
    for &port in &port_list {
        let sem = semaphore.clone();
        let addr = SocketAddr::new(ip, port);
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.ok()?;
            match timeout(Duration::from_millis(TIMEOUT_MS), TcpStream::connect(addr)).await {
                Ok(Ok(_)) => Some(port),
                _ => None,
            }
        }));
    }

    for t in tasks {
        if let Ok(Some(port)) = t.await {
            open.push((port, service_name(port)));
        }
    }
    open.sort_unstable();

    json!({
        "target": target,
        "ip": ip.to_string(),
        "open_ports": open.iter().map(|(p, s)| json!({
            "port": p,
            "service": s,
            "label": format!("{}/tcp{}", p, s.unwrap_or("?")),
        })).collect::<Vec<_>>(),
        "open_count": open.len(),
        "closed_count": total - open.len(),
        "total_scanned": total,
        "duration_ms": start.elapsed().as_millis(),
    })
}
