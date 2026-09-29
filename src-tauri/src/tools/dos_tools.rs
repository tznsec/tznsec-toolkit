use serde_json::json;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

/// Czy adres nalezy do bezpiecznego zakresu (localhost / LAN / Tailscale CGNAT).
/// Narzedzie do testowania wlasnej infrastruktury - celowo ograniczone,
/// zeby nie dalo sie uzyc przeciw obcej, publicznej usludze.
fn is_private_or_loopback(ip: &IpAddr) -> bool {
    crate::tools::tailscale_tools::is_allowed_scope(ip)
}

const MAX_REQUESTS: usize = 20_000;
const MAX_DURATION_SECS: u64 = 15;
const MAX_CONCURRENCY: usize = 200;

/// Test obciazeniowy wlasnej uslugi (localhost / LAN).
/// Twarde limity: liczba zadan, czas trwania i wspolczesnosc.
pub async fn stress_test(
    target: &str,
    port: u16,
    requests: usize,
    concurrency: usize,
    duration_secs: u64,
    path: &str,
) -> serde_json::Value {
    let target = target.trim();
    if target.is_empty() {
        return json!({ "error": "Podaj adres swojej uslugi (localhost lub IP z sieci prywatnej)" });
    }

    let ip: IpAddr = match target.parse::<IpAddr>() {
        Ok(v) => v,
        Err(_) => match (target, 0u16).to_socket_addrs() {
            Ok(mut it) => match it.next() {
                Some(s) => s.ip(),
                None => return json!({ "error": "Nie mozna rozroznic adresu" }),
            },
            Err(e) => return json!({ "error": format!("Blad DNS: {}", e) }),
        },
    };

    if !is_private_or_loopback(&ip) {
        return json!({
            "error": "Dozwolone tylko adresy localhost, LAN i Tailscale (CGNAT)",
            "wyjasnienie": format!(
                "{} to adres publiczny. To narzedzie sluzy do testowania wlasnej uslugi \
                 (obciazenie, limity, czas odpowiedzi), nie do atakowania cudzych serwerow. \
                 Jesli Twoja usluga jest w tailnecie Tailscale - uzyj adresu 100.x.",
                ip
            )
        });
    }

    let total = requests.clamp(1, MAX_REQUESTS);
    let conc = concurrency.clamp(1, MAX_CONCURRENCY);
    let dur = duration_secs.clamp(1, MAX_DURATION_SECS);
    let path = if path.trim().is_empty() { "/" } else { path.trim() };
    let addr = SocketAddr::new(ip, port);
    let deadline = Instant::now() + Duration::from_secs(dur);
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(conc));

    let mut latencies: Vec<u64> = Vec::with_capacity(total);
    let mut ok = 0usize;
    let mut fail = 0usize;
    let start = Instant::now();
    let mut issued = 0usize;

    while issued < total && Instant::now() < deadline {
        let batch = conc.min(total - issued);
        issued += batch;
        let mut tasks = Vec::with_capacity(batch);
        for _ in 0..batch {
            let sem = sem.clone();
            let addr = addr;
            let path = path.to_string();
            tasks.push(tokio::spawn(async move {
                let _p = sem.acquire_owned().await.ok()?;
                let t0 = Instant::now();
                let res = match tokio::time::timeout(
                    Duration::from_secs(5),
                    tokio::net::TcpStream::connect(addr),
                )
                .await
                {
                    Ok(Ok(mut s)) => {
                        // proby HTTP GET z minimalnym naglowkiem
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let req = format!(
                            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: TZNSEC-StressTest\r\nConnection: close\r\n\r\n",
                            path, addr
                        );
                        if s.write_all(req.as_bytes()).await.is_err() {
                            None
                        } else {
                            let mut buf = vec![0u8; 64];
                            match s.read(&mut buf).await {
                                Ok(n) if n > 0 => {
                                    let head = String::from_utf8_lossy(&buf[..n]);
                                    let code = head
                                        .split_whitespace()
                                        .nth(1)
                                        .and_then(|c| c.parse::<u16>().ok())
                                        .unwrap_or(0);
                                    Some(code)
                                }
                                _ => None,
                            }
                        }
                    }
                    _ => None,
                };
                Some((res, t0.elapsed().as_millis() as u64))
            }));
        }
        for t in tasks {
            if let Ok(Some((code, ms))) = t.await {
                match code {
                    Some(c) if c > 0 && c < 500 => ok += 1,
                    _ => fail += 1,
                }
                latencies.push(ms);
            } else {
                fail += 1;
            }
        }
    }

    latencies.sort_unstable();
    let n = latencies.len();
    let pct = |p: f64| -> u64 {
        if n == 0 {
            0
        } else {
            latencies[((n as f64 - 1.0) * p) as usize]
        }
    };
    let elapsed = start.elapsed();
    let secs = elapsed.as_secs_f64().max(0.001);
    let total_done = ok + fail;

    json!({
        "cel": format!("{}:{}", ip, port),
        "sciezka": path,
        "zakres": if crate::tools::tailscale_tools::is_allowed_scope(&ip) {
            "localhost / LAN / Tailscale (test wlasnej uslugi)"
        } else {
            "nieznany"
        },
        "zadania_wyslane": total_done,
        "sukces": ok,
        "bledy": fail,
        "czas_sekundy": format!("{:.2}", elapsed.as_secs_f64()),
        "zadania_na_sekunde": format!("{:.0}", total_done as f64 / secs),
        "latencja_ms": {
            "min": latencies.first().copied().unwrap_or(0),
            "p50": pct(0.50),
            "p95": pct(0.95),
            "p99": pct(0.99),
            "max": latencies.last().copied().unwrap_or(0)
        },
        "uwaga": "Wynik mowi ci, ile Twoja usluga obsluguje jednoczesnie. \
                  Nizszy p95 = lepsza odpornosc na obciazenie.",
    })
}

/// Analiza logow dos w poszukiwaniu wzorcow ataku (obronnie).
pub fn dos_log_analyzer(log: &str) -> serde_json::Value {
    let mut per_ip: HashMap<String, usize> = HashMap::new();
    let mut per_path: HashMap<String, usize> = HashMap::new();
    let mut per_ua: HashMap<String, usize> = HashMap::new();
    let mut statuses: HashMap<u16, usize> = HashMap::new();
    let mut total = 0usize;
    let mut bytes_total = 0u64;

    // typowy format combined: IP - - [ts] "GET /path HTTP/1.1" 200 1234 "ref" "UA"
    for line in log.lines() {
        if line.trim().is_empty() {
            continue;
        }
        total += 1;
        let mut ip = "?".to_string();
        let mut path = "?".to_string();
        let mut ua = "?".to_string();
        let mut code = 0u16;
        let mut size = 0u64;

        if let Some(first) = line.split_whitespace().next() {
            if first.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                ip = first.to_string();
            }
        }
        if let Some(q) = line.split('"').nth(1) {
            let parts: Vec<&str> = q.split_whitespace().collect();
            if parts.len() >= 2 {
                path = parts[1].to_string();
            }
        }
        if let Some(q) = line.split('"').nth(2) {
            code = q.split_whitespace().next().and_then(|c| c.parse().ok()).unwrap_or(0);
        }
        if let Some(q) = line.split('"').nth(1) {
            let _ = q;
        }
        // rozmiar: liczba po statusie
        let tail: Vec<&str> = line.rsplit('"').next().unwrap_or("").split_whitespace().collect();
        if let Some(s) = tail.get(1) {
            size = s.parse().unwrap_or(0);
        }
        bytes_total += size;

        if let Some(uaq) = line.split('"').nth(5) {
            ua = uaq.trim().chars().take(60).collect();
        }

        *per_ip.entry(ip).or_insert(0) += 1;
        *per_path.entry(path).or_insert(0) += 1;
        *per_ua.entry(ua).or_insert(0) += 1;
        if code > 0 {
            *statuses.entry(code).or_insert(0) += 1;
        }
    }

    let top = |m: &HashMap<String, usize>, k: usize| -> Vec<serde_json::Value> {
        let mut v: Vec<(&String, &usize)> = m.iter().collect();
        v.sort_by(|a, b| b.1.cmp(a.1));
        v.into_iter()
            .take(k)
            .map(|(a, b)| json!({ "klucz": a, "liczba": b }))
            .collect()
    };

    let errs = statuses.get(&404).copied().unwrap_or(0);
    let srv_errs = statuses.get(&500).copied().unwrap_or(0)
        + statuses.get(&502).copied().unwrap_or(0)
        + statuses.get(&503).copied().unwrap_or(0);
    let unauth = statuses.get(&401).copied().unwrap_or(0)
        + statuses.get(&403).copied().unwrap_or(0);

    let findings: Vec<serde_json::Value> = Vec::new();
    let mut f = findings;

    // progi oceny
    if total > 0 {
        let err_rate = (errs as f64 / total as f64) * 100.0;
        if err_rate > 40.0 {
            f.push(json!({ "typ": "skan portow / enumeracja", "poziom": "wysoki",
                "opis": format!("{:.0}% odpowiedzi 404 - typowy skan katalogow lub slow", err_rate),
                "akcja": "Sprawdz blokady w firewallu / WAF, ogranicz rate limit" }));
        }
        if srv_errs as f64 / total as f64 > 0.05 {
            f.push(json!({ "typ": "mozliwy DoS / wyczerpanie zasobow", "poziom": "krytyczny",
                "opis": format!("{} bledow serwera 5xx", srv_errs),
                "akcja": "Sprawdz zasoby (CPU/RAM/conn), wlac rate limiting i cache" }));
        }
        if unauth as f64 / total as f64 > 0.2 {
            f.push(json!({ "typ": "brute force", "poziom": "wysoki",
                "opis": format!("{} prob logowania / niedozwolonych dostepow", unauth),
                "akcja": "Wylacz konta po N probach, dodaj MFA" }));
        }
    }

    // pojedynczy IP z bardzo duza liczba requestow
    if let Some((ip, c)) = per_ip.iter().max_by_key(|(_, v)| **v) {
        if total > 50 && (*c as f64 / total as f64) > 0.3 {
            f.push(json!({ "typ": "koncentracja z jednego IP", "poziom": "sredni",
                "opis": format!("{} z {} requestow ({:.0}%) z {}", c, total, (*c as f64 / total as f64) * 100.0, ip),
                "akcja": "Rozwaz WAF / rate limit per IP" }));
        }
    }

    let verdict = if f.iter().any(|x| x["poziom"] == "krytyczny") {
        "KRYTYCZNE - mozliwy atak na dostepnosc"
    } else if !f.is_empty() {
        "wykryto anomalie - do analizy"
    } else {
        "brak oczywistych wzorcow ataku"
    };

    json!({
        "linie_analizowane": total,
        "rozmiar_odpowiedzi": format!("{:.1} MB", bytes_total as f64 / 1_048_576.0),
        "statusy": statuses.iter().map(|(k, v)| json!({ "kod": k, "liczba": v })).collect::<Vec<_>>(),
        "najwieksi_nadawcy": top(&per_ip, 8),
        "najczestsze_sciezki": top(&per_path, 8),
        "user_agenty": top(&per_ua, 5),
        "znalezione_wzorce": f,
        "ocena": verdict,
    })
}
