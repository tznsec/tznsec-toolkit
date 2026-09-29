use serde_json::json;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::process::Command;

/// Zakres Tailscale / CGNAT (RFC 6598). Nie jest routowany publicznie,
/// wiec nie mozna go uzyc do ataku na obca infrastrukture.
fn is_tailscale_cgnat(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.octets()[0] == 100 && (64..=127).contains(&v.octets()[1]),
        IpAddr::V6(v) => v.segments()[0] & 0xffc0 == 0xfc00 || (v.segments()[0] & 0xfff0) == 0xfd00,
    }
}

pub fn is_allowed_scope(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            o[0] == 127
                || o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 169 && o[1] == 254)
                || (o[0] == 100 && (64..=127).contains(&o[1]))
        }
        IpAddr::V6(v) => v.is_loopback() || (v.segments()[0] & 0xfe00) == 0xfc00,
    }
}

fn tailscale_cli() -> Option<std::path::PathBuf> {
    if let Ok(p) = std::env::var("ProgramFiles") {
        let c = std::path::Path::new(&p).join("Tailscale").join("tailscale.exe");
        if c.exists() {
            return Some(c);
        }
    }
    if let Ok(p) = std::env::var("LOCALAPPDATA") {
        let c = std::path::Path::new(&p).join("Tailscale").join("tailscale.exe");
        if c.exists() {
            return Some(c);
        }
    }
    // szukamy w PATH
    if let Ok(path) = std::env::var("PATH") {
        for d in path.split(';') {
            let c = std::path::Path::new(d).join("tailscale.exe");
            if c.exists() {
                return Some(c);
            }
        }
    }
    None
}

/// Wykrywa Tailscale: czy dziala, jaki ma adres i kto jest w sieci.
pub fn detect() -> serde_json::Value {
    let cli = match tailscale_cli() {
        Some(c) => c,
        None => {
            return json!({
                "zainstalowany": false,
                "aktywny": false,
                "adresy": [],
                "siec": [],
                "info": "Nie znaleziono tailscale.exe w Program Files ani w PATH.",
            })
        }
    };

    let version = Command::new(&cli).arg("version").output().ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    // wlasne adresy
    let mut own: Vec<String> = Vec::new();
    if let Ok(out) = Command::new(&cli).args(["ip"]).output() {
        for l in String::from_utf8_lossy(&out.stdout).lines() {
            let t = l.trim().to_string();
            if !t.is_empty() {
                own.push(t);
            }
        }
    }

    // status
    let (aktywny, siec, dns) = match Command::new(&cli)
        .args(["status", "--json"])
        .output()
    {
        Ok(o) => match serde_json::from_slice::<serde_json::Value>(&o.stdout) {
            Ok(v) => {
                let st = v.get("BackendState").and_then(|s| s.as_str()).unwrap_or("Unknown");
                let peers: Vec<serde_json::Value> = v
                    .get("Peer")
                    .and_then(|p| p.as_object())
                    .map(|m| m.values().cloned().collect())
                    .unwrap_or_default();

                let mut rows: Vec<serde_json::Value> = Vec::new();
                for p in peers {
                    let name = p.get("HostName").and_then(|h| h.as_str()).unwrap_or("?");
                    let ips: Vec<String> = p
                        .get("TailscaleIPs")
                        .and_then(|i| i.as_array())
                        .map(|a| a.iter().filter_map(|x| x.as_str()).map(|s| s.to_string()).collect())
                        .unwrap_or_default();
                    let online = p
                        .get("Online")
                        .and_then(|o| o.as_bool())
                        .unwrap_or(false);
                    let os = p.get("OS").and_then(|o| o.as_str()).unwrap_or("?");
                    rows.push(json!({
                        "nazwa": name,
                        "adresy": ips,
                        "online": online,
                        "system": os,
                    }));
                }
                rows.sort_by(|a, b| b["online"].as_bool().unwrap_or(false).cmp(&a["online"].as_bool().unwrap_or(false)));

                let dns_name = v
                    .get("MagicDNSSuffix")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string();

                (st == "Running", rows, dns_name)
            }
            Err(e) => (false, Vec::new(), format!("blad parsowania: {}", e)),
        },
        Err(e) => (false, Vec::new(), format!("blad zapytania: {}", e)),
    };

    json!({
        "zainstalowany": true,
        "aktywny": aktywny,
        "wersja": version.lines().next().unwrap_or(""),
        "sciezka": cli.to_string_lossy(),
        "adresy": own,
        "domena_magicdns": dns,
        "siec": siec,
        "uprawniony_zakres": "100.64.0.0/10 (CGNAT) - nie routowane publicznie",
        "info": if aktywny {
            "Test obciazeniowy moze teraz celowac w wezly Twojego tailnetu."
        } else {
            "Tailscale jest zainstalowany, ale nieaktywny. Uruchom usluge i zaciagnij wezel."
        },
    })
}

/// Lista twoich wezlow, do ktorych tool moze sie odwolac.
pub fn peers() -> serde_json::Value {
    let d = detect();
    if d["aktywny"] != true {
        return json!({ "error": d["info"], "wezly": [] });
    }
    json!({ "wezly": d["siec"], "adresy_wlasne": d["adresy"] })
}

/// Mapuje wlasne wezly do zakresow - pomocne przy planowaniu testu.
pub fn scope_summary() -> serde_json::Value {
    let d = detect();
    let mut m: BTreeMap<String, u32> = BTreeMap::new();
    for ip in d["adresy"].as_array().cloned().unwrap_or_default() {
        if let Ok(p) = ip.as_str().unwrap_or("").parse::<IpAddr>() {
            let kind = if p.is_loopback() {
                "localhost"
            } else if is_tailscale_cgnat(&p) {
                "tailscale"
            } else if is_allowed_scope(&p) {
                "prywatny"
            } else {
                "publiczny - niedozwolony"
            };
            *m.entry(kind.to_string()).or_insert(0) += 1;
        }
    }
    json!({
        "tailscale_aktywny": d["aktywny"],
        "twoje_adresy": d["adresy"],
        "kategorie": m,
        "dozwolone": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10 (Tailscale/CGNAT)", "fc00::/7"],
    })
}
