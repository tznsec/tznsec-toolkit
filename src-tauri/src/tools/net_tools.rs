use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

fn normalize(input: &str) -> Result<(IpAddr, u8), String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("Podaj adres, np. 192.168.1.0/24".into());
    }
    if !s.contains('/') {
        let ip: IpAddr = s.parse().map_err(|_| format!("Nieprawidłowy adres: {}", s))?;
        return Ok((ip, if ip.is_ipv4() { 32 } else { 128 }));
    }
    let (a, p) = s.split_once('/').ok_or("brak maski")?;
    let ip: IpAddr = a.trim().parse().map_err(|_| format!("Nieprawidłowy adres: {}", a))?;
    let max = if ip.is_ipv4() { 32u8 } else { 128u8 };
    let prefix: u8 = p
        .trim()
        .parse()
        .map_err(|_| format!("Nieprawidłowy prefiks: {}", p))?;
    if prefix > max {
        return Err(format!("Prefiks musi mieścić się w 0–{}", max));
    }
    Ok((ip, prefix))
}

pub fn cidr_analyze(input: &str) -> serde_json::Value {
    let (ip, prefix) = match normalize(input) {
        Ok(v) => v,
        Err(e) => return json!({ "error": e }),
    };

    let n = match ip {
        IpAddr::V4(v) => u32::from(v),
        IpAddr::V6(_) => return analyze_v6(ip, prefix),
    };
    let mask = v4_mask(prefix);
    let network = n & mask;
    let broadcast = network | !mask;
    let total = if prefix == 0 { u32::MAX as u64 + 1 } else { 1u64 << (32 - prefix) };
    let usable = if prefix <= 30 {
        total - 2
    } else if prefix == 31 {
        2
    } else {
        1
    };
    let first = if prefix <= 30 { network.wrapping_add(1) } else { network };
    let last = if prefix <= 30 { broadcast.wrapping_sub(1) } else { broadcast };

    json!({
        "family": "IPv4",
        "input": input.trim(),
        "prefix": format!("/{}", prefix),
        "maska_punktowa": Ipv4Addr::from(mask).to_string(),
        "maska_heks": format!("0x{:08x}", mask),
        "wildcard": Ipv4Addr::from(!mask).to_string(),
        "adres_sieci": Ipv4Addr::from(network).to_string(),
        "rozsylanie": Ipv4Addr::from(broadcast).to_string(),
        "pierwszy_host": Ipv4Addr::from(first).to_string(),
        "ostatni_host": Ipv4Addr::from(last).to_string(),
        "ilosc_adresow": total,
        "ilosc_hostow": usable,
        "typ": match prefix { 32 => "host /32", 31 => "p2p /31", 27..=30 => "podsieć", 24 => "podsieć klasowa", _ => "supernetsieć" },
    })
}

fn analyze_v6(ip: IpAddr, prefix: u8) -> serde_json::Value {
    let n = u128::from(match ip {
        IpAddr::V6(v) => v,
        _ => return json!({ "error": "to nie IPv6" }),
    });
    let mask = v6_mask(prefix);
    let network = n & mask;
    let last = network | !mask;
    let total: u128 = if prefix == 0 { u128::MAX } else { 1u128 << (128 - prefix) };

    json!({
        "family": "IPv6",
        "input": format!("{}/{}", ip, prefix),
        "prefix": format!("/{}", prefix),
        "maska_punktowa": Ipv6Addr::from(mask).to_string(),
        "adres_sieci": Ipv6Addr::from(network).to_string(),
        "ostatni_adres": Ipv6Addr::from(last).to_string(),
        "ilosc_adresow": if total > u64::MAX as u128 { format!("> 2^64") } else { total.to_string() },
        "typ": if prefix >= 64 { "typowy /64 (1 subnet na operatora)" } else { "duży blok" },
    })
}

/// Dzieli sieć na mniejsze podsieci (VLSM).
pub fn cidr_split(input: &str, new_prefix: u8, max_out: usize) -> serde_json::Value {
    let (ip, prefix) = match normalize(input) {
        Ok(v) => v,
        Err(e) => return json!({ "error": e }),
    };
    if let IpAddr::V4(_) = ip {
        if new_prefix < prefix {
            return json!({ "error": "Nowy prefiks musi być większy od obecnego" });
        }
        if new_prefix > 32 {
            return json!({ "error": "Maksymalny prefiks to /32" });
        }
    }

    let base = match ip {
        IpAddr::V4(v) => u32::from(v) & v4_mask(prefix),
        _ => return json!({ "error": "Dzielenie wspiera tylko IPv4" }),
    };

    let count: u64 = 1u64 << (new_prefix - prefix);
    let limit = max_out.clamp(1, 256);
    let step = 1u64 << (32 - new_prefix);
    let netmask = v4_mask(new_prefix);
    let usable = if new_prefix <= 30 { (1u64 << (32 - new_prefix)) - 2 } else { 1 };

    let mut subs = Vec::new();
    for i in 0..count.min(limit as u64) {
        let n = (base as u64).wrapping_add(i * step) as u32;
        let bcast = n | !netmask;
        let first = if new_prefix <= 30 { n.wrapping_add(1) } else { n };
        let last = if new_prefix <= 30 { bcast.wrapping_sub(1) } else { bcast };
        subs.push(json!({
            "index": i + 1,
            "sieci": Ipv4Addr::from(n).to_string(),
            "rozsylanie": Ipv4Addr::from(bcast).to_string(),
            "zakres": format!("{} - {}", Ipv4Addr::from(first), Ipv4Addr::from(last)),
            "hostow": usable,
        }));
    }

    json!({
        "zrodlo": format!("{}/{}", Ipv4Addr::from(base), prefix),
        "na": format!("/{}", new_prefix),
        "liczba_podsieci": count,
        "pokazano": subs.len(),
        "hostow_na_podsiec": usable,
        "podsieci": subs,
    })
}

/// Generuje listę adresów hostów w podsieci.
pub fn host_expand(input: &str, limit: usize) -> serde_json::Value {
    let (ip, prefix) = match normalize(input) {
        Ok(v) => v,
        Err(e) => return json!({ "error": e }),
    };
    let base = match ip {
        IpAddr::V4(v) => u32::from(v) & v4_mask(prefix),
        _ => return json!({ "error": "Ekspansja wspiera tylko IPv4" }),
    };
    if prefix > 30 {
        return json!({ "error": "Podsieć jest za mała na listę hostów (/30 lub większa maska)" });
    }

    let total = 1u64 << (32 - prefix);
    let cap = limit.clamp(1, 4096);
    let mut addrs = Vec::new();
    for i in 1..total.saturating_sub(1) {
        if addrs.len() >= cap {
            break;
        }
        addrs.push(Ipv4Addr::from((base as u64).wrapping_add(i) as u32).to_string());
    }
    json!({
        "siec": format!("{}/{}", Ipv4Addr::from(base), prefix),
        "zakres_hostsow": total.saturating_sub(2),
        "pokazano": addrs.len(),
        "adresy": addrs,
    })
}

/// Geo / dane o adresie IP przez publiczne API (HTTP, bez TLS).
pub async fn ip_info(ip: &str) -> serde_json::Value {
    let ip = ip.trim();
    if ip.is_empty() {
        return json!({ "error": "Podaj adres IP" });
    }
    let probe = if ip == "me" || ip == "self" {
        "8.8.8.8".to_string()
    } else {
        ip.to_string()
    };

    let url = format!(
        "http://ip-api.com/json/{}?fields=status,message,country,countryCode,regionName,city,district,zip,lat,lon,timezone,isp,org,as,query,reverse",
        probe
    );

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
    {
        Ok(c) => c,
        Err(e) => return json!({ "error": format!("Klient HTTP: {}", e) }),
    };

    match client.get(&url).send().await {
        Ok(resp) => match resp.json::<serde_json::Value>().await {
            Ok(mut v) => {
                if v.get("status").and_then(|s| s.as_str()) != Some("success") {
                    let msg = v.get("message").and_then(|m| m.as_str()).unwrap_or("brak danych");
                    return json!({ "error": format!("API: {}", msg) });
                }
                v.as_object_mut().map(|o| o.remove("status"));
                v
            }
            Err(e) => json!({ "error": format!("Nieprawidłowa odpowiedź: {}", e) }),
        },
        Err(e) => json!({ "error": format!("Zapytanie nieudane: {}", e) }),
    }
}
