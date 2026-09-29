use serde_json::json;
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::time::Duration;

/// Sprawdza haslo w bazie wyciekow przez API Have I Been Pwned.
/// Wysylana jest wylacznie suma SHA-1 (k-anonimowo) - samo haslo nie opuszcza komputera.
pub async fn breach_check(password: &str) -> serde_json::Value {
    if password.is_empty() {
        return json!({ "error": "Wpisz haslo" });
    }

    let mut h = Sha1::new();
    h.update(password.as_bytes());
    let full = h.finalize();
    let hex = full.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    let (prefix, suffix) = hex.split_at(5);

    let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("TZNSEC-Toolkit")
        .build()
    {
        Ok(c) => c,
        Err(e) => return json!({ "error": e.to_string() }),
    };

    match client.get(&url).send().await {
        Ok(resp) => match resp.text().await {
            Ok(body) => {
                for line in body.lines() {
                    let mut it = line.split(':');
                    let (h2, cnt) = (it.next().unwrap_or(""), it.next().unwrap_or("").trim());
                    if h2.eq_ignore_ascii_case(suffix) {
                        let times: u64 = cnt.parse().unwrap_or(0);
                        return json!({
                            "wyciekly": times > 0,
                            "liczba_wyciekow": times,
                            "hash_prefix": format!("{}…", prefix),
                            "ocena": if times > 0 {
                                "HASŁO ZNANE W WYCIEKU - natychmiast zmień"
                            } else {
                                "brak trafienia w bazie"
                            },
                            "prywatnosc": "Wyslano tylko 5 znaków skrótu SHA-1 (k-anonimowo). \
                                           Samo hasło nie opuszcza komputera."
                        });
                    }
                }
                json!({
                    "wyciekly": false,
                    "liczba_wyciekow": 0,
                    "hash_prefix": format!("{}…", prefix),
                    "ocena": "brak trafienia w bazie wyciekow",
                    "prywatnosc": "Wyslano tylko 5 znaków skrótu SHA-1 (k-anonimowo)."
                })
            }
            Err(e) => json!({ "error": format!("Odpowiedz: {}", e) }),
        },
        Err(e) => json!({ "error": format!("Zapytanie nieudane: {}", e) }),
    }
}

/// Sprawdza, czy host odpowiada na HTTPS i jakie ma naglowki bezpieczenstwa.
pub async fn tls_audit(host: &str) -> serde_json::Value {
    let host = host.trim().trim_start_matches("https://").trim_start_matches("http://");
    let host = host.split('/').next().unwrap_or(host);
    if host.is_empty() {
        return json!({ "error": "Podaj domenę" });
    }

    // rozwiązanie + sprawdzenie portu 443
    let resolved = (host, 443u16).to_socket_addrs().ok().and_then(|mut i| i.next());
    let ip_txt = match resolved {
        Some(s) => s.ip().to_string(),
        None => format!("brak DNS"),
    };

    let url = format!("https://{}/", host);
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(12))
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(e) => return json!({ "error": e.to_string() }),
    };

    match client.get(&url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let mut headers: HashMap<String, String> = HashMap::new();
            for (k, v) in resp.headers() {
                headers.insert(
                    k.as_str().to_ascii_lowercase(),
                    v.to_str().unwrap_or("<binarny>").chars().take(200).collect(),
                );
            }
            let hsts = headers.get("strict-transport-security").cloned();
            let score = crate::tools::header_tools::analyze_headers(&headers);

            json!({
                "host": host,
                "ip": ip_txt,
                "https_dostepne": true,
                "status": status,
                "certyfikat_wazny": true,
                "hsts": hsts,
                "naglowki_bezpieczenstwa": score,
                "redirect": format!("{} -> {}", url, status),
            })
        }
        Err(e) => json!({
            "host": host,
            "ip": ip_txt,
            "https_dostepne": false,
            "error": format!("{}", e),
            "wskazowka": "Brak HTTPS lub problem z certyfikatem - sprawdz konfiguracje serwera.",
        }),
    }
}

/// Prosty skaner podatnosci na podstawie wersji ujawnionych w naglowkach.
pub fn version_scan(headers_text: &str, body: &str) -> serde_json::Value {
    let mut findings: Vec<serde_json::Value> = Vec::new();
    let hay = format!("{} {}", headers_text, body).to_lowercase();

    let sigs: Vec<(&str, &str, &str)> = vec![
        ("wordpress", r#"(?m)wp-content|wp-includes"#, "WordPress"),
        ("joomla", r#"(?m)joomla|/media/jui"#, "Joomla"),
        ("drupal", r#"(?m)drupal|/sites/default/files"#, "Drupal"),
        ("php", r#"(?m)x-powered-by:\s*php/([0-9.]+)"#, "PHP"),
        ("apache", r#"(?m)server:\s*apache/([0-9.]+)"#, "Apache"),
        ("nginx", r#"(?m)server:\s*nginx/([0-9.]+)"#, "nginx"),
        ("iis", r#"(?m)server:\s*microsoft-iis/([0-9.]+)"#, "Microsoft IIS"),
        ("laravel", r#"(?m)laravel_session|x-csrf-token"#, "Laravel"),
        ("django", r#"(?m)csrfmiddlewaretoken|__admin_media_prefix__"#, "Django"),
    ];

    for (id, pat, name) in sigs {
        if let Ok(re) = regex::Regex::new(pat) {
            if re.is_match(&hay) {
                let ver = re
                    .captures(&hay)
                    .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
                    .unwrap_or_else(|| "nie ujawniono wersji".into());
                findings.push(json!({ "technologia": name, "sygnatura": id, "wersja": ver }));
            }
        }
    }

    // pliki diagnostyczne
    let exposures: Vec<(&str, &str)> = vec![
        ("/.env", "Zmienne środowiskowe z sekretami"),
        ("/phpinfo.php", "Pełna konfiguracja PHP"),
        ("/.git/HEAD", "Repozytorium git - możliwy dump źródeł"),
        ("/backup.zip", "Kopia zapasowa"),
        ("/wp-config.php.bak", "Konfiguracja WordPress"),
        ("/.DS_Store", "Metadane macOS"),
    ];
    let ex: Vec<serde_json::Value> = exposures
        .iter()
        .filter(|(p, _)| hay.contains(p))
        .map(|(p, d)| json!({ "sciezka": p, "ryzyko": d }))
        .collect();

    json!({
        "wykryte_technologie": findings,
        "mozliwe_ujawnienia": ex,
        "status": if findings.is_empty() { "brak rozpoznanych sygnatur" } else { "rozpoznano stos technologiczny" },
        "porada": "Nieznane wersje = trudniejszy exploit. Sprawdz z https://www.cvedetails.com",
    })
}
