use base64::{engine::general_purpose, Engine as _};
use serde_json::json;

/// Buduje gotowe polecenie curl z podanych parametrów.
pub fn curl_build(method: &str, url: &str, headers: &str, body: &str, insecure: bool) -> serde_json::Value {
    if url.trim().is_empty() {
        return json!({ "error": "Podaj URL" });
    }
    let mut parts: Vec<String> = vec!["curl".into()];
    if insecure {
        parts.push("-k".into());
    }
    parts.push("-X".into());
    parts.push(method.to_uppercase());

    for line in headers.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            parts.push("-H".into());
            parts.push(format!("'{}: {}'", k.trim().replace('\'', "'\\''"), v.trim().replace('\'', "'\\''")));
        }
    }
    if !body.trim().is_empty() {
        parts.push("-d".into());
        parts.push(format!("'{}'", body.replace('\'', "'\\''")));
    }
    parts.push(format!("'{}'", url.trim().replace('\'', "'\\''")));

    let cmd = parts.join(" ");

    // klient HTTP w Pythonie jako alternatywa
    let py = format!(
        "import requests\nr = requests.request(\"{}\", url=\"{}\"{})\nprint(r.status_code)\nprint(r.text)",
        method.to_uppercase(),
        url.trim(),
        if body.trim().is_empty() { String::new() } else {
            format!(", data=r'''{}'''", body)
        }
    );

    json!({
        "curl": cmd,
        "powershell": format!(
            "Invoke-WebRequest -Uri \"{}\" -Method {} -UseBasicParsing{}",
            url.trim(),
            method.to_uppercase(),
            if body.trim().is_empty() { String::new() } else {
                format!(" -Body '{}'", body.replace('\'', "''"))
            }
        ),
        "python": py,
    })
}

/// Parsuje certyfikat PEM/X.509 i pokazuje podstawowe informacje.
pub fn cert_parse(pem: &str) -> serde_json::Value {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----") && !l.trim().is_empty())
        .collect();
    if body.is_empty() {
        return json!({ "error": "Nie znaleziono danych base64 między nagłówkami PEM" });
    }
    let der = match general_purpose::STANDARD.decode(&body) {
        Ok(d) => d,
        Err(e) => return json!({ "error": format!("Nieprawidłowy base64: {}", e) }),
    };

    let typ = if pem.contains("PRIVATE KEY") {
        "klucz prywatny"
    } else if pem.contains("CERTIFICATE") {
        "certyfikat X.509"
    } else if pem.contains("PUBLIC KEY") {
        "klucz publiczny"
    } else {
        "nieznany typ PEM"
    };

    // wyciągamy ciągi drukowalne z DER (heurystyka: nazwy OID/subjektów)
    let mut strings: Vec<String> = Vec::new();
    let mut cur = String::new();
    for b in &der {
        if (32..127).contains(b) {
            cur.push(*b as char);
        } else {
            if cur.len() >= 4 {
                strings.push(cur.clone());
            }
            cur.clear();
        }
    }
    if cur.len() >= 4 {
        strings.push(cur);
    }
    strings.retain(|s| s.chars().any(|c| c.is_ascii_alphabetic()));

    json!({
        "typ": typ,
        "rozmiar_der": format!("{} bajtów", der.len()),
        "szacowana_dlugosc_klucza": format!("~{} bitów (heurystyka)", (der.len() * 8).next_multiple_of(8)),
        "ilosc_znakow_widocznych": strings.len(),
        "ciagi": strings.iter().take(25).collect::<Vec<_>>(),
        "ostrzezenie": "Pełną weryfikację certyfikatu (ważność, łańcuch zaufania, OCSP) \
                       wykonaj narzędziem openssl: openssl x509 -in cert.pem -text -noout",
    })
}

/// Pobiera i analizuje security.txt oraz robots.txt (obronne).
pub async fn site_files(url: &str) -> serde_json::Value {
    let base = url.trim().trim_end_matches('/');
    if base.is_empty() {
        return json!({ "error": "Podaj domenę lub URL" });
    }
    let base = if base.starts_with("http") {
        base.to_string()
    } else {
        format!("https://{}", base)
    };

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("TZNSEC-Toolkit/1.0 (security review)")
        .build()
    {
        Ok(c) => c,
        Err(e) => return json!({ "error": format!("Klient HTTP: {}", e) }),
    };

    let mut out: Vec<serde_json::Value> = Vec::new();

    for (label, path) in [("security.txt", "/.well-known/security.txt"), ("robots.txt", "/robots.txt")] {
        let full = format!("{}{}", base, path);
        match client.get(&full).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                out.push(json!({
                    "plik": label,
                    "url": full,
                    "status": status,
                    "istnieje": (200..300).contains(&status),
                    "rozmiar": text.len(),
                    "tresc": text.chars().take(3000).collect::<String>(),
                    "analiza": analyze_txt(label, &text),
                }));
            }
            Err(e) => out.push(json!({
                "plik": label,
                "url": full,
                "status": 0,
                "istnieje": false,
                "blad": e.to_string(),
            })),
        }
    }

    let found = out.iter().filter(|v| v["istnieje"] == true).count();
    json!({
        "baza": base,
        "znaleziono": found,
        "pliki": out,
    })
}

fn analyze_txt(label: &str, text: &str) -> serde_json::Value {
    if label == "security.txt" {
        let has_expires = text.contains("Expires:");
        let has_contact = text.contains("Contact:");
        let has_policy = text.contains("Policy:");
        let in_root = !text.is_empty();
        json!({
            "kontakt": has_contact,
            "polityka": has_policy,
            "termin_waznosci": has_expires,
            "w_katalogu_wellknown": in_root,
            "ocena": if has_contact && has_policy { "poprawny security.txt" }
                     else { "niekompletny - brakuje pól kontaktowych lub polityki" },
        })
    } else {
        let disallow: Vec<&str> = text
            .lines()
            .filter_map(|l| l.strip_prefix("Disallow:"))
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .take(20)
            .collect();
        json!({
            "reguły_disallow": disallow.len(),
            "przykłady": disallow,
            "sitemaps": text.lines().filter(|l| l.starts_with("Sitemap:")).count(),
            "porada": "Katalogi zablokowane w robots.txt nie są chronione hasłem - \
                       to wyłącznie wskazówka dla robotów.",
        })
    }
}
