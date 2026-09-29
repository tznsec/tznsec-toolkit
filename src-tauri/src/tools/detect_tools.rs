use serde_json::json;
use std::collections::HashMap;

// (nazwa, regex, opis, poziom)
struct Sig {
    name: &'static str,
    re: &'static str,
    desc: &'static str,
    level: &'static str,
    fix: &'static str,
}

const SIGS: &[Sig] = &[
    Sig { name: "SQL Injection", re: r#"(?i)('|\")\s*(or|and)\s+('|\")?\d+('|\")?\s*=|(\%27)|(')\s*(or|and)\s+(')?1(')?\s*=|union\s+(all\s+)?select|select\s+.+\s+from\s+\w+|sleep\(\d+\)|benchmark\(\d+|waitfor\s+delay"#, desc: "PrĂłba modyfikacji zapytania SQL przez dane wejĹ›ciowe", level: "krytyczny", fix: "Parametryzacja zapytaĹ„ (bind variables), walidacja typĂłw" },
    Sig { name: "XSS", re: r#"(?i)(<\s*script|<\s*img[^>]+onerror\s*=|<\s*svg[^>]+onload\s*=|javascript\s*:|on(click|mouseover|focus|load|error)\s*=\s*['\"]|document\.cookie|alert\(['\"]?xss)"#, desc: "WstrzykniÄ™cie skryptu przez treĹ›Ä‡ wejĹ›ciowÄ…", level: "krytyczny", fix: "Kodowanie wyjĹ›cia (escaping), CSP, sanitize DOM" },
    Sig { name: "Log4Shell (CVE-2021-44228)", re: r#"\$\{jndi:(ldap|ldaps|rmi|dns|iiop|corba|nis|nds)://"#, desc: "Exploit JNDI w logach aplikacji Java", level: "krytyczny", fix: "Aktualizacja log4j do 2.17.1+, usuniÄ™cie lookupĂłw JNDI" },
    Sig { name: "Command Injection", re: r#"(;|\||&&|\$\()\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|powershell|cmd)\b|;rm\s+-rf|\|\s*(nc|bash)\b"#, desc: "WstrzykniÄ™cie poleceĹ„ powĹ‚oki", level: "krytyczny", fix: "Bez budowania stringĂłw z poleceĹ„, allowlista argumentĂłw" },
    Sig { name: "Path Traversal", re: r#"\.\./\.\.|\.\.\\\.\.\\|%2e%2e%2f|%2e%2e/|/etc/passwd|/proc/self/environ|boot\.ini|win\.ini"#, desc: "WyjĹ›cie poza katalog bazowy", level: "wysoki", fix: "Normalizacja Ĺ›cieĹĽki, kanonikalizacja, allowlista katalogĂłw" },
    Sig { name: "SSRF", re: r#"(?i)(http|ftp|gopher|file)://(127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|\[::1\])"#, desc: "Ĺ»Ä…danie do zasobĂłw wewnÄ™trznych (moĹĽe ujawniÄ‡ metadane chmury)", level: "wysoki", fix: "Allowlista hostĂłw docelowych, blokada link-local" },
    Sig { name: "SSTI", re: r#"(?i)\{\{\s*\d+\s*[\+\-\*]\s*\d+\s*\}\}|\$\{\s*\d+\s*[\+\*]|\{%\s*\d+\s*%\}|<%=.*%>"#, desc: "WstrzykniÄ™cie szablonu (server-side template injection)", level: "wysoki", fix: "Brak eval/dynamicznego renderowania szablonĂłw z danych" },
    Sig { name: "XXE", re: r#"(?i)<!ENTITY[^>]+SYSTEM|<!DOCTYPE[^>]+SYSTEM"#, desc: "Wczytywanie zewnÄ™trznych encji XML", level: "wysoki", fix: "WyĹ‚Ä…cz rozwijanie encji w parserze XML" },
    Sig { name: "NoSQL Injection", re: r#"(?i)\$ne\s*:|\$gt\s*:|\$regex\s*:|where\(\s*this\.[a-z]+\s*==\s*['\"]?[a-z]*['\"]?\s*\)"#, desc: "Manipulacja operatorami bazy NoSQL", level: "krytyczny", fix: "Walidacja typĂłw schematem, wyĹ‚Ä…cz eval w zapytaniach" },
    Sig { name: "Deserialization", re: r#"(?i)rO0AB|O:\d+:\"[^"]+\"|__reduce__|ObjectInputStream|yaml\.load\s*\("#, desc: "Niebezpieczna deserializacja obiektĂłw", level: "wysoki", fix: "Bezpieczne formaty (JSON), podpisane dane, allowlist klas" },
    Sig { name: "Prototype Pollution", re: r#"(?i)__proto__\s*\[|constructor\s*\[\s*['\"]prototype"#, desc: "Zanieczyszczenie prototypu w JS", level: "Ĺ›redni", fix: "Blokada __proto__/constructor, Object.create(null)" },
    Sig { name: "Open Redirect", re: r#"(?i)(redirect|url|next|return|dest|goto)\s*=\s*(https?:)?//(?!localhost)"#, desc: "Przekierowanie na domenÄ™ zewnÄ™trznÄ…", level: "Ĺ›redni", fix: "Allowlista domen docelowych" },
    Sig { name: "CRLF Injection", re: r#"%0d%0a|\r\n(?=[A-Za-z-]+:)|(?i)%0a(set-cookie|location)"#, desc: "WstrzykniÄ™cie CRLF do nagĹ‚Ăłwka HTTP", level: "Ĺ›redni", fix: "Sanityzacja CRLF w nagĹ‚Ăłwkach" },
    Sig { name: "Race Condition", re: r#"(?i)/tmp/[a-z0-9]+\.(tmp|lock)|(?i)flock|mktemp"#, desc: "Wzorzec podatny na wyĹ›cig (pliki tymczasowe)", level: "niski", fix: "mktemp z atomowym O_EXCL, blokady plikowe" },
];

/// Wykrywa w tekĹ›cie wzorce atakĂłw (zastosowanie obronne / WAF / triage logĂłw).
pub fn scan_payloads(text: &str) -> serde_json::Value {
    let mut findings: Vec<serde_json::Value> = Vec::new();
    let mut summary: HashMap<&str, usize> = HashMap::new();

    for sig in SIGS {
        let re = match regex::Regex::new(sig.re) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let hits: Vec<serde_json::Value> = re
            .find_iter(text)
            .take(25)
            .map(|m| {
                let line = text[..m.start()].lines().count() + 1;
                let snippet = m.as_str();
                let snippet = if snippet.len() > 90 {
                    format!("{}â€¦", &snippet[..90])
                } else {
                    snippet.to_string()
                };
                json!({ "linia": line, "fragment": snippet })
            })
            .collect();

        if !hits.is_empty() {
            *summary.entry(sig.level).or_insert(0) += hits.len();
            findings.push(json!({
                "nazwa": sig.name,
                "poziom": sig.level,
                "opis": sig.desc,
                "naprawa": sig.fix,
                "liczba": hits.len(),
                "przyklady": hits,
            }));
        }
    }

    let critical = summary.get("krytyczny").copied().unwrap_or(0);
    let high = summary.get("wysoki").copied().unwrap_or(0);

    json!({
        "typ_wejscia": if text.lines().count() > 3 { "log / plik" } else { "pojedyncze wejĹ›cie" },
        "rozmiary": format!("{} znakĂłw, {} linii", text.len(), text.lines().count()),
        "wykryte_typy": findings.len(),
        "trafienia_krytyczne": critical,
        "trafienia_wysokie": high,
        "ocena": if critical > 0 { "KRYTYCZNE â€” wymaga natychmiastowej reakcji" }
                 else if high > 0 { "WYSOKIE â€” przeanalizuj ĹşrĂłdĹ‚o zdarzenia" }
                 else if !findings.is_empty() { "Ĺ›rednie â€” zweryfikuj kontekst" }
                 else { "brak znanych wzorcĂłw ataku" },
        "wyniki": findings,
    })
}

/// Generator bezpiecznych testĂłw payloadĂłw do wĹ‚asnego Ĺ›rodowiska.
pub fn payload_refs() -> serde_json::Value {
    let items: Vec<serde_json::Value> = SIGS
        .iter()
        .map(|s| json!({ "nazwa": s.name, "poziom": s.level, "opis": s.desc, "naprawa": s.fix }))
        .collect();
    json!({ "katalog": items.len(), "pozycje": items })
}
