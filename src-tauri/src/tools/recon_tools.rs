use serde_json::json;
use std::collections::HashMap;

/// Wykrywa jakie narzedzia pentesterskie sa zainstalowane.
/// Model dzieki temu nie proponuje nmap, skoro go nie ma - tylko curl/PowerShell.
pub fn check_tools() -> serde_json::Value {
    let candidates = [
        "nmap", "masscan", "curl", "wget", "python", "python3", "pip", "pip3",
        "sqlmap", "nikto", "hydra", "john", "hashcat", "netcat", "nc",
        "git", "node", "npm", "openssl", "ping", "nslookup", "telnet", "ssh",
    ];
    let mut present: Vec<String> = Vec::new();
    let mut missing: Vec<String> = Vec::new();

    for c in candidates {
        let ok = if cfg!(windows) {
            std::process::Command::new("cmd")
                .args(["/C", "where", c])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        } else {
            std::process::Command::new("which")
                .arg(c)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        };
        if ok {
            present.push(c.to_string());
        } else {
            missing.push(c.to_string());
        }
    }

    json!({
        "dostepne": present,
        "brakujace": missing,
        "wskazowka": if present.contains(&"nmap".to_string()) {
            "nmap dostepny - mozesz proponowac pelne skanowanie wersji"
        } else {
            "Brak nmap. Do skanowania portow uzyj wbudowanego narzedzia 'Skaner portow' \
             w aplikacji, a do HTTP uzyj curl (jest dostepny)."
        },
        "instalacja": "winget install Insecure.Nmap  albo  choco install nmap",
    })
}

/// Uproszczona analiza wyniku komendy - wyciaga fakty do raportu.
pub fn analyze_output(command: &str, stdout: &str, stderr: &str, exit_code: i32) -> serde_json::Value {
    fn push(signals: &mut Vec<serde_json::Value>, tag: &str, level: &str, title: &str, detail: &str) {
        signals.push(json!({ "typ": tag, "poziom": level, "znalezisko": title, "detal": detail }));
    }
    let out = stdout.to_lowercase();
    let mut signals: Vec<serde_json::Value> = Vec::new();

    // --- naglowki HTTP ---
    if command.contains("curl") && out.contains("http/") {
        let raw = stdout.to_string();
        let mut server = "nieznany".to_string();
        let mut powered = "brak".to_string();
        let mut missing: Vec<String> = Vec::new();
        let mut has_cookie = false;

        for line in raw.lines() {
            let l = line.to_lowercase();
            if l.starts_with("server:") {
                server = line[7..].trim().to_string();
            }
            if l.starts_with("x-powered-by:") {
                powered = line[13..].trim().to_string();
            }
            if l.starts_with("set-cookie:") {
                has_cookie = true;
                if !l.contains("httponly") {
                    missing.push("HttpOnly na cookie".to_string());
                }
                if !l.contains("secure") {
                    missing.push("Secure na cookie".to_string());
                }
                if !l.contains("samesite") {
                    missing.push("SameSite na cookie".to_string());
                }
            }
            for h in [
                "strict-transport-security",
                "content-security-policy",
                "x-frame-options",
                "x-content-type-options",
                "referrer-policy",
            ] {
                if l.starts_with(&format!("{}:", h)) && l.contains(h) {
                    signals.push(json!({
                        "typ": "naglowek", "poziom": "ok",
                        "znalezisko": h, "detal": line.splitn(2, ':').nth(1).unwrap_or("").trim()
                    }));
                }
            }
        }

        let wersja = if powered == "brak" {
            "brak ujawnionej wersji (dobre)".to_string()
        } else {
            format!("ujawniona wersja: {}", powered)
        };
        push(&mut signals, "technologia", "info", &format!("Serwer: {}", server), &wersja);
        for m in missing {
            push(&mut signals, "cookie", "mid", &format!("Brak flagi: {}", m), "cookie bez tej flagi jest ryzykowne");
        }
        if !has_cookie {
            push(&mut signals, "cookie", "ok", "Brak naglowka Set-Cookie", "sesja nie jest cookie (albo nie ma sesji)");
        }
    }

    // --- SQL / NoSQL injection w odpowiedzi ---
    for (pat, name) in [
        ("sql syntax", "SQL"),
        ("mysql_fetch", "SQL"),
        ("postgresql", "SQL"),
        ("ora-", "Oracle"),
        ("warning: mysql", "SQL"),
        ("sqlite", "SQL"),
    ] {
        if out.contains(pat) {
            push(&mut signals, "wstrzykniecie", "krytyczny",
                &format!("Mozliwy SQL injection: {}", name),
                "serwer zwrocil komunikat bledu bazy danych - komunikaty szczegolowe ujawniaja architekture",
            );
        }
    }

    // --- path traversal ---
    if out.contains("root:x:") && out.contains("bin/") {
        push(&mut signals, "traversal", "krytyczny", "Odczyt /etc/passwd", "serwer zwrocil zawartosc pliku systemowego - traversal dziala");
    }
    if out.contains("[extensions]") || out.contains("extension_dir") {
        push(&mut signals, "traversal", "krytyczny", "Odczyt phpinfo()", "plik phpinfo.php jest dostepny publicznie");
    }

    // --- panele i wrażliwe pliki ---
    for (pat, title) in [
        ("phpmyadmin", "phpMyAdmin wystawiony"),
        ("administrator/", "panel administracyjny"),
        ("wp-login", "panel logowania WordPress"),
        ("jenkins", "Jenkins wystawiony"),
        ("grafana", "Grafana wystawiona"),
        (".env", "plik .env dostepny"),
        (".git/head", "repozytorium .git wystawione"),
        ("docker-compose.yml", "docker-compose.yml dostepny"),
        ("actuator/env", "Spring Boot actuator wystawiony"),
        ("server-status", "status Apache wystawiony"),
    ] {
        if out.contains(pat) {
            push(&mut signals, "ekspozycja", "wysoki", title, "sciezka odpowiada na HTTP 200 - sprawdz dostepnosc");
        }
    }

    // --- naglowki bledow HTTP ---
    if command.contains("curl") {
        for code in ["401", "403", "500", "502", "503"] {
            if out.contains(&format!("{} ", code)) || stdout.contains(&format!("HTTP/1.1 {}", code)) {
                let lvl = if code == "500" || code == "502" || code == "503" { "wysoki" } else { "info" };
                let detail = match code {
                    "401" => "wymagane uwierzytelnienie",
                    "403" => "brak dostepu (dobra konfiguracja)",
                    _ => "blad serwera - sprawdz logi i stos",
                };
                push(&mut signals, "http", lvl, &format!("HTTP {}", code), detail);
            }
        }
    }

    // --- bledniki ---
    if exit_code != 0 {
        let first = stderr.lines().next().unwrap_or("").trim();
        if !first.is_empty() {
            push(&mut signals, "wykonanie", "info", &format!("Kod wyjscia {}", exit_code), first);
        }
    }

    let critical = signals.iter().filter(|s| s["poziom"] == "krytyczny").count();
    let high = signals.iter().filter(|s| s["poziom"] == "wysoki").count();

    json!({
        "komenda": command,
        "exit_code": exit_code,
        "sygnaly": signals,
        "krytyczne": critical,
        "wysokie": high,
        "podsumowanie": match (critical, high) {
            (0, 0) if signals.is_empty() => "brak rozpoznanych sygnalow - wynik czysty lub niekompletny".to_string(),
            (0, 0) => "kilka obserwacji, brak krytycznych".to_string(),
            (0, n) => format!("{} obserwacji wysokiego ryzyka", n),
            (n, _) => format!("{} krytycznych - wymaga natychmiastowej uwagi", n),
        },
    })
}
