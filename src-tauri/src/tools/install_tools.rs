use serde_json::json;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Katalog z definicja narzedzi: co mamy, czym zainstalowac, do czego sluzy.
pub fn catalog() -> serde_json::Value {
    json!([
        { "id": "nmap",    "nazwa": "Nmap",        "bin": "nmap",    "opis": "skaner portow, detekcja wersji, skrypty NSE", "winget": "Insecure.Nmap", "pip": "",                "kategoria": "siec" },
        { "id": "masscan", "nazwa": "Masscan",     "bin": "masscan", "opis": "bardzo szybki skaner portow",              "winget": "",            "pip": "",                "kategoria": "siec" },
        { "id": "curl",    "nazwa": "curl",        "bin": "curl",    "opis": "klient HTTP w wierszu polecen",            "winget": "",            "pip": "",                "kategoria": "http" },
        { "id": "git",     "nazwa": "Git",         "bin": "git",     "opis": "repozytorium, diff, eksport raportow",     "winget": "Git.Git",    "pip": "",                "kategoria": "narzedzia" },
        { "id": "sqlmap",  "nazwa": "sqlmap",      "bin": "sqlmap",  "opis": "automatyczny test SQL injection",          "winget": "",            "pip": "sqlmap",         "kategoria": "atak" },
        { "id": "nikto",   "nazwa": "Nikto",       "bin": "nikto",   "opis": "skaner podatnosci aplikacji www",         "winget": "",            "pip": "",                "kategoria": "atak" },
        { "id": "hydra",   "nazwa": "Hydra",       "bin": "hydra",   "opis": "brute force (logowanie, SSH, HTTP)",      "winget": "",            "pip": "hydra",          "kategoria": "atak" },
        { "id": "john",    "nazwa": "John the Ripper", "bin": "john", "opis": "lamacz hasel offline",                  "winget": "",            "pip": "",                "kategoria": "atak" },
        { "id": "hashcat", "nazwa": "hashcat",     "bin": "hashcat", "opis": "lamacz hasel z akceleracja GPU",          "winget": "",            "pip": "",                "kategoria": "atak" },
        { "id": "netcat",  "nazwa": "Netcat",      "bin": "nc",      "opis": "debug TCP, sprawdzanie portow",           "winget": "",            "pip": "",                "kategoria": "siec" },
        { "id": "python",  "nazwa": "Python",      "bin": "python",  "opis": "skrypty pomocnicze do analizy",           "winget": "Python.Python.3.12", "pip": "",            "kategoria": "narzedzia" },
        { "id": "pip",     "nazwa": "pip",         "bin": "pip",     "opis": "menedzer pakietow Pythona",              "winget": "",            "pip": "",                "kategoria": "narzedzia" }
    ])
}

fn has_winget() -> bool {
    Command::new("winget")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn has_pip() -> bool {
    Command::new("pip")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn which(bin: &str) -> bool {
    if cfg!(windows) {
        Command::new("cmd")
            .args(["/C", "where", bin])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    } else {
        Command::new("which")
            .arg(bin)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

/// Stan wszystkich narzedzi + mozliwosc instalacji.
pub fn status() -> serde_json::Value {
    let cat = catalog();
    let mut items: Vec<serde_json::Value> = Vec::new();

    if let Some(arr) = cat.as_array() {
        for t in arr {
            let bin = t["bin"].as_str().unwrap_or("");
            let installed = which(bin);
            let winget = t["winget"].as_str().unwrap_or("");
            let pip = t["pip"].as_str().unwrap_or("");

            let metoda = if !winget.is_empty() {
                Some("winget")
            } else if !pip.is_empty() && has_pip() {
                Some("pip")
            } else {
                None
            };

            items.push(json!({
                "id": t["id"],
                "nazwa": t["nazwa"],
                "opis": t["opis"],
                "kategoria": t["kategoria"],
                "zainstalowane": installed,
                "metoda": metoda,
                "winget_id": winget,
                "pip_paket": pip,
                "polecenie": match metoda {
                    Some("winget") => format!("winget install --id {} -e --accept-source-agreements --accept-package-agreements", winget),
                    Some("pip") => format!("pip install {}", pip),
                    _ => String::new(),
                },
                "dostepne_instalatory": json!({
                    "winget": has_winget(),
                    "pip": has_pip(),
                }),
            }));
        }
    }

    let present = items.iter().filter(|i| i["zainstalowane"] == true).count();
    json!({
        "narzedzia": items,
        "zainstalowane": present,
        "razem": items.len(),
        "instalatory": { "winget": has_winget(), "pip": has_pip() },
    })
}

/// Instaluje narzedzie. Wymaga potwierdzenia uzytkownika w UI.
pub fn install(tool_id: &str) -> serde_json::Value {
    let cat = catalog();
    let item = match cat.as_array().and_then(|a| a.iter().find(|t| t["id"] == tool_id)) {
        Some(i) => i,
        None => return json!({ "error": "Nieznane narzedzie" }),
    };

    let winget = item["winget"].as_str().unwrap_or("");
    let pip = item["pip"].as_str().unwrap_or("");

    let (cmd, args): (String, Vec<String>) = if !winget.is_empty() && has_winget() {
        (
            "winget".into(),
            vec![
                "install".into(),
                "--id".into(),
                winget.into(),
                "-e".into(),
                "--accept-source-agreements".into(),
                "--accept-package-agreements".into(),
                "--silent".into(),
                "--disable-interactivity".into(),
            ],
        )
    } else if !pip.is_empty() && has_pip() {
        ("pip".into(), vec!["install".into(), pip.into()])
    } else {
        return json!({
            "error": "Brak dostepnego instalatora",
            "instrukcja": if !winget.is_empty() {
                "Zainstaluj recznie: winget install --id <ID> -e"
            } else {
                "Zainstaluj recznie: pip install <PAKIET>"
            }
        });
    };

    let mut child = match Command::new(&cmd)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return json!({ "error": format!("Nie mozna uruchomic {}: {}", cmd, e) }),
    };

    // instalacja moze trwac dlugo
    let start = Instant::now();
    let limit = Duration::from_secs(900);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut out = String::new();
                if let Some(mut s) = child.stdout.take() {
                    use std::io::Read;
                    let _ = s.read_to_string(&mut out);
                }
                let code = status.code().unwrap_or(-1);
                let bin = item["bin"].as_str().unwrap_or("");
                let ok = which(bin);
                return json!({
                    "ok": code == 0 || ok,
                    "exit_code": code,
                    "narzedzie": item["nazwa"],
                    "zainstalowane": ok,
                    "czas_s": start.elapsed().as_secs(),
                    "wyjscie": out.chars().take(1500).collect::<String>(),
                    "uwaga": if code != 0 && !ok {
                        "Instalacja zakonczona bledem - sprawdz uprawnienia (moze wymagac admina)"
                    } else {
                        "Gotowe. Niektore narzedzia wymagaja restartu aplikacji lub nowego terminala."
                    },
                });
            }
            Ok(None) => {
                if start.elapsed() > limit {
                    let _ = child.kill();
                    return json!({ "error": "Instalacja przekroczyla 15 min - przerwano" });
                }
                std::thread::sleep(Duration::from_millis(400));
            }
            Err(e) => return json!({ "error": e.to_string() }),
        }
    }
}
