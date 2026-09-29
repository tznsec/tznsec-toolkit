use serde_json::json;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const MAX_OUTPUT: usize = 6000;
const MAX_FILE_BYTES: usize = 2 * 1024 * 1024;

/// Katalog roboczy - jedyne miejsce, w ktorym AI moze zapisywac pliki.
pub fn workspace() -> PathBuf {
    let base = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".into());
    Path::new(&base).join("Documents").join("tznsec-workspace")
}

pub fn ensure_workspace() -> std::io::Result<PathBuf> {
    let d = workspace();
    std::fs::create_dir_all(&d)?;
    Ok(d)
}

/// Blokuje wyjscie poza katalog roboczy (obejście przez .., symlinki, absolutne sciezki).
fn resolve_in_workspace(input: &str) -> Result<PathBuf, String> {
    let root = ensure_workspace().map_err(|e| e.to_string())?;
    let root = root.canonicalize().map_err(|e| e.to_string())?;

    let p = Path::new(input.trim());
    if p.is_absolute() {
        // absolutna - musi zawierac sie w workspace
        let joined = p.to_path_buf();
        let canon = joined.canonicalize().unwrap_or(joined);
        if !canon.starts_with(&root) {
            return Err("Sciezka poza katalogem roboczym zablokowana".into());
        }
        return Ok(canon);
    }

    // relatywna - odrzucamy komponenty ucieczki
    for c in p.components() {
        match c {
            Component::ParentDir => return Err("Wspozmienna '..' zablokowana".into()),
            Component::Prefix(_) | Component::RootDir => {
                return Err("Sciezki bezwzgledne zablokowane".into())
            }
            _ => {}
        }
    }
    let joined = root.join(p);
    let canon = joined.canonicalize().unwrap_or(joined);
    if !canon.starts_with(&root) {
        return Err("Sciezka poza katalogiem roboczym zablokowana".into());
    }
    Ok(canon)
}

const HIGH_RISK: &[(&str, &str)] = &[
    ("format ", "formatuje dysk - nieodwracalne"),
    ("diskpart", "zarzadza dyskami"),
    ("rm -rf /", "kasuje caly system"),
    ("del /f /s /q c:", "kasuje dysk C"),
    ("remove-item", "usuwa pliki"),
    ("rd /s /q", "usuwa katalogi"),
    ("cipher /w", "nadpisuje wolne miejsce"),
    ("bcdedit", "modyfikuje bootlader"),
    ("reg delete", "kasuje wpisy rejestru"),
    ("takeown", "przejmuje wlasnosc plikow"),
    ("icacls", "zmienia uprawnienia"),
    ("net user", "zarzadza kontami"),
    ("net localgroup", "zarzadza grupami"),
    ("sc create", "instaluje usluge"),
    ("sc delete", "usuwa usluge"),
    ("schtasks /create", "tworzy zadanie w harmonogramie"),
    ("shutdown", "wylacza system"),
    ("vssadmin delete", "kasuje kopie zapasowe"),
    ("wmic", "stare narzedzie administracyjne"),
    ("winget install", "instaluje oprogramowanie"),
    ("choco install", "instaluje oprogramowanie"),
    ("pip install", "instaluje pakiety"),
    ("npm install", "instaluje pakiety"),
    ("npm i -g", "instaluje globalnie"),
    ("cargo install", "instaluje narzedzia"),
    ("git push", "wysyla zmiany do zdalnego repozytorium"),
    ("set-executionpolicy", "zmienia polityke PowerShell"),
    ("add-mppreference", "zmienia konfiguracje Defendera"),
    ("set-mppreference", "wylacza ochrone Defendera"),
];

const MEDIUM_RISK: &[&str] = &[
    "nmap", "netcat", "nc ", "masscan", "sqlmap", "nikto", "hydra", "john",
    "hashcat", "curl", "wget", "invoke-webrequest", "invoke-restmethod",
    "powershell", "cmd /c", "start ", "taskkill", "stop-process", "reg add",
    "curl.exe -o", "certutil -decode", "bitsadmin", "webrequest",
];

/// Ocena ryzyka komendy - informuje UI, czy wymaga to dodatkowego potwierdzenia.
pub fn classify(command: &str) -> (&'static str, String) {
    let c = command.to_lowercase();
    for (pat, why) in HIGH_RISK {
        if c.contains(pat) {
            return ("high", why.to_string());
        }
    }
    for pat in MEDIUM_RISK {
        if c.contains(pat) {
            return ("medium", format!("wykonuje: {}", pat.trim()));
        }
    }
    ("low", String::new())
}

/// Wykonuje komende w katalogu roboczym. Wywolywane wylacznie po potwierdzeniu uzytkownika.
pub fn exec(command: &str, timeout_secs: u64) -> serde_json::Value {
    let cmd = command.trim();
    if cmd.is_empty() {
        return json!({ "error": "Pusta komenda" });
    }
    if cmd.len() > 2000 {
        return json!({ "error": "Komenda za dluga (max 2000 znakow)" });
    }

    let dir = match ensure_workspace() {
        Ok(d) => d,
        Err(e) => return json!({ "error": e.to_string() }),
    };

    let mut child = if cfg!(windows) {
        Command::new("cmd")
            .args(["/C", cmd])
            .current_dir(&dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    } else {
        Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .current_dir(&dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    };

    let mut child = match child {
        Ok(c) => c,
        Err(e) => return json!({ "error": format!("Nie mozna uruchomic: {}", e) }),
    };

    // ograniczony czas wykonania
    let limit = Duration::from_secs(timeout_secs.clamp(1, 600));
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) => {
                if start.elapsed() > limit {
                    let _ = child.kill();
                    let _ = child.wait();
                    return json!({
                        "ok": false,
                        "error": format!("Przekroczono limit {} s - proces przerwany", timeout_secs),
                    });
                }
                std::thread::sleep(Duration::from_millis(60));
            }
            Err(e) => return json!({ "error": e.to_string() }),
        }
    }

    let mut out = String::new();
    let mut err = String::new();
    if let Some(mut s) = child.stdout.take() {
        let _ = s.read_to_string(&mut out);
    }
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_string(&mut err);
    }
    let status = child.wait().ok().and_then(|s| s.code()).unwrap_or(-1);

    let trunc = |s: &str| -> String {
        let t = s.trim();
        if t.chars().count() > MAX_OUTPUT {
            format!("{}\n… (przycięto do {} znaków)", t.chars().take(MAX_OUTPUT).collect::<String>(), MAX_OUTPUT)
        } else {
            t.to_string()
        }
    };

    json!({
        "ok": status == 0,
        "exit_code": status,
        "katalog": dir.to_string_lossy(),
        "stdout": trunc(&out),
        "stderr": trunc(&err),
        "czas_ms": start.elapsed().as_millis(),
    })
}

pub fn write_file(path: &str, content: &str) -> serde_json::Value {
    let target = match resolve_in_workspace(path) {
        Ok(p) => p,
        Err(e) => return json!({ "error": e }),
    };
    if content.len() > MAX_FILE_BYTES {
        return json!({ "error": "Plik za duzy (max 2 MB)" });
    }
    if let Some(parent) = target.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::write(&target, content) {
        Ok(_) => json!({
            "ok": true,
            "sciezka": target.to_string_lossy(),
            "bajty": content.len(),
        }),
        Err(e) => json!({ "error": e.to_string() }),
    }
}

pub fn read_file(path: &str) -> serde_json::Value {
    let target = match resolve_in_workspace(path) {
        Ok(p) => p,
        Err(e) => return json!({ "error": e }),
    };
    match std::fs::read(&target) {
        Ok(d) => {
            let s = String::from_utf8_lossy(&d);
            let clipped: String = s.chars().take(MAX_OUTPUT).collect();
            json!({
                "ok": true,
                "sciezka": target.to_string_lossy(),
                "bajty": d.len(),
                "tresc": clipped,
            })
        }
        Err(e) => json!({ "error": e.to_string() }),
    }
}

pub fn list_dir(path: &str) -> serde_json::Value {
    let target = if path.trim().is_empty() {
        match ensure_workspace() {
            Ok(d) => d,
            Err(e) => return json!({ "error": e.to_string() }),
        }
    } else {
        match resolve_in_workspace(path) {
            Ok(p) => p,
            Err(e) => return json!({ "error": e }),
        }
    };
    match std::fs::read_dir(&target) {
        Ok(rd) => {
            let mut items: Vec<serde_json::Value> = Vec::new();
            for e in rd.flatten().take(300) {
                let is_dir = e.path().is_dir();
                let size = e.metadata().ok().map(|m| m.len()).unwrap_or(0);
                items.push(json!({
                    "nazwa": e.file_name().to_string_lossy(),
                    "katalog": is_dir,
                    "bajty": size,
                }));
            }
            json!({ "ok": true, "sciezka": target.to_string_lossy(), "liczba": items.len(), "elementy": items })
        }
        Err(e) => json!({ "error": e.to_string() }),
    }
}

/// Wyciaga wywolania narzedzi z odpowiedzi modelu.
/// Format: blok json z polem "tool", np.
/// ```json
/// {"tool": "run_command", "args": {"command": "nmap -p 1-100 127.0.0.1"}}
/// ```
pub fn parse_tool_calls(text: &str) -> Vec<serde_json::Value> {
    const KNOWN: &[&str] = &["run_command", "write_file", "read_file", "list_dir"];
    let mut found = Vec::new();

    // 1. skanuj bloki ```json ... ``` oraz zwykle { ... }
    let bytes: Vec<char> = text.chars().collect();
    let mut i = 0usize;
    let n = bytes.len();

    while i < n {
        // szukamy poczatku obiektu json
        if bytes[i] == '{' {
            let start = i;
            let mut depth = 0i32;
            let mut in_str = false;
            let mut esc = false;
            let mut end = None;

            while i < n {
                let c = bytes[i];
                if in_str {
                    if esc {
                        esc = false;
                    } else if c == '\\' {
                        esc = true;
                    } else if c == '"' {
                        in_str = false;
                    }
                } else if c == '"' {
                    in_str = true;
                } else if c == '{' {
                    depth += 1;
                } else if c == '}' {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(i);
                        break;
                    }
                }
                i += 1;
            }
            let end = match end {
                Some(e) => e,
                None => {
                    i = start + 1;
                    continue;
                }
            };

            let chunk: String = bytes[start..=end].iter().collect();
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&chunk) {
                if let Some(t) = v.get("tool").and_then(|t| t.as_str()) {
                    if KNOWN.contains(&t) {
                        found.push(json!({
                            "tool": t,
                            "args": v.get("args").cloned().unwrap_or(json!({})),
                            "raw": chunk,
                        }));
                    }
                }
            }
            i = end + 1;
        } else {
            i += 1;
        }
    }
    found
}

/// Opis dostepnych narzedzi wplatany do promptu systemowego.
pub fn tools_prompt() -> String {
    format!(
        "DOSTEPNE NARZEDZIA (wymagaja zgody uzytkownika - kazda akcja jest pokazywana do akceptacji):\n\
         1. run_command  {{\"tool\":\"run_command\",\"args\":{{\"command\":\"...\"}}}}\n\
         2. write_file   {{\"tool\":\"write_file\",\"args\":{{\"path\":\"raport.md\",\"content\":\"...\"}}}}\n\
         3. read_file    {{\"tool\":\"read_file\",\"args\":{{\"path\":\"raport.md\"}}}}\n\
         4. list_dir     {{\"tool\":\"list_dir\",\"args\":{{\"path\":\"\"}}}}\n\n\
         ZASADY UZYCIA NARZEDZI:\n\
         - Narzedzia wolasz wypisujac w bloku json w tresci odpowiedzi.\n\
         - Mozesz zaproponowac kilka wywolan w jednej odpowiedzi.\n\
         - Uzytkownik moze kazde wywolanie odrzucic - jesli odrzuci, nie probuj ponowic\n\
           i zaproponuj inacze.\n\
         - Sciezki plikow musza byc wzgledne do katalogu roboczego: {}\n\
         - Nie proponuj komend kasujacych system, formatujacych dysk, wylaczajacych\n\
           ochrone (Defender, firewall) ani modyfikujacych boot.\n\
         - Nie proponuj komend, ktore moga zaklopotac innych uzytkownikow w sieci.\n\
         - Preferuj najpierw bezpieczne komendy odczytujace (nmap -sV, curl -I, whoami, ipconfig).\n\
         - Zawsze podsumuj wynik dla czloweka po wykonaniu narzedzia.",
        workspace().to_string_lossy()
    )
}
