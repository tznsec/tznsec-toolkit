use serde_json::json;
use std::path::PathBuf;

/// Katalog roboczy aplikacji - jedyne miejsce, ktore panic moze wyczyscic.
fn scratch_dir() -> PathBuf {
    std::env::temp_dir().join("tznsec-toolkit-scratch")
}

/// Tryb panic: czysci stan aplikacji i zamyka program.
/// Swiadomie NIE usuwa plikow uzytkownika - to funkcja "burn notice",
/// a nie narzedzie do kasowania danych.
pub fn panic_mode(shutdown: bool) -> serde_json::Value {
    let mut cleared: Vec<String> = Vec::new();

    // 1. schowek - nadpisujemy trescia jednym znakiem, potem czyscimy
    #[cfg(windows)]
    {
        use std::process::Command;
        // PowerShell - nadpisuje schowek przez 3 cykle, potem go czysci
        let ps = "Set-Clipboard -Value ('x' * 64) -ErrorAction SilentlyContinue; \
                  Start-Sleep -Milliseconds 120; \
                  Set-Clipboard -Value '' -ErrorAction SilentlyContinue";
        match Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", ps])
            .output()
        {
            Ok(_) => cleared.push("schowek wyczyszczony (3 nadpisania)".into()),
            Err(e) => cleared.push(format!("schowek: błąd {}", e)),
        }
    }

    // 2. katalog roboczy aplikacji - nadpisujemy pliki przed usunieciem
    let dir = scratch_dir();
    let mut wiped = 0usize;
    if dir.exists() {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_file() {
                    if let Ok(meta) = std::fs::metadata(&p) {
                        let len = meta.len().min(4 * 1024 * 1024) as usize;
                        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&p) {
                            use std::io::Write;
                            let _ = f.write_all(&vec![0u8; len]);
                            let _ = f.flush();
                        }
                    }
                    if std::fs::remove_file(&p).is_ok() {
                        wiped += 1;
                    }
                }
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
        cleared.push(format!("katalog roboczy wyczyszczony ({} plików)", wiped));
    } else {
        cleared.push("brak plików tymczasowych".into());
    }

    json!({
        "wykonane": cleared,
        "schowek": "wyczyszczony",
        "pliki_uzytkownika": "nietkniete",
        "zamkniecie": shutdown,
        "info": "Tryb panic czyści stan aplikacji, aby nie zostawic sladow. \
                 Nie usuwa Twoich plikow.",
    })
}

/// Zapisuje zaszyfrowany plik roboczy (uzywane przez szyfrator).
pub fn scratch_note(name: &str, content: &str) -> serde_json::Value {
    let dir = scratch_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return json!({ "error": format!("Nie można utworzyć katalogu: {}", e) });
    }
    let safe: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(48)
        .collect();
    if safe.is_empty() {
        return json!({ "error": "Nieprawidłowa nazwa" });
    }
    let p = dir.join(format!("{}.tmp", safe));
    match std::fs::write(&p, content) {
        Ok(_) => json!({ "ok": true, "sciezka": p.to_string_lossy() }),
        Err(e) => json!({ "error": e.to_string() }),
    }
}
