use serde_json::json;
use std::collections::HashMap;
use std::sync::OnceLock;

fn crc_table() -> &'static [u32; 256] {
    static T: OnceLock<[u32; 256]> = OnceLock::new();
    T.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            *e = c;
        }
        t
    })
}

fn crc32(data: &[u8]) -> u32 {
    let t = crc_table();
    let mut c = 0xFFFF_FFFFu32;
    for b in data {
        c = t[((c ^ *b as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    !c
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for byte in data {
        a = (a + *byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

fn sum8(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |a, b| a.wrapping_add(*b))
}

/// Rozpoznaje format hasha po długości i zbiorze znaków.
pub fn hash_identify(input: &str) -> serde_json::Value {
    let h = input.trim();
    if h.is_empty() {
        return json!({ "error": "Wklej skrót" });
    }

    let hex_like = h.chars().all(|c| c.is_ascii_hexdigit());
    let base64ish = h.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-' || c == '_');
    let b32 = h.chars().all(|c| c.is_ascii_uppercase() || ('A'..='Z').contains(&c) || "234567=".contains(c));

    let mut cands: Vec<(&str, &str)> = Vec::new();
    match h.len() {
        32 if hex_like => cands.push(("MD5", "16 bajtów, najczęstszy skrót hasła/pliku")),
        40 if hex_like => cands.push(("SHA-1", "20 bajtów, git commits, certyfikaty podpisu")),
        56 if hex_like => cands.push(("SHA-224", "28 bajtów")),
        64 if hex_like => cands.push(("SHA-256", "32 bajty, standard dla haseł i plików")),
        96 if hex_like => cands.push(("SHA-384", "48 bajtów")),
        128 if hex_like => cands.push(("SHA-512", "64 bajty")),
        40 if b32 => cands.push(("RIPEMD-160", "zwykle base32")),
        _ => {}
    }

    let kind = if h.chars().all(|c| c.is_ascii_digit()) && h.len() <= 10 {
        "może być skrótem CRC32"
    } else if h.contains('$') && h.starts_with("$") {
        "format crypt (unix $id$salt$hash)"
    } else if h.starts_with("$argon2") {
        "argon2 (krypt)"
    } else if h.starts_with("$2") {
        "bcrypt"
    } else if h.len() == 60 && h.contains('$') {
        "bcrypt / sha256crypt"
    } else {
        "nieznany"
    };

    json!({
        "dlugosc": h.len(),
        "znaki": if hex_like { "hex" } else if b32 { "base32" } else if base64ish { "base64" } else { "mieszane" },
        "rozpoznania": cands.iter().map(|(n, d)| json!({"algorytm": n, "opis": d})).collect::<Vec<_>>(),
        "wniosek": if cands.is_empty() { kind } else { cands[0].0 },
        "roznica_znakow": h.chars().collect::<Vec<_>>().windows(2).all(|w| w[0] != w[1]),
    })
}

pub fn checksum(text: &str) -> serde_json::Value {
    use base64::{engine::general_purpose, Engine as _};
    let b = text.as_bytes();
    let b64 = general_purpose::STANDARD.encode(b);
    json!({
        "CRC32": format!("0x{:08x} ({})", crc32(b), crc32(b)),
        "CRC32_dziesietnie": crc32(b),
        "Adler32": format!("0x{:08x}", adler32(b)),
        "Suma_8bit": sum8(b),
        "Suma_16bit": b.iter().fold(0u16, |a, c| a.wrapping_add(*c as u16)),
        "Rozmiar": b.len(),
        "Base64": b64,
    })
}

/// Entropia Shannona (bitów na znak) + ocena, czy dane wyglądają na zaszyfrowane/skompresowane.
pub fn entropy_analysis(text: &str) -> serde_json::Value {
    let b = text.as_bytes();
    if b.is_empty() {
        return json!({ "error": "Brak danych" });
    }
    let mut freq: HashMap<u8, usize> = HashMap::new();
    for c in b {
        *freq.entry(*c).or_insert(0usize) += 1;
    }
    let n = b.len() as f64;
    let mut h = 0.0f64;
    for cnt in freq.values() {
        let p = *cnt as f64 / n;
        h -= p * p.log2();
    }

    let printable = b.iter().filter(|c| (**c as i32) >= 32 && (**c as i32) < 127).count() as f64 / n;
    let verdict = if h > 7.5 && printable < 0.85 {
        "wysoka entropia — możliwe szyfrowanie, kompresja lub plik binarny"
    } else if h > 6.5 {
        "wysoka entropia — kodowanie (base64/hex) lub tekst o równomiernych znakach"
    } else if h > 4.5 {
        "typowy tekst / kod źródłowy"
    } else {
        "niska entropia — powtarzalny wzorzec (np. padding, zera)"
    };

    json!({
        "entropia": format!("{:.3}", h),
        "bajty": b.len(),
        "znaki_unikalne": freq.len(),
        "znaki_drukowalne": format!("{:.1}%", printable * 100.0),
        "ocena": verdict,
    })
}

/// Skanuje tekst pod sekrety i klucze API (zastosowanie obronne).
pub fn secret_scan(text: &str) -> serde_json::Value {
    let mut found: Vec<serde_json::Value> = Vec::new();

    let patterns: Vec<(&str, &str, &str)> = vec![
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", "krytyczne"),
        (r"ghp_[A-Za-z0-9]{36}", "GitHub token", "krytyczne"),
        (r"github_pat_[A-Za-z0-9_]{22,}", "GitHub fine-grained PAT", "krytyczne"),
        (r"sk-[A-Za-z0-9]{20,}", "OpenAI / sk- token", "krytyczne"),
        (r"xox[baprs]-[A-Za-z0-9-]{10,}", "Slack token", "krytyczne"),
        (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key", "krytyczne"),
        (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JWT w kodzie", "wysokie"),
        (r"-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", "klucz prywatny", "krytyczne"),
        (r#"(?i)password\s*[:=]\s*["'][^"']{4,}["']"#, "hasło w kodzie", "wysokie"),
        (r#"(?i)(api[_-]?key|secret|token)\s*[:=]\s*["'][A-Za-z0-9_\-]{12,}["']"#, "klucz/sekret w kodzie", "wysokie"),
        (r"[a-zA-Z0-9._%+-]+:[^@\s/]+@[a-zA-Z0-9.-]+", "dane w URL (user:pass@host)", "średnie"),
        (r#"postgres(ql)?://[^\s"']+"#, "DSN bazy danych", "wysokie"),
        (r#"mongodb(\+srv)?://[^\s"']+"#, "DSN MongoDB", "wysokie"),
    ];

    for (pat, name, sev) in patterns {
        let re = match regex::Regex::new(pat) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for m in re.find_iter(text).take(20) {
            let raw = m.as_str();
            let masked = if raw.len() <= 12 {
                raw.to_string()
            } else {
                format!("{}{}{}", &raw[..6], "…", &raw[raw.len().saturating_sub(4)..])
            };
            found.push(json!({
                "typ": name,
                "poważność": sev,
                "linia": text[..m.start()].lines().count() + 1,
                "fragment": masked,
            }));
        }
    }

    // entropia długich ciągów - możliwe przypadkowe sekrety
    let re = regex::Regex::new(r"[A-Za-z0-9+/=_\-]{24,}").unwrap();
    for m in re.find_iter(text).take(40) {
        let s = m.as_str();
        let mut freq = std::collections::HashMap::new();
        for c in s.chars() {
            *freq.entry(c).or_insert(0usize) += 1;
        }
        let n = s.chars().count() as f64;
        let h: f64 = freq.values().map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        }).sum();
        if h > 4.0 && !s.chars().all(|c| c.is_ascii_digit()) {
            found.push(json!({
                "typ": "losowy ciąg znaków (kandydat na klucz)",
                "poważność": "średnie",
                "linia": text[..m.start()].lines().count() + 1,
                "fragment": format!("{}…{} ({} znaków)", &s[..8], &s[s.len().saturating_sub(4)..], s.len()),
            }));
        }
    }

    let critical = found.iter().filter(|f| f["poważność"] == "krytyczne").count();
    json!({
        "znaleziono": found.len(),
        "krytycznych": critical,
        "status": if critical > 0 { "WYCIEK — natychmiast unieważnij klucze" }
                  else if !found.is_empty() { "podejrzane ciągi — zweryfikuj" }
                  else { "nie znaleziono typowych sekretów" },
        "trafienia": found,
    })
}
