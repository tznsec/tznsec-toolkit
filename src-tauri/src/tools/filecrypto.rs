use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::json;
use std::path::Path;

const MAGIC: &[u8; 8] = b"TZNSECF1";
const KDF_ITERATIONS: u32 = 210_000;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;

/// PBKDF2-HMAC-SHA256, 210k iteracji, wyjscie 256 bitow.
fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), salt, KDF_ITERATIONS, &mut out);
    out
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    OsRng.fill_bytes(&mut v);
    v
}

fn safe_path(input: &str) -> Result<std::path::PathBuf, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Podaj sciezke do pliku".into());
    }
    let p = Path::new(trimmed);
    if !p.is_absolute() {
        return Err("Uzyj pelnej sciezki bezwzglednej, np. C:\\Users\\Ty\\dane.txt".into());
    }
    Ok(p.to_path_buf())
}

/// Szyfruje plik haslem (AES-256-GCM + PBKDF2).
pub fn encrypt_file(input: &str, password: &str) -> serde_json::Value {
    if password.len() < 8 {
        return json!({ "error": "Haslo musi miec min. 8 znakow" });
    }
    let path = match safe_path(input) {
        Ok(p) => p,
        Err(e) => return json!({ "error": e }),
    };
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => return json!({ "error": format!("Nie mozna odczytac pliku: {}", e) }),
    };

    let salt = random_bytes(SALT_LEN);
    let nonce_bytes = random_bytes(NONCE_LEN);
    let key_bytes = derive_key(password, &salt);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = match cipher.encrypt(nonce, data.as_ref()) {
        Ok(c) => c,
        Err(_) => return json!({ "error": "Szyfrowanie nie powiodlo sie" }),
    };

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("bin")
        .to_string();
    let out_path = path.with_extension(format!("{}.tzns", ext));

    let mut blob = Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(MAGIC);
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    if let Err(e) = std::fs::write(&out_path, &blob) {
        return json!({ "error": format!("Nie mozna zapisac: {}", e) });
    }

    json!({
        "ok": true,
        "plik_zrodlowy": path.to_string_lossy(),
        "plik_wyjsciowy": out_path.to_string_lossy(),
        "rozmiar_pliku": data.len(),
        "rozmiar_szyfrogramu": blob.len(),
        "algorytm": "AES-256-GCM",
        "kdf": format!("PBKDF2-HMAC-SHA256, {} iteracji, sol 32 B", KDF_ITERATIONS),
        "uwaga": "Plik zrodlowy pozostaje nienaruszony. Bez hasla odszyfrowanie jest niemozliwe.",
    })
}

/// Odszyfrowuje plik .tzns.
pub fn decrypt_file(input: &str, password: &str) -> serde_json::Value {
    let path = match safe_path(input) {
        Ok(p) => p,
        Err(e) => return json!({ "error": e }),
    };
    let blob = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => return json!({ "error": format!("Nie mozna odczytac: {}", e) }),
    };
    if blob.len() < MAGIC.len() + SALT_LEN + NONCE_LEN + 16 || &blob[..8] != MAGIC {
        return json!({ "error": "To nie plik .tzns (zly naglowek)" });
    }

    let mut off = MAGIC.len();
    let salt = &blob[off..off + SALT_LEN];
    off += SALT_LEN;
    let nonce_bytes = &blob[off..off + NONCE_LEN];
    off += NONCE_LEN;
    let ciphertext = &blob[off..];

    let key_bytes = derive_key(password, salt);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(nonce_bytes);

    match cipher.decrypt(nonce, ciphertext) {
        Ok(plain) => {
            let out_path = path.with_extension("dec");
            if let Err(e) = std::fs::write(&out_path, &plain) {
                return json!({ "error": format!("Nie mozna zapisac: {}", e) });
            }
            json!({
                "ok": true,
                "plik_wyjsciowy": out_path.to_string_lossy(),
                "rozmiar": plain.len(),
                "podglad": String::from_utf8_lossy(&plain).chars().take(400).collect::<String>(),
            })
        }
        Err(_) => json!({ "error": "Nie udalo sie odszyfrowac - zle haslo lub plik uszkodzony" }),
    }
}
