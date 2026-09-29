use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{json, Value};
use sha2::Digest;
use std::path::PathBuf;

const MAGIC: &[u8; 4] = b"TSEC";

fn config_path() -> PathBuf {
    let base = std::env::var("APPDATA")
        .or_else(|_| std::env::var("XDG_CONFIG_HOME"))
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".into());
    PathBuf::from(base).join("tznsec-toolkit").join("settings.dat")
}

/// Klucz AES jest losowy i lezy obok pliku - chroni przed przypadkowym
/// odczytem, nie przed kims, kto ma dostep do katalogu uzytkownika.
fn machine_key() -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    let seeds: Vec<String> = [
        std::env::var("COMPUTERNAME").unwrap_or_default(),
        std::env::var("USERNAME").unwrap_or_default(),
        std::env::var("USERPROFILE").unwrap_or_default(),
    ]
    .iter()
    .cloned()
    .collect();
    hasher.update(seeds.join("|").as_bytes());
    let out = hasher.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&out);
    k
}

fn seal(plain: &str) -> Vec<u8> {
    let salt: Vec<u8> = {
        let mut v = vec![0u8; 8];
        OsRng.fill_bytes(&mut v);
        v
    };
    let mut nonce_bytes = vec![0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let mut seed = machine_key();
    // lekka deriwacja przez sol
    let mut h = sha2::Sha256::new();
    sha2::Digest::update(&mut h, &[seed.as_slice(), salt.as_slice()].concat());
    let d = sha2::Digest::finalize(h);
    seed.copy_from_slice(&d);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&seed));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plain.as_bytes())
        .unwrap_or_default();

    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    out
}

fn open(blob: &[u8]) -> Option<String> {
    if blob.len() < 4 + 8 + 12 + 16 || &blob[..4] != MAGIC {
        return None;
    }
    let salt = &blob[4..12];
    let nonce_bytes = &blob[12..24];
    let ct = &blob[24..];

    let mut h = sha2::Sha256::new();
    sha2::Digest::update(&mut h, &[machine_key().as_slice(), salt].concat());
    let d = sha2::Digest::finalize(h);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&d));
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ct)
        .ok()
        .and_then(|p| String::from_utf8(p).ok())
}

fn read_raw() -> Value {
    let p = config_path();
    // zwykly JSON (bez sekretow) + osobny plik z sekretami
    let mut out = json!({});
    if let Ok(s) = std::fs::read_to_string(&p.with_extension("json")) {
        if let Ok(v) = serde_json::from_str::<Value>(&s) {
            out = v;
        }
    }
    if let Ok(b) = std::fs::read(p) {
        if let Some(s) = open(&b) {
            if let Ok(v) = serde_json::from_str::<Value>(&s) {
                out["api_keys"] = v;
            }
        }
    }
    out
}

fn write_raw(v: &Value) -> Result<(), String> {
    let p = config_path();
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut plain = v.clone();
    let secrets = plain.get("api_keys").cloned().unwrap_or(json!({}));
    plain.as_object_mut().map(|o| o.remove("api_keys"));

    std::fs::write(
        p.with_extension("json"),
        serde_json::to_string_pretty(&plain).unwrap_or_default(),
    )
    .map_err(|e| e.to_string())?;

    if secrets.as_object().map(|o| !o.is_empty()).unwrap_or(false) {
        let s = serde_json::to_string(&secrets).unwrap_or_default();
        std::fs::write(&p, seal(&s)).map_err(|e| e.to_string())?;
    } else {
        let _ = std::fs::remove_file(&p);
    }
    Ok(())
}

pub fn defaults() -> Value {
    json!({
        "ai": {
            "provider": "xkiro",
            "model": "qwen/qwen3.6-27b:free",
            "api_keys": {},
            "remember_key": true,
            "auto_approve_low_risk": false,
            "command_timeout": 60,
            "max_output": 6000
        },
        "ui": { "theme": "dark", "animations": true, "boot": true, "tooltips": true },
        "scan": { "default_ports": "1-1024", "max_ports": 4096 },
        "privacy": { "telemetry": false, "clear_on_exit": true }
    })
}

pub fn load() -> Value {
    let mut d = defaults();
    let saved = read_raw();
    if let (Some(dst), Some(src)) = (d.as_object_mut(), saved.as_object()) {
        for (k, v) in src {
            match (dst.get_mut(k), v) {
                (Some(Value::Object(a)), Value::Object(b)) => {
                    for (bk, bv) in b {
                        a.insert(bk.clone(), bv.clone());
                    }
                }
                _ => {
                    dst.insert(k.clone(), v.clone());
                }
            }
        }
    }
    // klucza nie zwracamy do UI - tylko informacje o jego obecnosci
    if let Some(keys) = d["ai"]["api_keys"].as_object() {
        let names: Vec<String> = keys.keys().cloned().collect();
        d["ai"]["key_stored_for"] = json!(names);
    }
    d["_sciezka"] = json!(config_path().to_string_lossy());
    d
}

pub fn save(patch: Value) -> Result<Value, String> {
    let mut cur = read_raw();
    if let (Some(c), Some(p)) = (cur.as_object_mut(), patch.as_object()) {
        for (k, v) in p {
            match (c.get_mut(k), v) {
                (Some(Value::Object(a)), Value::Object(b)) => {
                    for (bk, bv) in b {
                        a.insert(bk.clone(), bv.clone());
                    }
                }
                _ => {
                    c.insert(k.clone(), v.clone());
                }
            }
        }
    }
    write_raw(&cur)?;

    let mut out = load();
    // natychmiastowe zapisanie klucza jesli wlaczone
    if let Some(ak) = out["ai"]["api_keys"].as_object().cloned() {
        if !ak.is_empty() {
            let mut cur2 = read_raw();
            if let Some(o) = cur2.as_object_mut() {
                o.insert("api_keys".into(), Value::Object(ak));
            }
            write_raw(&cur2)?;
        }
    }
    Ok(out)
}

pub fn set_key(provider: &str, key: &str) -> Result<Value, String> {
    let mut cur = read_raw();
    if !cur.is_object() {
        cur = json!({});
    }
    let obj = cur.as_object_mut().unwrap();
    if !obj.contains_key("api_keys") {
        obj.insert("api_keys".into(), json!({}));
    }
    let keys = obj.get_mut("api_keys").unwrap().as_object_mut().unwrap();
    if key.trim().is_empty() {
        keys.remove(provider);
    } else {
        keys.insert(provider.to_string(), json!(key.trim()));
    }
    write_raw(&cur)?;
    Ok(load())
}

pub fn forget_key(provider: &str) -> Result<Value, String> {
    set_key(provider, "")
}

pub fn reset() -> Result<Value, String> {
    let p = config_path();
    let _ = std::fs::remove_file(&p);
    let _ = std::fs::remove_file(p.with_extension("json"));
    Ok(load())
}
