use base64::{engine::general_purpose, Engine as _};
use serde_json::json;
use urlencoding::{decode, encode};

pub fn base64_operation(text: &str, mode: &str) -> serde_json::Value {
    match mode {
        "encode" => {
            let encoded = general_purpose::STANDARD.encode(text.as_bytes());
            json!({ "result": encoded, "mode": "encode" })
        }
        "decode" => {
            match general_purpose::STANDARD.decode(text.as_bytes()) {
                Ok(decoded) => {
                    let result = String::from_utf8_lossy(&decoded).to_string();
                    json!({ "result": result, "mode": "decode" })
                }
                Err(e) => json!({ "error": format!("Błąd dekodowania: {}", e) }),
            }
        }
        _ => json!({ "error": "Nieznany tryb. Użyj 'encode' lub 'decode'" }),
    }
}

pub fn url_operation(text: &str, mode: &str) -> serde_json::Value {
    match mode {
        "encode" => {
            let encoded = encode(text);
            json!({ "result": encoded.to_string(), "mode": "encode" })
        }
        "decode" => {
            let decoded = decode(text).unwrap_or_default();
            json!({ "result": decoded.to_string(), "mode": "decode" })
        }
        _ => json!({ "error": "Nieznany tryb. Użyj 'encode' lub 'decode'" }),
    }
}

pub fn hex_operation(text: &str, mode: &str) -> serde_json::Value {
    match mode {
        "encode" => {
            let encoded = hex::encode(text.as_bytes());
            json!({ "result": encoded, "mode": "encode" })
        }
        "decode" => {
            match hex::decode(text) {
                Ok(decoded) => {
                    let result = String::from_utf8_lossy(&decoded).to_string();
                    json!({ "result": result, "mode": "decode" })
                }
                Err(e) => json!({ "error": format!("Błąd dekodowania: {}", e) }),
            }
        }
        _ => json!({ "error": "Nieznany tryb. Użyj 'encode' lub 'decode'" }),
    }
}
