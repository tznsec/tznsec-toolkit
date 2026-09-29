use base64::{engine::general_purpose, Engine as _};
use serde_json::{json, Value};

pub fn analyze_jwt(token: &str) -> serde_json::Value {
    let parts: Vec<&str> = token.split('.').collect();
    
    if parts.len() != 3 {
        return json!({ "error": "Nieprawidłowy format JWT (wymagane 3 części)" });
    }

    let decode_part = |part: &str| -> Result<Value, String> {
        let padded = match part.len() % 4 {
            0 => part.to_string(),
            n => format!("{}{}", part, "=".repeat(4 - n)),
        };
        general_purpose::URL_SAFE_NO_PAD
            .decode(padded.as_bytes())
            .map_err(|e| e.to_string())
            .and_then(|bytes| {
                serde_json::from_slice(&bytes).map_err(|e| e.to_string())
            })
    };

    let header = match decode_part(parts[0]) {
        Ok(h) => h,
        Err(e) => return json!({ "error": format!("Błąd nagłówka: {}", e) }),
    };

    let payload = match decode_part(parts[1]) {
        Ok(p) => p,
        Err(e) => return json!({ "error": format!("Błąd payload: {}", e) }),
    };

    let signature = parts[2];
    let signature_len = signature.len();

    json!({
        "header": header,
        "payload": payload,
        "signature_length": signature_len,
        "is_valid_format": true,
        "algorithm": header.get("alg").and_then(|a| a.as_str()).unwrap_or("unknown"),
        "token_type": header.get("typ").and_then(|t| t.as_str()).unwrap_or("unknown")
    })
}
