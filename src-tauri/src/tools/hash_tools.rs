use serde_json::json;
use sha2::{Digest, Sha256, Sha512};
use sha1::Sha1;

pub fn hash_text(text: &str, algorithm: &str) -> serde_json::Value {
    let result = match algorithm.to_lowercase().as_str() {
        "md5" => format!("{:x}", md5::compute(text.as_bytes())),
        "sha1" => {
            let mut hasher = Sha1::new();
            hasher.update(text.as_bytes());
            format!("{:x}", hasher.finalize())
        }
        "sha256" => {
            let mut hasher = Sha256::new();
            hasher.update(text.as_bytes());
            format!("{:x}", hasher.finalize())
        }
        "sha512" => {
            let mut hasher = Sha512::new();
            hasher.update(text.as_bytes());
            format!("{:x}", hasher.finalize())
        }
        _ => return json!({ "error": "Nieznany algorytm hashujący" }),
    };

    json!({
        "algorithm": algorithm,
        "input_length": text.len(),
        "hash": result
    })
}
