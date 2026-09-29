use serde_json::json;
use std::collections::HashMap;

pub fn analyze_headers(headers: &HashMap<String, String>) -> serde_json::Value {
    let mut security_headers = HashMap::new();
    let mut missing_headers = Vec::new();
    let mut present_headers = Vec::new();

    let important_headers = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    ];

    for header in &important_headers {
        let found = headers.iter().find(|(k, _)| k.to_lowercase() == *header);
        match found {
            Some((k, v)) => {
                security_headers.insert(k.clone(), v.clone());
                present_headers.push(header.to_string());
            }
            None => missing_headers.push(header.to_string()),
        }
    }

    let score = (present_headers.len() as f64 / important_headers.len() as f64 * 100.0) as u32;

    json!({
        "security_score": score,
        "present_headers": present_headers,
        "missing_headers": missing_headers,
        "security_headers": security_headers,
        "total_headers": headers.len()
    })
}
