use serde_json::json;

pub fn check_strength(password: &str) -> serde_json::Value {
    let length = password.len();
    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());
    
    let mut score = 0;
    let mut feedback = Vec::new();

    if length >= 8 { score += 1; } else { feedback.push("Hasło powinno mieć min. 8 znaków"); }
    if length >= 12 { score += 1; }
    if length >= 16 { score += 1; }
    if has_uppercase { score += 1; } else { feedback.push("Dodaj wielkie litery"); }
    if has_lowercase { score += 1; } else { feedback.push("Dodaj małe litery"); }
    if has_digit { score += 1; } else { feedback.push("Dodaj cyfry"); }
    if has_special { score += 1; } else { feedback.push("Dodaj znaki specjalne"); }

    let strength = match score {
        0..=2 => "Słabe",
        3..=4 => "Średnie",
        5..=6 => "Mocne",
        _ => "Bardzo mocne",
    };

    let charset_size: f64 = (if has_uppercase { 26.0 } else { 0.0 }) +
        (if has_lowercase { 26.0 } else { 0.0 }) +
        (if has_digit { 10.0 } else { 0.0 }) +
        (if has_special { 32.0 } else { 0.0 }) + 1.0;
    let entropy = (length as f64) * charset_size.log2();

    json!({
        "score": score,
        "max_score": 7,
        "strength": strength,
        "length": length,
        "has_uppercase": has_uppercase,
        "has_lowercase": has_lowercase,
        "has_digit": has_digit,
        "has_special": has_special,
        "entropy": format!("{:.1}", entropy),
        "feedback": feedback
    })
}
