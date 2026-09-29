use serde_json::json;

/// Porównanie dwóch tekstów (LCS) z wyróżnieniem różnic.
pub fn diff(a: &str, b: &str) -> serde_json::Value {
    let x: Vec<&str> = a.lines().collect();
    let y: Vec<&str> = b.lines().collect();

    // LCS DP - ograniczone, by nie eksplodowało pamięci
    const MAX: usize = 1500;
    if x.len() > MAX || y.len() > MAX {
        return json!({ "error": format!("Tekst za duży (max {} linii)", MAX) });
    }

    let mut dp = vec![vec![0u32; y.len() + 1]; x.len() + 1];
    for i in (0..x.len()).rev() {
        for j in (0..y.len()).rev() {
            dp[i][j] = if x[i] == y[j] {
                dp[i + 1][j + 1] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }

    let mut added = 0;
    let mut removed = 0;
    let mut same = 0;
    let mut rows: Vec<serde_json::Value> = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);

    while i < x.len() && j < y.len() {
        if x[i] == y[j] {
            same += 1;
            rows.push(json!({ "typ": "=", "tekst": x[i] }));
            i += 1;
            j += 1;
        } else if dp[i + 1][j] >= dp[i][j + 1] {
            removed += 1;
            rows.push(json!({ "typ": "-", "tekst": x[i] }));
            i += 1;
        } else {
            added += 1;
            rows.push(json!({ "typ": "+", "tekst": y[j] }));
            j += 1;
        }
    }
    while i < x.len() {
        removed += 1;
        rows.push(json!({ "typ": "-", "tekst": x[i] }));
        i += 1;
    }
    while j < y.len() {
        added += 1;
        rows.push(json!({ "typ": "+", "tekst": y[j] }));
        j += 1;
    }

    let total = added + removed + same;
    let score = if total == 0 { 100 } else { (same * 100) / total };

    json!({
        "dodane": added,
        "usuniete": removed,
        "niezmienione": same,
        "podobnosc": format!("{}%", score),
        "diff": rows,
    })
}

/// Tester wyrażeń regularnych.
pub fn regex_test(pattern: &str, text: &str, flags_case_insensitive: bool) -> serde_json::Value {
    let mut re = String::new();
    if flags_case_insensitive {
        re.push_str("(?i)");
    }
    re.push_str(pattern);

    let compiled = match regex::Regex::new(&re) {
        Ok(r) => r,
        Err(e) => return json!({ "error": format!("Błędny regex: {}", e) }),
    };

    let matches: Vec<serde_json::Value> = compiled
        .find_iter(text)
        .take(200)
        .map(|m| {
            json!({
                "znajdziek": m.as_str(),
                "pozycja": m.start(),
                "linie": text[..m.start()].lines().count() + 1,
                "grupy": m.as_str().chars().take(60).collect::<String>(),
            })
        })
        .collect();

    let named: Vec<String> = compiled
        .capture_names()
        .filter_map(|n| n.map(|s| s.to_string()))
        .collect();

    json!({
        "poprawny": true,
        "liczba_dopasowan": matches.len(),
        "grupy_nazwane": named,
        "dopasowania": matches,
    })
}

/// Formatowanie / walidacja JSON.
pub fn json_tool(text: &str, mode: &str) -> serde_json::Value {
    match mode {
        "format" => match serde_json::from_str::<serde_json::Value>(text) {
            Ok(v) => json!({ "ok": true, "wynik": serde_json::to_string_pretty(&v).unwrap_or_default() }),
            Err(e) => json!({ "error": format!("Nieprawidłowy JSON: {}", e) }),
        },
        "minify" => match serde_json::from_str::<serde_json::Value>(text) {
            Ok(v) => json!({ "ok": true, "wynik": serde_json::to_string(&v).unwrap_or_default() }),
            Err(e) => json!({ "error": format!("Nieprawidłowy JSON: {}", e) }),
        },
        "escape" => json!({ "ok": true, "wynik": serde_json::to_string(&text).unwrap_or_default().replace('"', "\\\"") }),
        "unescape" => match serde_json::from_str::<String>(text) {
            Ok(v) => json!({ "ok": true, "wynik": v }),
            Err(e) => json!({ "error": format!("Nie można odkodować: {}", e) }),
        },
        _ => json!({ "error": "Nieznany tryb" }),
    }
}

fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let b = c as u8;
                let off = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                (off + (b - off + 13) % 26) as char
            } else {
                c
            }
        })
        .collect()
}

/// Proste transformacje tekstowe.
pub fn text_transform(text: &str, mode: &str) -> serde_json::Value {
    let out = match mode {
        "upper" => text.to_uppercase(),
        "lower" => text.to_lowercase(),
        "title" => text
            .split_whitespace()
            .map(|w| {
                let mut c = w.chars();
                match c.next() {
                    Some(f) => f.to_uppercase().collect::<String>() + &c.as_str().to_lowercase(),
                    None => String::new(),
                }
            })
            .collect::<Vec<_>>()
            .join(" "),
        "rot13" => rot13(text),
        "reverse" => text.chars().rev().collect(),
        "reverse_lines" => {
            let mut v: Vec<&str> = text.lines().collect();
            v.reverse();
            v.join("\n")
        }
        "strip_ws" => text.split_whitespace().collect::<Vec<_>>().join(" "),
        "count" => {
            let words = text.split_whitespace().count();
            let lines = text.lines().count();
            let chars = text.chars().count();
            let mut uniq: Vec<&str> = text.split_whitespace().collect();
            uniq.sort_unstable();
            uniq.dedup();
            return json!({
                "znaki": chars,
                "znaki_bez_spacji": text.chars().filter(|c| !c.is_whitespace()).count(),
                "slowa": words,
                "linie": lines,
                "bajty": text.len(),
                "unikalne_slowa": uniq.len()
            });
        }
        _ => return json!({ "error": "Nieznany tryb transformacji" }),
    };
    json!({ "ok": true, "wynik": out })
}
