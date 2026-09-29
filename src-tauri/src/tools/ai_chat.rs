use serde_json::json;
use std::time::Duration;

/// Presety dostawcow. Wszystkie sa zgodne z OpenAI /chat/completions.
pub fn providers() -> serde_json::Value {
    json!([
        { "id": "xkiro",    "nazwa": "xkiro  (DARMOWE, testowane)", "base": "https://api.xkiro.com/v1",
          "modele": ["qwen/qwen3.6-27b:free", "qwen/qwen3.5-plus:free", "qwen/qwen3.7-flash:free",
                     "qwen/qwen3-max:free", "minimax/minimax-m2.7:free", "minimax/minimax-m3:free"],
          "klucz": true, "uwaga": "Sprawdzone 29.09.2026. qwen3.6-27b odpowiada na pytania o pentest; qwen3.7-flash je odrzuca" },
        { "id": "ollama",   "nazwa": "Ollama  (Lokalny, ZA DARMO)",   "base": "http://127.0.0.1:11434/v1",
          "modele": ["qwen2.5-coder:7b", "qwen2.5-coder:3b", "llama3.1:8b", "mistral:7b"],
          "klucz": false, "uwaga": "Bezplatne i bez limitu, liczy sie tylko moc Twojego CPU/GPU. Pobierz: ollama.com" },
        { "id": "lmstudio", "nazwa": "LM Studio  (Lokalny, ZA DARMO)", "base": "http://127.0.0.1:1234/v1",
          "modele": [], "klucz": false,
          "uwaga": "Bezplatne, aplikacja z GUI. Pobierz model i wlacz serwer: lmstudio.ai" },
        { "id": "gemini",   "nazwa": "Google Gemini  (darmowy limit)", "base": "https://generativelanguage.googleapis.com/v1beta/openai",
          "modele": ["gemini-2.0-flash", "gemini-2.5-flash", "gemini-2.5-pro"],
          "klucz": true, "uwaga": " Darmowy limit tokenow od Google. Klucz: aistudio.google.com/apikey" },
        { "id": "xai",      "nazwa": "xAI Grok  (PLATNE)",  "base": "https://api.x.ai/v1",
          "modele": ["grok-4.6", "grok-4.5", "grok-3-beta"],
          "klucz": true, "uwaga": "UWAGA: rozliczane per token ($2-6 / 1M). Darmowe jest tylko grok.com w przegladarce" },
        { "id": "openai",   "nazwa": "OpenAI  (PLATNE)",   "base": "https://api.openai.com/v1",
          "modele": ["gpt-4o-mini", "gpt-4o"],
          "klucz": true, "uwaga": "Rozliczane per token" },
        { "id": "openrouter","nazwa": "OpenRouter  (ma modele za darmo)", "base": "https://openrouter.ai/api/v1",
          "modele": ["deepseek/deepseek-r1:free", "meta-llama/llama-3.3-70b-instruct:free", "auto"],
          "klucz": true, "uwaga": "Warianty z :free w nazwie sa bezplatne. Klucz: openrouter.ai/keys" },
        { "id": "custom",   "nazwa": "Wlasny endpoint",     "base": "", "modele": [], "klucz": false,
          "uwaga": "Dowolny serwer zgodny z OpenAI" }
    ])
}

/// Prompt systemowy - asystent do autoryzowanego testowania bezpieczenstwa.
fn system_prompt() -> &'static str {
    "Jestes asystentem bezpieczenstwa w TZNSEC Toolkit. Pomagasz w AUTORYZOWANYM \
     testowaniu bezpieczenstwa (pentest) na systemach, do ktorych uzytkownik ma pelne \
     prawa i pisemna zgode.\n\n\
     ZASADY:\n\
     - Wspomagaj tylko w zakresie localhost, sieci prywatnej (10/8, 172.16/12, 192.168/16), \
     link-local i tailnetow Tailscale (100.64/10, fc00::/7).\n\
     - Gdy uzytkownik prosi o cel spoza tych zakresow, odmow i wskaz, ze potrzebna jest \
     autoryzacja, oraz zaproponuj test na wlasnym srodowisku.\n\
     - Nie pomagaj w budowaniu oprogramowania destrukcyjnego: ransomware, keyloggerow, \
     botnetow, exploitow bez autoryzacji, technik omijania EDR w celach omijania kontroli.\n\
     - Nie projektuj atakow na cudza infrastrukture, w tym na dostep bez zgody wlasciciela.\n\n\
     STYL ODPOWIEDZI:\n\
     - Po polsku, konkretnie i krótko.\n\
     - Podawaj komendy do uruchomienia, wyjasniajac co robia.\n\
     - Jesli wynik wskazuje podatnosc, dodaj wariant naprawy i sposob weryfikacji poprawki.\n\
     - Jesli czegos nie wiesz, powiedz to wprost zamiast zgadywac.\n\n\
     ZASADA KRYTYCZNA - NIE RELACJONUJ O CZYM NIE WIESZ:\n\
     - NIGDY nie pisz, ze cos 'przeskanowales', 'sprawdziles', 'znalazles' lub 'wykryles',\n\
       jesli w tej turze nie otrzymales wyniku z narzedzia.\n\
     - Nie opisuj stanu systemu, ktorego nie odczytales. Nie zgaduj portow, naglowkow\n\
       ani podatnosci.\n\
     - Jesli chcesz cos sprawdzic - NAJPIERW zaproponuj wywolanie narzedzia.\n\
       Dopiero po otrzymaniu wyniku mozesz opisac, co ono wykazalo.\n\
     - Jesli nie masz narzedzia, powiedz wprost: 'nie moge tego sprawdzic, potrzebujesz X'.\n\
     - Jesli uzytkownik prosi o skan, a nie masz jeszcze zadnego wyniku z narzedzia,\n\
       powiedz jednym zdaniem, ze skan nie zostal jeszcze wykonany."
}

#[derive(serde::Deserialize)]
pub struct Msg {
    pub role: String,
    pub content: String,
}

/// Wysyla rozmowe do wskazanego endpointu. Klucz idzie wylacznie do
/// dostawcy - nie jest zapisywany ani logowany.
pub async fn chat(base: &str, api_key: &str, model: &str, history: Vec<Msg>, context: &str) -> serde_json::Value {
    let base = base.trim().trim_end_matches('/');
    if base.is_empty() {
        return json!({ "error": "Brak adresu endpointu" });
    }
    if base.contains("169.254.169.254") {
        return json!({ "error": "Zablokowano odpytywanie metadanych chmury" });
    }
    if !(base.starts_with("https://") || base.starts_with("http://127.0.0.1") || base.starts_with("http://localhost")) {
        return json!({ "error": "Dozwolone https:// albo lokalny http://127.0.0.1 / http://localhost" });
    }

    let model = if model.trim().is_empty() { "qwen/qwen3.7-flash:free" } else { model.trim() };

    let mut msgs = vec![json!({
        "role": "system",
        "content": format!("{}\n\n{}", system_prompt(), crate::tools::agent_tools::tools_prompt())
    })];
    if !context.trim().is_empty() {
        msgs.push(json!({
            "role": "system",
            "content": format!("Kontekst z narzedzi TZNSEC (wynik ponizej):\n{}", context.trim())
        }));
    }
    for m in history.iter().take(40) {
        if m.content.trim().is_empty() {
            continue;
        }
        let role = if m.role == "assistant" { "assistant" } else { "user" };
        msgs.push(json!({ "role": role, "content": m.content }));
    }

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
    {
        Ok(c) => c,
        Err(e) => return json!({ "error": e.to_string() }),
    };

    let mut rb = client
        .post(format!("{}/chat/completions", base))
        .json(&json!({
            "model": model,
            "messages": msgs,
            "stream": false,
            "temperature": 0.4,
        }));

    let key = api_key.trim();
    if !key.is_empty() {
        rb = rb.bearer_auth(key);
    }

    match rb.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            if !(200..300).contains(&status) {
                let msg = serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|v| v["error"]["message"].as_str().map(|s| s.to_string()))
                    .unwrap_or_else(|| body.chars().take(300).collect());
                return json!({ "error": format!("HTTP {}: {}", status, msg) });
            }
            match serde_json::from_str::<serde_json::Value>(&body) {
                Ok(v) => {
                    let text = v["choices"][0]["message"]["content"]
                        .as_str()
                        .unwrap_or("(brak tresci)")
                        .to_string();
                    let usage = v.get("usage").cloned().unwrap_or(json!({}));
                    json!({ "ok": true, "tresc": text, "model": v["model"].as_str().unwrap_or(model), "usage": usage })
                }
                Err(e) => json!({ "error": format!("Nieprawidlowa odpowiedz: {}", e) }),
            }
        }
        Err(e) => {
            let hint = if e.is_connect() {
                " Czy usluga dziala? Ollama: 'ollama serve', LM Studio: uruchom serwer lokalny."
            } else {
                ""
            };
            json!({ "error": format!("{}{}", e, hint) })
        }
    }
}
