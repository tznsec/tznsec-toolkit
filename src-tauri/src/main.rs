#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde_json::{json, Value};
use std::collections::HashMap;
use tauri::State;
use tokio::sync::Mutex;

mod tools;
use tools::*;

struct Ui {
    liczba_narzedzi: Mutex<u32>,
}

// ================= SIEĆ =================

#[tauri::command]
async fn port_scan(target: String, ports: Option<String>) -> Result<Value, String> {
    Ok(port_scanner::scan_ports(&target, ports.as_deref()).await)
}

#[tauri::command]
fn cidr_analyze(cidr: String) -> Result<Value, String> {
    Ok(net_tools::cidr_analyze(&cidr))
}

#[tauri::command]
fn cidr_split(cidr: String, new_prefix: u8) -> Result<Value, String> {
    Ok(net_tools::cidr_split(&cidr, new_prefix, 64))
}

#[tauri::command]
fn host_expand(cidr: String) -> Result<Value, String> {
    Ok(net_tools::host_expand(&cidr, 256))
}

#[tauri::command]
async fn ip_info(ip: String) -> Result<Value, String> {
    Ok(net_tools::ip_info(&ip).await)
}

#[tauri::command]
async fn dns_lookup(domain: String, record_type: Option<String>) -> Result<Value, String> {
    Ok(dns_tools::lookup(&domain, record_type.as_deref()).await)
}

// ================= KRYTOGRAFIA =================

#[tauri::command]
fn hash_data(text: String, algorithm: String) -> Result<Value, String> {
    Ok(hash_tools::hash_text(&text, &algorithm))
}

#[tauri::command]
fn hash_identify(hash: String) -> Result<Value, String> {
    Ok(crypto_tools::hash_identify(&hash))
}

#[tauri::command]
fn base64_tool(text: String, mode: String) -> Result<Value, String> {
    Ok(encoding_tools::base64_operation(&text, &mode))
}

#[tauri::command]
fn hex_tool(text: String, mode: String) -> Result<Value, String> {
    Ok(encoding_tools::hex_operation(&text, &mode))
}

#[tauri::command]
fn url_encode_tool(text: String, mode: String) -> Result<Value, String> {
    Ok(encoding_tools::url_operation(&text, &mode))
}

#[tauri::command]
fn checksum_calc(text: String) -> Result<Value, String> {
    Ok(crypto_tools::checksum(&text))
}

#[tauri::command]
fn entropy_analysis(text: String) -> Result<Value, String> {
    Ok(crypto_tools::entropy_analysis(&text))
}

#[tauri::command]
fn jwt_tool(token: String) -> Result<Value, String> {
    Ok(jwt_tools::analyze_jwt(&token))
}

#[tauri::command]
fn json_tool(text: String, mode: String) -> Result<Value, String> {
    Ok(text_tools::json_tool(&text, &mode))
}

#[tauri::command]
fn text_transform(text: String, mode: String) -> Result<Value, String> {
    Ok(text_tools::text_transform(&text, &mode))
}

// ================= BEZPIECZEŃSTWO =================

#[tauri::command]
fn password_strength(password: String) -> Result<Value, String> {
    Ok(password_tools::check_strength(&password))
}

#[tauri::command]
fn headers_analyze(headers: HashMap<String, String>) -> Result<Value, String> {
    Ok(header_tools::analyze_headers(&headers))
}

#[tauri::command]
fn user_agent_info(user_agent: String) -> Result<Value, String> {
    Ok(ua_tools::parse_user_agent(&user_agent))
}

#[tauri::command]
fn scan_payloads(text: String) -> Result<Value, String> {
    Ok(detect_tools::scan_payloads(&text))
}

#[tauri::command]
fn payload_refs() -> Result<Value, String> {
    Ok(detect_tools::payload_refs())
}

#[tauri::command]
fn secret_scan(text: String) -> Result<Value, String> {
    Ok(crypto_tools::secret_scan(&text))
}

// ================= HTTP / DANE =================

#[tauri::command]
fn curl_build(method: String, url: String, headers: String, body: String, insecure: bool) -> Result<Value, String> {
    Ok(http_tools::curl_build(&method, &url, &headers, &body, insecure))
}

#[tauri::command]
fn cert_parse(pem: String) -> Result<Value, String> {
    Ok(http_tools::cert_parse(&pem))
}

#[tauri::command]
async fn site_files(url: String) -> Result<Value, String> {
    Ok(http_tools::site_files(&url).await)
}

// ================= DOS / OBRONA =================

#[tauri::command]
async fn stress_test(
    target: String,
    port: String,
    requests: String,
    concurrency: String,
    duration: String,
    path: String,
) -> Result<Value, String> {
    Ok(dos_tools::stress_test(
        &target,
        port.trim().parse().unwrap_or(80),
        requests.trim().parse().unwrap_or(500),
        concurrency.trim().parse().unwrap_or(20),
        duration.trim().parse().unwrap_or(5),
        &path,
    )
    .await)
}

#[tauri::command]
fn dos_log_analyzer(log: String) -> Result<Value, String> {
    Ok(dos_tools::dos_log_analyzer(&log))
}

// ================= AI =================

#[derive(serde::Deserialize)]
struct AiMsg {
    role: String,
    content: String,
}

#[derive(serde::Deserialize)]
struct AiRequest {
    base: String,
    api_key: String,
    model: String,
    messages: Vec<AiMsg>,
    context: Option<String>,
}

#[tauri::command]
fn ai_providers() -> Result<Value, String> {
    Ok(ai_chat::providers())
}

#[tauri::command]
async fn ai_chat(req: AiRequest) -> Result<Value, String> {
    let msgs: Vec<ai_chat::Msg> = req
        .messages
        .into_iter()
        .map(|m| ai_chat::Msg { role: m.role, content: m.content })
        .collect();
    Ok(ai_chat::chat(
        &req.base,
        &req.api_key,
        &req.model,
        msgs,
        req.context.as_deref().unwrap_or(""),
    )
    .await)
}

// ================= AGENT / NARZEDZIA AI =================

#[tauri::command]
fn agent_exec(command: String, timeout_secs: String) -> Result<Value, String> {
    let t = timeout_secs.trim().parse().unwrap_or(60);
    Ok(agent_tools::exec(&command, t))
}

#[tauri::command]
fn agent_write_file(path: String, content: String) -> Result<Value, String> {
    Ok(agent_tools::write_file(&path, &content))
}

#[tauri::command]
fn agent_read_file(path: String) -> Result<Value, String> {
    Ok(agent_tools::read_file(&path))
}

#[tauri::command]
fn agent_list_dir(path: String) -> Result<Value, String> {
    Ok(agent_tools::list_dir(&path))
}

#[tauri::command]
fn agent_parse_calls(text: String) -> Result<Value, String> {
    Ok(json!({ "calls": agent_tools::parse_tool_calls(&text) }))
}

#[tauri::command]
fn agent_classify(command: String) -> Result<Value, String> {
    let (level, why) = agent_tools::classify(&command);
    Ok(json!({ "level": level, "powod": why }))
}

#[tauri::command]
fn agent_workspace() -> Result<Value, String> {
    Ok(json!({
        "sciezka": agent_tools::workspace().to_string_lossy(),
        "istnieje": agent_tools::workspace().exists(),
    }))
}

#[tauri::command]
fn recon_tools_check() -> Result<Value, String> {
    Ok(recon_tools::check_tools())
}

#[tauri::command]
fn recon_analyze(command: String, stdout: String, stderr: String, exit_code: i32) -> Result<Value, String> {
    Ok(recon_tools::analyze_output(&command, &stdout, &stderr, exit_code))
}

#[tauri::command]
async fn tools_status() -> Result<Value, String> {
    // wykrywanie procesow wolne - nie blokuj wątku UI
    Ok(tokio::task::spawn_blocking(install_tools::status)
        .await
        .unwrap_or_else(|e| json!({ "error": e.to_string() })))
}

#[tauri::command]
async fn tool_install(id: String) -> Result<Value, String> {
    Ok(tokio::task::spawn_blocking(move || install_tools::install(&id))
        .await
        .unwrap_or_else(|e| json!({ "error": e.to_string() })))
}

// ================= USTAWIENIA =================

#[tauri::command]
fn settings_load() -> Result<Value, String> {
    Ok(settings_tools::load())
}

#[tauri::command]
fn settings_save(patch: Value) -> Result<Value, String> {
    settings_tools::save(patch)
}

#[tauri::command]
fn settings_set_key(provider: String, key: String) -> Result<Value, String> {
    settings_tools::set_key(&provider, &key)
}

#[tauri::command]
fn settings_forget_key(provider: String) -> Result<Value, String> {
    settings_tools::forget_key(&provider)
}

#[tauri::command]
fn settings_reset() -> Result<Value, String> {
    settings_tools::reset()
}

// ================= TAILSCALE =================

#[tauri::command]
fn tailscale_detect() -> Result<Value, String> {
    Ok(tailscale_tools::detect())
}

#[tauri::command]
fn tailscale_peers() -> Result<Value, String> {
    Ok(tailscale_tools::peers())
}

#[tauri::command]
fn tailscale_scope() -> Result<Value, String> {
    Ok(tailscale_tools::scope_summary())
}

// ================= PLIKI / PANIC =================

#[tauri::command]
fn file_encrypt(path: String, password: String) -> Result<Value, String> {
    Ok(filecrypto::encrypt_file(&path, &password))
}

#[tauri::command]
fn file_decrypt(path: String, password: String) -> Result<Value, String> {
    Ok(filecrypto::decrypt_file(&path, &password))
}

#[tauri::command]
fn panic_mode(shutdown: bool) -> Result<Value, String> {
    Ok(panic_tools::panic_mode(shutdown))
}

// ================= OPERACJE BEZPIECZENSTWA =================

#[tauri::command]
async fn breach_check(password: String) -> Result<Value, String> {
    Ok(secops_tools::breach_check(&password).await)
}

#[tauri::command]
async fn tls_audit(host: String) -> Result<Value, String> {
    Ok(secops_tools::tls_audit(&host).await)
}

#[tauri::command]
fn version_scan(headers: String, body: String) -> Result<Value, String> {
    Ok(secops_tools::version_scan(&headers, &body))
}

// ================= DIFF / REGEX =================

#[tauri::command]
fn diff(a: String, b: String) -> Result<Value, String> {
    Ok(text_tools::diff(&a, &b))
}

#[tauri::command]
fn regex_test(pattern: String, text: String, ignore_case: bool) -> Result<Value, String> {
    Ok(text_tools::regex_test(&pattern, &text, ignore_case))
}

#[tauri::command]
async fn app_status(state: State<'_, Ui>) -> Result<String, String> {
    let mut n = state.liczba_narzedzi.lock().await;
    *n += 1;
    Ok(format!("TZNSEC Toolkit v1.0 — {} narzędzi online", n))
}

/// Okresla swiadomosc DPI przed utworzeniem okna.
/// Bez tego Windows rozciaga bitmapę, a WebView2 dostaje bledny rozmiar
/// viewportu (objaw: tresc przesunieta i przycięta).
#[cfg(windows)]
fn dpi_aware() {
    use std::ffi::c_void;
    extern "system" {
        fn SetProcessDpiAwarenessContext(value: *mut c_void) -> i32;
        fn SetProcessDPIAware() -> i32;
    }
    // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
    const PER_MONITOR_AWARE_V2: isize = -4;
    unsafe {
        if SetProcessDpiAwarenessContext(PER_MONITOR_AWARE_V2 as *mut c_void) == 0 {
            SetProcessDPIAware();
        }
    }
}

#[cfg(not(windows))]
fn dpi_aware() {}

fn main() {
    dpi_aware();

    tauri::Builder::default()
        .manage(Ui {
            liczba_narzedzi: Mutex::new(31),
        })
        .invoke_handler(tauri::generate_handler![
            // sieć
            port_scan,
            cidr_analyze,
            cidr_split,
            host_expand,
            ip_info,
            dns_lookup,
            // kryptografia
            hash_data,
            hash_identify,
            base64_tool,
            hex_tool,
            url_encode_tool,
            checksum_calc,
            entropy_analysis,
            jwt_tool,
            json_tool,
            text_transform,
            // bezpieczeństwo
            password_strength,
            headers_analyze,
            user_agent_info,
            scan_payloads,
            payload_refs,
            secret_scan,
            // http
            curl_build,
            cert_parse,
            site_files,
            // ai
            ai_providers,
            ai_chat,
            // agent / narzedzia
            agent_exec,
            agent_write_file,
            agent_read_file,
            agent_list_dir,
            agent_parse_calls,
            agent_classify,
            agent_workspace,
            recon_tools_check,
            recon_analyze,
            tools_status,
            tool_install,
            // ustawienia
            settings_load,
            settings_save,
            settings_set_key,
            settings_forget_key,
            settings_reset,
            // dos / obrona
            stress_test,
            dos_log_analyzer,
            // tailscale
            tailscale_detect,
            tailscale_peers,
            tailscale_scope,
            // pliki / panic
            file_encrypt,
            file_decrypt,
            panic_mode,
            // operacje bezpieczenstwa
            breach_check,
            tls_audit,
            version_scan,
            // diff / regex
            diff,
            regex_test,
            app_status,
        ])
        .run(tauri::generate_context!())
        .expect("nie udało się uruchomić aplikacji");
}
