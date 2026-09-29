# TZNSEC Toolkit

Desktopowy zestaw narzędzi do cyberbezpieczeństwa i kryptografii.
Rust + Tauri, interfejs HTML/CSS, działa offline.

## Uruchomienie

```bash
cargo build --release
target\release\tznsec-toolkit.exe
```

## Narzędzia

**Kryptografia** — generator hashy (MD5, SHA-1, SHA-256, SHA-512), identyfikator
formatu hasha, Base64, Hex, kodowanie URL, sumy kontrolne (CRC32, Adler32), analiza
entropii, analizator JWT, formatowanie JSON.

**Cyberbezpieczeństwo** — siła hasła, audyt nagłówków HTTP, wykrywanie ataków w logach
(SQLi, XSS, Log4Shell, traversal, SSRF, SSTI, XXE, NoSQL, deserializacja), skan
wycieków sekretów, sprawdzenie hasła w bazie wycieków (k-anonimowo), audyt TLS,
fingerprint stosu technologicznego, detektor DoS w logach dostępu.

**Sieć** — skaner portów TCP, kalkulator CIDR, podział podsieci, generator listy
hostów, informacje o IP, zapytania DNS, pobieranie security.txt i robots.txt.

**Laboratorium** — Tailscale (detekcja i węzły), szyfrator plików (AES-256-GCM,
PBKDF2 210k iteracji), test obciążeniowy, tryb panic, diff, tester regex, generator
curl, analiza certyfikatu PEM, transformacje tekstu.

**Narzędzia** — instalacja zewnętrznych narzędzi pentesterskich (nmap, sqlmap,
nikto, hydra, john, hashcat, masscan, netcat, git) jednym kliknięciem przez winget
lub pip.

**AI Hacking** — asystent do autoryzowanego pentestu. Wykonuje komendy, czyta i zapisuje
pliki, sam analizuje wyniki i decyduje o kolejnych krokach. Każda akcja wymaga
potwierdzenia (opcjonalnie tryb pełnej automatyzacji w Ustawieniach).

## Architektura

```
src/                    frontend (HTML, CSS, JS)
src-tauri/src/main.rs    komendy IPC
src-tauri/src/tools/     logika narzędzi
```

Backend komunikuje się z frontendem przez Tauri IPC — bez lokalnego serwera.
Interfejs renderuje systemowy WebView2, więc aplikacja jest natywnym oknem.

## Bezpieczeństwo

- Test obciążeniowy przyjmuje wyłącznie adresy localhost, LAN i Tailscale
  (100.64/10, fc00::/7). Adresy publiczne są odrzucane.
- Komendy AI mają limity czasu i klasyfikację ryzyka; ryzyko wysokie zawsze
  wymaga ręcznego zatwierdzenia.
- Pliki agenta są ograniczone do katalogu roboczego, ścieżki z `..` są blokowane.
- Klucze API szyfrowane AES-256-GCM w `%APPDATA%\tznsec-toolkit\settings.dat`,
  poza repozytorium.
- Prompt injection z logów lub stron nie wykonuje komend bez Twojego kliknięcia.

## Uwagi

Aplikacja jest narzędziem do pracy na systemach, do których masz pełne prawa
i pisemną zgodę. Testy poza zakresem localhost/LAN/Tailscale wymagają autoryzacji.

---

Wykonane przez **tznsec**
