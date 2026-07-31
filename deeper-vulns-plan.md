# Plan: Mehr Vulnerabilitäten mit BugBountyV2tool finden

## Strategie

Zwei Hebel: **A) Bestehende Phasen vertiefen** (mehr Payloads, mehr Tools, mehr Coverage) und **B) Neue Phasen hinzufügen** (Lücken schließen).

---

## A) Bestehende Phasen vertiefen (10 Phasen, höchste Priorität)

### A1. 66-SSRF-FULL — Cloud Metadata & Blind SSRF ausbauen

**Problem:** Aktuell nur AWS/GCP/Azure Metadata-Endpoints + basic OOB-Callback. IMDSv2, ECS, ALB, und Cloud Run fehlen.

**Erweiterung:**
- IMDSv2 `X-aws-ec2-metadata-token` Bypass (PUT → Header)
- ECS Container Metadata (`http://169.254.170.2/v2/metadata`)
- ALB `/proxy/...` Endpoint-Probing (CVE-2024-fresh)
- GCP Metadata: `/?recursive=true`, `computeMetadata/v1/?recursive=true`
- Cloud Run: `http://metadata.google.internal/...`
- DigitalOcean: `http://169.254.169.254/metadata/v1.json`
- Alibaba Cloud: `http://100.100.100.200/latest/meta-data/`
- Blind SSRF mit Time-based Detection (kein OOB nötig)

**Verifikation:** `pytest tests/ -k ssrf -v` + manuelle Probe gegen test-server

---

### A2. 20-GRAPHQL — Persisted Queries, Batching & Introspection Deepening

**Problem:** Nur basic Introspection + clairvoyance + graphinder. Fehlt: Persisted Query Analysis, Batching-Attacken, Alias-basierte Data Exfiltration.

**Erweiterung:**
- Persisted Query ID Enumeration (via `?query_id=` Brute-Force)
- Alias-basiertes Batching (`query { a1:user(id:1){name} ... a100:user(id:100){name} }`)
- Depth-basierte Rekursion (Verschachtelte Queries bis Depth 20)
- Custom Scalar/Directive Enumeration aus Introspection
- Field Suggestion Attack (GraphQL schemas ohne Introspection dogfooding)
- Rate-Limit Bypass via Batch Query (komprimierte Requests)

**Verifikation:** Test gegen GraphQL-Honeypot (z.B. `graphql-go` playground)

---

### A3. 37-FILEUPLOAD + 78-FILEUPLOADADV — Polyglot, Race & Metadata Attacks

**Problem:** Extension-Bypass + Content-Type Manipulation vorhanden; fehlt: Polyglot-Generierung, Race-Condition-Upload, EXIF-Metadaten-Injection.

**Erweiterung:**
- GIF+PHP/JPG+ASP Polyglot Generator (stdlib: `struct.pack` für Magic Bytes)
- Race Condition: Upload → Read in schneller Folge (File-rename TOCTOU)
- EXIF Tool Metadaten-Injection (Autor-Feld für Stored XSS)
- Filename SQL-Injection / Path-Traversal via Dateiname
- Filesize-Limit Bypass (Chunked Upload, Content-Range Manipulation)
- SVG mit embedded XSS/XXE

**Verifikation:** Test-HTTP-Server mit File-Upload-Endpoint starten

---

### A4. 11-INJECT (XSS) + 80-STOREXSS — Context-aware XSS

**Problem:** Dalfox + kxss + Gxss + basic Stored XSS reichen, aber kontextbewusste Payloads (JS-Kontext, CSS-Kontext, Attribute-Kontext) fehlen.

**Erweiterung:**
- Context Detection: HTML/JS/CSS/URL/Angular/React Kontext erkennen (regex-basiert)
- Payload-Generierung pro Context (z.B. `';alert(1)//` für JS String, `"-alert(1)-` für Attribute)
- Angular/React Template Injection (`{{constructor.constructor('alert(1)')()}}`)
- Stored XSS: Cross-Session-Verifikation (Playwright: Post → Login als anderer User → Check Render)
- Service Worker XSS (Register + Cache Manipulation)
- Mautic/XSS via CSS `background:url(javascript:...)`

**Verifikation:** Playwright-basierter Test mit XSS-Dummy-App

---

### A5. 153-BIZLOGIC + 154-PAYMENT — State-Machine & Workflow Violation

**Problem:** Nur heuristische Header/Payload-Liste. Keine echte State-Machine-Analyse oder Workflow-Extraktion.

**Erweiterung:**
- State-Machine Discovery: HTTP-Status-Code-Übergänge tracken (z.B. 200→302→403→500)
- Step-Skipping: Checklisten-Attacken (z.B. Payment überspringen → direkt Download)
- Coupon-Stacking: Mehrere Coupons parallel anwenden
- Negative-Pricing: Negative Mengen / Preise testen
- Integer Overflow: Große Zahlen in `price`/`quantity`/`amount`
- Race in Payment: Gleichzeitige Bestellungen mit gleichem Guthaben
- JWT-Tampering in Business-Logic: `{"role":"admin","price":0}`

**Verifikation:** pytest mit simulierten Business-Logic-Endpoints

---

### A6. 19-GIT — Git Exposure Deepening

**Problem:** Nur `.git` Directory Scanning + gitleaks + trufflehog. Fehlt: `.git/config` Analyse, `.gitmodules`, Commit-History-Recovery.

**Erweiterung:**
- `.git/config` → Remote-URLs mit Credentials extrahieren
- `.gitmodules` → Submodule-URLs scanen
- Git-Object-Download: `git cat-file` via HTTP (raw Objekte aus `.git/objects/`)
- Commit-History Walk: Mehrere Commits aus Objekten rekonstruieren
- `.gitignore` Exposure → Hidden Files finden
- `.git/refs/heads/master` → Latest Commit SHA lesen
- `git diff --cached` über staged changes

**Verifikation:** Fake-Git-Repo im `outdir` deployen, Phase dagegen laufen lassen

---

### A7. 23-RACE + 83-RACEBURST — Vollständiges Race-Toolkit

**Problem:** Nur 5/10 parallele Requests. Fehlt: TOCTOU-Bestätigung, Session-Management, Turbo Intruder Style.

**Erweiterung:**
- TOCTOU-Verifikation: Read-after-Write in Schleife (10x) → Consistency-Check
- Session-Race: Gleicher Request mit 2 Sessions (z.B. Geld transfer A→B und B→A gleichzeitig)
- Endpoint-Weight-Race: Schweren Request + leichten Request parallel (z.B. Upload + GET)
- Last-Byte-Synchronisation: `send()` in Teilen mit `sleep()` dazwischen
- WebSocket Race: Concurrent WS Messages
- Rate-Limit Race: Fenster-Vergrößerung durch parallele Requests

**Verifikation:** Race-Proxy (eigener Test-Server) + pytest

---

### A8. 30-LFI — Log-Poisoning & PHP-Wrapper Vertiefung

**Problem:** Nur basic PHP Wrappers + RFI + Log-Poisoning via User-Agent. Fehlt: Session-Wrapper, Proc-FS, Env-Var-Leak.

**Erweiterung:**
- PHP Session Wrapper: `php://filter/convert.base64-encode/resource=/tmp/sess_...`
- `/proc/self/environ` + `/proc/self/fd/0..N` Enumeration
- `/proc/self/cmdline` → Server-Prozess-Info
- SSH Key Leak: `~/.ssh/id_rsa`, `/home/*/.ssh/authorized_keys`
- Log-Poisoning via `Referer`, `Cookie`, `X-Forwarded-For` (zusätzlich zu User-Agent)
- `/var/log/apache2/access.log`, `/var/log/nginx/access.log`
- Windows: `C:/boot.ini`, `C:/Windows/win.ini`, `C:/inetpub/wwwroot/web.config`
- Java: `file:///etc/passwd`, `file:///C:/windows/system32/drivers/etc/hosts`

**Verifikation:** Test-LFI-Server (PHP + Apache) in Docker

---

### A9. 15-SECRETS — JS-Secret-Erkennung mit ML/Regex

**Problem:** Nur SecretFinder + trufflehog Regex. Fehlt: Entropy-basierte Detection, GitHub-Token-Validation, Semgrep-Regeln.

**Erweiterung:**
- Entropy-Analyse: Shanon-Entropie > 4.5 → Potential Secret (stdlib `math.log2` + Frequenz)
- API-Key Live-Validation: GitHub-Token, AWS-Key, Slack-Token gegen echte API testen
- Semgrep-Regeln für JS-Secrets (embedded Rule-Set)
- JWT in JS extrahieren + dekodieren (base64 decode ohne verify)
- Google-API-Key Scope Detection (eingeschränkt vs. unrestricted)
- Firebase-DB-URLs erkennen + öffentlichen Zugriff testen
- Grafana/Prometheus/ELK Endpoints aus JS extrahieren

**Verifikation:** Test-JS-File mit bekannten Secrets → Phase muss alle finden

---

### A10. 169-WEBTRANSPORT + 168-H3QUIC — Moderne Protokolle ausbauen

**Problem:** Nur basic Endpoint-Enumeration. Keine aktive Manipulation oder Stream-Angriffe.

**Erweiterung:**
- 0-RTT Replay: QUIC 0-RTT Handshake replayen → Idempotenz-Prüfung
- QLOG-Analyse: Wenn QLOG verfügbar, Connection-Details extrahieren
- WebTransport Datagram Injection: Unidirektionale Streams testen
- HTTP/3 Server Push Abuse: Nicht-angeforderte Push-Responses
- Alt-Svc Header Analyse: HTTP/3 Upgrade Path erkennen
- QUIC Version Downgrade: Version `0xff000000` (Google QUIC) erzwingen

**Verifikation:** Gegen h2o/nghttp2 QUIC-Server testen

---

## B) Neue Phasen (6 neue Phasen-Gruppen)

### B1. Aktiver Web-Crawler (Phase 170-CRAWL)

**Rationale:** Tool sammelt nur passive URLs (gau, wayback, katana). Aktives Crawling entdeckt Hidden Endpoints, die nicht in öffentlichen Archiven sind.

**Technik:**
- Playwright/requests-basiertes Crawling
- JS-Rendering für SPA (React, Vue, Angular)
- Form-Filling mit Default-Werten
- robots.txt + sitemap.xml Parsing
- Link-Extraktion + Deduplizierung
- Session-Management (Login → Auth-Crawling)
- Max Tiefe 3, Max 200 URLs pro Domain

**Verifikation:** Crawling gegen lokale Test-App → alle in `<a>` Links gefunden?

---

### B2. Authenticated Scanning (Phase 171-AUTHSCAN)

**Rationale:** Viele Phasen erkennen nichts, weil sie nicht eingeloggt sind. Explizite Auth-Phase: Login-Flow automatisieren, Session-Cookie extrahieren, dann andere Phasen damit füttern.

**Technik:**
- Form-basierter Login (User/Pass → POST → Cookie extrahieren)
- OAuth/SSO Login (Redirect Chain folgen)
- Session-Cookie in `cookie` Config-Feld schreiben
- 2FA-Umgehung: Wenn 2FA erkannt → Session-Token aus API-Response extrahieren
- Multi-Role: `user_a` und `user_b` für IDOR

**Verifikation:** Gegen Test-App mit Login-Formular → Cookie muss in `outdir/cookies/` landen

---

### B3. Mobile API Deep Analysis (Phase 172-MOBILE-DEEP)

**Rationale:** Phase 75-MOBILEAPI ist nur basic Endpoint-Discovery. APK/IPA Decompilation + Firebase + Plist Secrets fehlen.

**Technik:**
- APK-Download + `unzip` + `dex2jar` + `jadx` Decompilation (optional)
- `AndroidManifest.xml` → exported Activities, Content-Provider, Deep Links
- `GoogleService-Info.plist` → Firebase/API Keys
- iOS `Info.plist` → URL Schemes, App Transport Security
- Hardcoded API Endpoints + Secrets aus Smali/BYTEcode
- Firebase-DB-Testing: `https://<app>.firebaseio.com/.json`
- Realm/CoreData DB Exposure

**Verifikation:** Test-APK mit bekannten Hardcoded-Secrets

---

### B4. Software Composition Analysis (Phase 173-SCA)

**Rationale:** Phase 29-DEPCHECK prüft nur JS-Deps via npm audit. Fehlt: SBOM-Generierung, transitive Dep-Analyse, License Compliance.

**Technik:**
- `package-lock.json` / `yarn.lock` → Dependency Tree parsen
- `requirements.txt` / `Pipfile.lock` → Python Deps
- `go.sum` → Go Deps
- CVE Matching via lokaler NVD-Datenbank (oder OSV.dev API)
- Transitive Deps auflösen (rekursiv)
- SBOM im CycloneDX JSON-Format generieren
- License-Compliance-Check (GPL/AGPL in kommerziellen Projekten flaggen)

**Verifikation:** Gegen Repo mit bekannten vulnerablen Deps testen

---

### B5. Container Security (Phase 174-CONTAINER-SEC)

**Rationale:** Phase 128-DOCKER prüft nur Registry-Exposure. Fehlt: Image-Layer-Scan, Runtime-Security, Docker-Socket-Exposure.

**Technik:**
- `Dockerfile` Analyse: `FROM` Base-Image, `RUN apt-get`, exposed Ports, USER
- `docker-compose.yml` → Service-Exposure, Netzwerkkonfiguration
- Docker-Socket Check: `curl --unix-socket /var/run/docker.sock http://localhost/containers/json`
- Container Runtime: `/proc/1/cgroup` → Container-Erkennung
- Image-Layer: Wenn Registry-Zugriff → Layer-Download + Secret-Scanning
- Kubernetes: Phase 129-K8S existiert, aber `kubelet` Read-Only-Port + `etcd` + `dashboard` Deployment-Check fehlen
- `seccomp` / `AppArmor` Profile Check

**Verifikation:** Gegen Docker-Container mit bekanntem Socket-Exposure testen

---

### B6. WebSocket Deep Fuzzing (Phase 175-WS-DEEP)

**Rationale:** Phase 54-WS-FUZZ + 41-WEBSOCKET testen basic Messages. Fehlt: Protokoll-Fuzzing, Ping/Pong-Manipulation, Close-Frame-Attacken.

**Technik:**
- Payload-Fuzzing über WebSocket (100+ Payloads aus Injection-Library)
- Ping/Pong-Flood → Resource-Exhaustion
- Close-Frame-Manipulation (Status-Code 1000-4999 testen)
- Sub-Protocol Enumeration (Header `Sec-WebSocket-Protocol`)
- WS-DoS: Large Payloads (>1MB)
- Cross-Origin WebSocket (kein Origin-Check)
- WS Message Replay (gleiche Message nochmal senden)

**Verifikation:** Gegen lokalen WS-Echo-Server

---

## Priorisierungsmatrix

| Phase | Aufwand | Impact | Neue Vuln-Klassen | Quick-Win |
|-------|---------|--------|-------------------|-----------|
| A1: SSRF Deepening | Medium | Hoch | IMDSv2, ECS, Cloud Run | Ja |
| A2: GraphQL | Mittel | Hoch | Batching, Persisted Query | Ja |
| A3: FileUpload Polyglot | Niedrig | Mittel | Polyglot RCE, Metadata XSS | **Ja** |
| A4: Context-aware XSS | Hoch | Sehr hoch | Angular/React SSTI, SW XSS | Nein |
| A5: Business Logic | Mittel | Hoch | Step-Skipping, Integer Overflow | Teilweise |
| A6: Git Deepening | Niedrig | Mittel | Commit-History, Submodule | **Ja** |
| A7: Race Toolkit | Mittel | Mittel | TOCTOU, Session-Race | Nein |
| A8: LFI Deepening | Niedrig | Hoch | Session Wrapper, Proc-FS | **Ja** |
| A9: JS Secrets ML | Mittel | Mittel | Entropy, Live-Validation | Teilweise |
| A10: Modern Proto | Hoch | Niedrig | 0-RTT, Stream-Angriff | Nein |
| B1: Active Crawler | Hoch | Sehr hoch | Hidden Endpoints | Nein |
| B2: Auth Scan | Mittel | Sehr hoch | Authenticated Vulns | **Ja** |
| B3: Mobile Deep | Mittel | Hoch | APK Secrets, Firebase | Teilweise |
| B4: SCA | Mittel | Hoch | Transitive CVEs | Teilweise |
| B5: Container Sec | Mittel | Mittel | Socket, Runtime | Nein |
| B6: WS Deep | Niedrig | Mittel | WS Injection, DoS | **Ja** |

---

## Empfohlener Fahrplan

**Sprint 1 (Quick Wins):** A3 (Polyglot), A6 (Git), A8 (LFI), B6 (WS-Deep), A1 (SSRF)

**Sprint 2 (Tiefe Integration):** A2 (GraphQL), A5 (Business Logic), A9 (JS-Secrets), B2 (Auth Scan)

**Sprint 3 (Neue Phasen):** B1 (Crawler), B3 (Mobile), B4 (SCA)

**Sprint 4 (Advanced):** A4 (Context-XSS), A7 (Race), A10 (Modern Proto), B5 (Container)

---

## Verifikation für jede Änderung

1. **Lint:** `ruff check vulnforge/ && ruff format --check vulnforge/`
2. **Typecheck:** `mypy vulnforge/`
3. **Test:** `pytest tests/ -v` (mindestens existierende Tests nicht brechen)
4. **Phase-spezifisch:** Neue Test-Datei in `tests/test_phase_XXX.py`
5. **Integration:** `pytest tests/test_integration.py -v`
