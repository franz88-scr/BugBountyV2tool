# Plan: BugBountyV2tool — Erweiterung der Vulnerability Detection

## Überblick

Dieser Plan basiert auf einer Analyse der aktuellen 185+ Phasen. Zwei bestehende Pläne (`vuln-deepening-plan.md`, `vuln-enhance-agent-prompt.md`) beschreiben bereits 20 neue Phasen (IDs 170–190) und 12 Vertiefungen. Diese wurden **noch nicht implementiert** — die Dateien existieren nicht, die Phasen sind nicht registriert.

Dieser Plan konsolidiert die bestehenden Vorschläge und identifiziert zusätzliche Lücken (Phase 3), die in den bisherigen Plänen fehlen.

---

## Phase 1: Bestehende Pläne implementieren (hohe Priorität)

Die beiden existierenden Plan-Dateien enthalten bereits detaillierte Spezifikationen. Diese sollten zuerst umgesetzt werden, da sie durchdacht und ready-to-implement sind.

### 1A: 20 neue Phasen (IDs 170–190)

| Datei | Phasen | Beschreibung |
|-------|--------|-------------|
| `vulnforge/phases/client_side_v2.py` | 170-CLIENTPP, 171-CSSINJECT, 172-DANGLING | Prototype Pollution, CSS Injection, Dangling Markup |
| `vulnforge/phases/modern_web.py` | 173-SERVICEWORKER, 174-WASMSEC, 176-JWT2SELF | Service Worker, WASM, JWT XSS |
| `vulnforge/phases/advanced_inject.py` | 175-OAUTHDEVICE, 177-SELENIUMXSS, 179-WAFBYPASS, 180-SWAGGERABUSE, 181-MFABYPASS, 182-CAPTCHABYPASS, 184-SSRFPARTIAL, 190-BROTLIORACLE | Advanced injection + auth bypass |
| `vulnforge/phases/protocol.py` | 183-CACHEDIG | HTTP/2 Cache Digestion |
| `vulnforge/phases/cms_deep.py` | 185-MAGENTO, 186-SHAREPOINT, 187-CONFLUENCE, 188-CICD, 189-TOMCAT | CMS/Framework Deep Testing |

**Detail-Spezifikation**: Siehe `vuln-enhance-agent-prompt.md` Zeilen 71–204.

### 1B: 12 Vertiefungen bestehender Phasen

| Phase | Datei | Was fehlt |
|-------|-------|-----------|
| 12-SSTI | `injection.py` | +10 Template Engines, Blind SSTI via OOB |
| 25-XXE | `injection_misc.py` | SVG XXE, DOCX XXE, XInclude, Charset-Bypass |
| 30-LFI | `client_side.py` | PHP wrappers, Log Poisoning, Windows paths |
| 22-NOSQLI | `injection_misc.py` | Firebase, CouchDB, MongoDB `$where` |
| 26-CMDINJECT | `injection_misc.py` | Time-based, OOB-based, Filter-Bypass |
| 24/36-JWT | `auth.py` | JWK injection, `kid` path traversal, EdDSA→HS256 |
| 28-CACHED | `client_side.py` | Unkeyed cookies, Vary poisoning |
| 20/132-GRAPHQL | `graphql_chain.py` | Batching, Aliasing-DoS, Field Suggestion BF |
| 34/136-RATELIMIT | `fuzzing.py` | X-Forwarded-For rotation, Proxy rotation |
| 37-FILEUPLOAD | `client_side.py` | Polyglot files, Race condition, ImageMagick |
| 80-STOREXSS | `client_side.py` | Multipage crawl, OOB confirmation |
| 11b-SQLMAP | `injection.py` | Level=5/Risk=3, MSSQL/PostgreSQL |

**Detail-Spezifikation**: Siehe `vuln-enhance-agent-prompt.md` Zeilen 208–276.

---

## Phase 2: Zusätzliche Deepenings (mittlere Priorität)

Nach Implementierung der 12 geplanten Vertiefungen lohnen sich diese weiteren:

| Phase | Verbesserung | Aufwand | Impact |
|-------|-------------|---------|--------|
| **157-2FA → MFA Deep** | TOTP-Brute-Force (Timing-Window), MFA-Fatigue (Push-Spam), Backup-Code-Rate-Limit, Enrollment-Bypass (MFA optional → nur PW) | 3d | Hoch |
| **86-DORK** | +Shodan-dorking, +GreyNoise dorks, +GitHub dorks für Credentials | 1d | Medium |
| **41-WEBSOCKET / 54-WS-FUZZ** | Origin-Leak-Test, Cross-Origin-WebSocket-Hijacking (CSWSH), Protokoll-Smuggling über WS | 2d | Hoch |
| **38-SMUGGLE** | HTTP/2 Downgrading-Smuggling, Connection: keep-alive Smuggle | 1d | Medium |
| **39-OAUTH** | Statische Redirect-URI Liste (whitelist-basiert), State-Parameter-Überprüfung, PKCE-Challenge-Bypass | 1d | Mittel |
| **65-SESSION** | Concurrent-Session-Limit-Test, Session-Fixation via Cookie-Präfix, JWK-Header-in-Session | 1d | Medium |
| **49-FRAMEWORKS** | Nuxt.js, Next.js, Remix, Astro, SvelteKit spezifische Checks | 1d | Mittel |
| **127-CICD** | GitHub Actions Cache Poisoning, Self-Hosted Runner Abuse, GitLab CI Variable Leak | 1d | Mittel |

---

## Phase 3: Neue Phasen — Lücken in den bisherigen Plänen (hohe Priorität)

Diese Attack-Vektoren wurden weder in `vuln-deepening-plan.md` noch in `vuln-enhance-agent-prompt.md` adressiert.

### Neue Dateien

```
vulnforge/phases/account.py           # 191-ATO (Account Takeover)
vulnforge/phases/redos.py             # 192-REDOS (ReDoS)
vulnforge/phases/webrtc.py            # 193-WEBRTC (WebRTC Leak)
vulnforge/phases/cookie_security.py   # 194-COOKIETOSS (Cookie Tossing), 195-MIMESNIFF (MIME Sniffing)
vulnforge/phases/pwa_security.py      # 196-PUSHAPI (Web Push API)
```

### Detail-Spezifikation

#### 191-ATO — Account Takeover Detection
- **Erkennung**: Credential Stuffing via API (Login mit Default- oder bekannten Credentials), Password-Reset-Token-Rate-Limiting, OTP-Bypass via Response-Manipulation, Email-Change-ohne-Confirmation, OAuth-Account-Linking-Abuse
- **Output**: `ato_findings.txt`
- **Deps**: `05-HARVEST`
- **CWE**: CWE-287, CWE-640, CWE-620

#### 192-REDOS — ReDoS Detection
- **Erkennung**: Sende crafted Inputs an Such-/Validierungsendpunkte, die Regex-Catastrophic-Backtracking auslösen (`a a a a a a!` pattern), messe Response-Time-Delta, identifiziere Endpoints mit >5s Verzögerung
- **Payloads**: Email-ReDoS `a@a.a a a a a a a a a a a a a!`, Base64-ReDoS, Date-ReDoS
- **Output**: `redos_findings.txt`
- **Deps**: `05-HARVEST`, `07-PARAMS`

#### 193-WEBRTC — WebRTC Internal IP Leak
- **Erkennung**: STUN/TURN Server Discovery via JS-Execution (Playwright), prüfe ob ICE-Candidates interne IPs leaken (`10.x`, `192.168.x`, `172.16-31.x`), STUN-SSRF (URL-Umleitung von STUN-Requests)
- **Output**: `webrtc_leak.txt`
- **Deps**: `04-SCAN` oder `05-HARVEST`

#### 194-COOKIETOSS — Cookie Tossing
- **Erkennung**: Prüfe ob Subdomain A Cookie für Domain `.example.com` setzen kann, der Session-Cookie von Subdomain B überschattet. Teste mit `__Host-` und `__Secure-` Prefix-Bypass. 
- **Checks**: Fehlendes `__Host-` Prefix auf Session-Cookies, wildcard Domain-Cookies ohne Path-Restriction
- **Output**: `cookie_toss.txt`
- **Deps**: `05-HARVEST`

#### 195-MIMESNIFF — Content-Type / MIME Sniffing
- **Erkennung**: Prüfe `X-Content-Type-Options: nosniff` Header, teste MIME-Sniffing-Bypass (`Content-Type: text/plain` mit HTML-Payload), JSON/XML Endpoints mit HTML-Injection
- **Output**: `mime_sniff.txt`
- **Deps**: `04-SCAN`

#### 196-PUSHAPI — Web Push API Security
- **Erkennung**: Push-Subscription-Endpoints ohne Auth, VAPID-Key-Exposure, Push-Payload-Injection, Subscription-Hijacking via fehlender User-Geste
- **Output**: `push_api.txt`
- **Deps**: `05-HARVEST`, `06-JSINTEL`

---

## Priorisierte Umsetzungsreihenfolge

| Rang | Task | Geschätzter Aufwand | Impact |
|------|------|---------------------|--------|
| 1 | **170-CLIENTPP** (Prototype Pollution) | 2d | Critical |
| 2 | **191-ATO** (Account Takeover) | 2d | Critical |
| 3 | **172-DANGLING** (Dangling Markup) | 1d | High |
| 4 | **171-CSSINJECT** (CSS Injection) | 1d | High |
| 5 | **MFA Deep** (Phase 157 erweitern) | 3d | Critical |
| 6 | **192-REDOS** (ReDoS) | 1d | High |
| 7 | **173-SERVICEWORKER** (Service Worker) | 2d | High |
| 8 | **SSTI Deep** (Phase 12) | 1d | High |
| 9 | **XXE Deep** (Phase 25) | 1d | High |
| 10 | **JWT Deep** (Phase 24/36) | 1d | Medium |
| 11 | **LFI Deep** (Phase 30) | 1d | Medium |
| 12 | **194-COOKIETOSS** | 1d | Medium |
| 13 | **SQLMap Deep** (Phase 11b) | 1d | Medium |
| 14 | **CMDINJECT Deep** (Phase 26) | 1d | Medium |
| 15 | **NoSQLi Deep** (Phase 22) | 1d | Medium |
| 16 | **180-SWAGGERABUSE** | 2d | High |
| 17 | **195-MIMESNIFF** | 0.5d | Low-Medium |
| 18 | **Cache Poisoning Deep** (Phase 28) | 1d | Medium |
| 19 | **193-WEBRTC** | 1d | Medium |
| 20 | **File Upload Deep** (Phase 37) | 1d | Medium |
| 21 | **Rate Limit Deep** (Phase 34/136) | 1d | Medium |
| 22 | **190-BROTLIORACLE** | 2d | Medium |
| 23 | **GraphQL Deep** (Phase 20/132) | 1d | Medium |
| 24 | **176-JWT2SELF** | 1d | Medium |
| 25 | **196-PUSHAPI** | 1d | Low-Medium |
| 26 | **Stored XSS Deep** (Phase 80) | 2d | Medium |
| 27 | **CMS Deep** (Phase 185-189) | 3d | Medium |

---

## Registrierung (für alle Phasen)

Jede neue Phase muss registriert werden in:

| Datei | Was |
|-------|-----|
| `vulnforge/config.py` | `VALID_PHASES`, optional `QUICK_SKIP_PHASES`, `DOS_PHASES`, `PHASE_CATEGORIES` |
| `vulnforge/phases/__init__.py` | Import, `PIPELINE` list, `PHASE_DEPS`, `_PHASE_WEIGHTS`, `STAGES` |
| `vulnforge/artifacts.py` | `ArtifactDef` für jeden Output-File |
| `vulnforge/finding.py` | `_VULN_TYPE_CWE`, `_VULN_TYPE_CVSS`, `_VULN_TYPE_SEVERITY` |
| `vulnforge/remediation.py` | `REMEDIATIONS` Eintrag |

---

## Verification

```bash
ruff check vulnforge/
mypy vulnforge/
pytest tests/ -v
python3 vulnforge.py --list-phases 2>&1 | grep "1[7-9][0-9]-"
```
