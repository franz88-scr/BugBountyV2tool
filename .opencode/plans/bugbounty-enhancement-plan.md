# BugBountyV2tool Enhancement Plan

## Zielsetzung
Das Tool hat bereits **164 Phasen** und **45+ integrierte Tools**. Es deckt Recon, Injection, Auth, Client-Side, Cloud, OSINT und CMS sehr gut ab. Ziel ist es, Lücken zu schließen und existierende Phasen zu vertiefen, um 2026-relevante Vulnerabilities zu finden die aktuell durchs Raster fallen.

---

## Track A: Neue Hochwert-Phasen (vorher nicht abgedeckt)

### A1: LLM/AI Security (`149-LLMSEC`–`152-LLMADV`)
**Warum fehlt das?** LLM-Endpunkte gibt es bei fast jedem Target (Chatbots, Support, Code-Gen). Kein anderes OS-Tool testet das systematisch.

- **149-LLMSEC**: Prompt Injection (direct, indirect, jailbreak patterns)
- **150-LLMLEAK**: System Prompt Leakage, sensitive data extraction via prompt engineering
- **151-RAGPOISON**: RAG context poisoning, knowledge base injection
- **152-LLMADV**: Tool calling abuse, function parameter injection, output validation bypass

### A2: Business Logic Deep Testing (`153-BIZLOGIC`–`157-BIZADV`)
**Warum?** Business Logic Bugs sind die wertvollsten Findings in Bug Bounties (Payment Bypass, Coupon Abuse). Aktuell nur 1 generische Workflow-Phase.

- **153-BIZLOGIC**: State machine violation, multi-step workflow skipping, race window in workflows
- **154-PAYMENT**: Price manipulation, integer overflow, currency swap, Stripe webhook replay
- **155-COUPON**: Coupon stacking, reuse, negative quantity, multi-use abuse
- **156-MTENANT**: Multi-tenant isolation, tenant ID switching, shared resource access
- **157-2FA**: 2FA/CAPTCHA bypass (OTP reuse, backup code, captcha replay, rate-limit reset)

### A3: SSO & Federation (`158-SSO`–`160-SSOADV`)
**Warum?** Enterprise-Targets haben fast immer SSO. Aktuelle OAuth/SAML-Phasen sind basic.

- **158-SSO**: OIDC hybrid flow abuse, token injection, nonce replay
- **159-SAMLADV**: XML signature wrapping, assertion injection, response tampering
- **160-SSOCONF**: Cross-tenant token confusion, IdP spoofing, login CSRF

### A4: Electron/Desktop Security (`161-ELECTRON`–`164-ELECTRONADV`)
**Warum?** Discord, Slack, Teams, VS Code, 1Password — alle haben Bug-Bounty-Programme. Keine Electron-Coverage.

- **161-ELECTRON**: contextIsolation check, preload script analysis
- **162-ELECTRONRCE**: nodeIntegration abuse, shell.openPath, openExternal RCE
- **163-ELECTRONPROTO**: Protocol handler hijack, argument injection
- **164-ELECTRONUPD**: Auto-update MITM, rollback attacks, squirrel abuse

### A5: Supply Chain (`165-SUPPLYCHAIN`–`166-SUPPLYADV`)
**Warum?** Dependency Confusion zahlt oft hohe Bounties. Keine Coverage.

- **165-DEPCONF**: Dependency confusion (public package takeover via private name matching)
- **166-TYPOSQUAT**: Typo-squatting detection in package.json, requirements.txt, go.mod

### A6: Modern Protocols (`167-H2RAPID`–`169-QUICFUZZ`)
**Warum?** CVE-2023-44487 (HTTP/2 Rapid Reset) war 2023-2024 extrem relevant. HTTP/3 kommt.

- **167-H2RAPID**: HTTP/2 rapid reset, stream cancellation flood
- **168-H3QUIC**: QUIC/HTTP/3 attack surface (QPACK bomb, 0-RTT replay, connection migration)
- **169-WEBTRANSPORT**: WebTransport endpoint fuzzing

---

## Track B: Tiefenverbesserung bestehender Phasen

### B1: OAuth (Phasen 39, 61, 82) — aktuell 3 Phasen, Ziel 6
| Neu | Beschreibung |
|---|---|
| Device Authorization Grant | device_code interception, user_code brute force |
| PKCE Bypass | code_challenge_method downgrade, missing PKCE |
| Token Injection | auth code injection, token swapping zwischen Clients |

### B2: JWT (Phasen 24, 36) — aktuell 2 Phasen, Ziel 5
| Neu | Beschreibung |
|---|---|
| JKU Injection | jku-Header auf attacker-controlled JWK-Set zeigen |
| JWK Confusion | Public Key in jwk-Header bei RSA-Tokens |
| Key ID Traversal | Path Traversal via kid-Header |
| Algorithm Confusion | HS256 für RSA-Tokens erzwingen |

### B3: GraphQL (Phasen 20, 132) — aktuell 2 Phasen, Ziel 5
| Neu | Beschreibung |
|---|---|
| Persisted Query Bypass | Introspection trotz persisted-only mode |
| Alias Exhaustion | 10.000+ Aliase in einer Query |
| Depth Limit Bypass | Fragment recursion, union type depth |
| Batching Auth Bypass | Private Felder via batched Queries |

### B4: IDOR (Phasen 17, 81) — aktuell 2 Phasen, Ziel 5
| Neu | Beschreibung |
|---|---|
| UUID v1 Extraction | Timestamp aus v1-UUIDs extrahieren |
| Hash ID Detection | Base64/Hash-Patterns in IDs erkennen |
| Time-Based Prediction | Sequenzielle Timestamp-Vorhersage |
| Bulk Enumeration | Parallelisierte ID-Enumeration |

### B5: File Upload (Phasen 37, 78) — aktuell 2 Phasen, Ziel 5
| Neu | Beschreibung |
|---|---|
| Polyglot Files | GIF+PHP, JPEG+JS, SVG+XSS |
| Zip Slip | Path Traversal via zip-entries |
| SVG Attacks | XSS via onload, XXE via SVG parser |
| Filename Injection | Path traversal + cmd injection via filename |

### B6: SSRF (Phasen 17b, 66) — aktuell 2 Phasen, Ziel 5
| Neu | Beschreibung |
|---|---|
| Cloud Metadata 2024+ | IMDSv2 bypass, neue AWS/GCP/Azure endpoints |
| PDF Generator SSRF | wkhtmltopdf, puppeteer SSRF |
| DNS Rebinding Chain | Host-basierte Allowlists umgehen |
| Open Redirect → SSRF | Chaining von open redirect zu SSRF |

### B7: Race Conditions (Phasen 23, 83) — aktuell 2 Phasen, Ziel 5
| Neu | Beschreibung |
|---|---|
| TOCTOU | Read-then-write race auf Limits/Kontingente |
| Database Race | Concurrent row update, unique constraint bypass |
| Async/Await Race | JavaScript Promise.all race auf Balance-Checks |
| Coupon/Discount Race | Parallel redeem desselben Coupons |

### B8: XSS (Phasen 11, 11a, 80, 99e) — aktuell 4 Phasen, Ziel 6
| Neu | Beschreibung |
|---|---|
| DOM Clobbering | anchor/id-basiertes DOM-Clobbering |
| Mutation XSS | Sanitizer API bypass, DOMPurify bypass |
| Scriptless XSS | CSS injection, style-tag data exfiltration |
| Service Worker XSS | Malicious SW registration |

---

## Track C: Cross-Cutting

### C1: Smart Phase Chaining
- SSRF-fähige Parameter erkennen → auto-trigger SSRF-FULL
- File Upload Finding → auto-trigger Command Injection auf Upload-Endpoint
- OAuth Finding → auto-trigger JWT-Phase auf Token-Endpoint
- IDOR Finding → auto-trigger Rate Limit Bypass für Bulk Enumeration

### C2: Context-Aware Payload Selection
- Nur Laravel-Payloads wenn Framework=laravel erkannt
- WAF-Erkennung → Payload-Obfuskation anpassen
- Content-Type erkennen → passende Encoding (JSON vs URL vs XML)
- Response-Format erkennen → passende Injection-Vektoren

### C3: False-Positive Learning Loop
- Tool-Reliability pro Target-Typ tracken
- Confidence automatisch anpassen basierend auf Historie
- FP-Patterns aus vergangenen Scans für Filterung nutzen

---

## Priorisierung

| Rang | Feature | Aufwand | Impact | Risiko |
|---|---|---|---|---|
| 1 | LLM/AI Security | Medium | Sehr hoch | Niedrig |
| 2 | Business Logic | Medium | Sehr hoch | Mittel |
| 3 | Race Conditions vertiefen | Niedrig | Hoch | Niedrig |
| 4 | JWT vertiefen | Niedrig | Hoch | Niedrig |
| 5 | SSRF vertiefen | Niedrig | Hoch | Niedrig |
| 6 | SSO/Federation | Mittel | Hoch | Mittel |
| 7 | IDOR vertiefen | Niedrig | Mittel | Niedrig |
| 8 | File Upload vertiefen | Mittel | Hoch | Mittel |
| 9 | Electron/Desktop | Hoch | Mittel | Hoch |
| 10 | Supply Chain | Mittel | Mittel | Niedrig |

---

## Dateien die geändert werden müssen

### Neue Phasen implementieren:
- `vulnforge/phases/llm_ai.py` — LLM Security Phases (149-152)
- `vulnforge/phases/bizlogic.py` — Business Logic Phases (153-157)
- `vulnforge/phases/sso.py` — SSO/Federation Phases (158-160)
- `vulnforge/phases/electron.py` — Electron Security Phases (161-164)
- `vulnforge/phases/supplychain.py` — Supply Chain Phases (165-166)
- `vulnforge/phases/modern_proto.py` — HTTP/2, HTTP/3, QUIC (167-169)

### Bestehende Phasen vertiefen:
- `vulnforge/phases/auth.py` — OAuth + JWT vertiefen
- `vulnforge/phases/email_misc.py` — IDOR vertiefen
- `vulnforge/phases/client_side.py` — File Upload, XSS vertiefen
- `vulnforge/phases/injection.py` — SSRF, GraphQL vertiefen
- `vulnforge/phases/smuggling.py` — Race Conditions vertiefen

### Registrierung:
- `vulnforge/phases/__init__.py` — Neue Phasen importieren + PIPELINE/PHASE_DEPS eintragen
- `vulnforge/config.py` — Neue IDs in VALID_PHASES + FAST_PHASES + QUICK_SKIP + DOS set

### Config:
- `vulnforge/config.py` — Neue CLI-Flags + Config-Felder

### Installation:
- `install.sh` — Neue externe Tools (falls nötig)
- `Dockerfile` — Neue Abhängigkeiten (falls nötig)

---

## Verification

1. `ruff check vulnforge/ && ruff format --check vulnforge/` — kein Lint-Fehler
2. `mypy vulnforge/` — kein Typecheck-Fehler
3. `pytest tests/ -v` — alle bestehenden Tests grün
4. Neuer Test: `pytest tests/test_new_phases.py -v` — mindestens smoke test pro neuer Phase
5. `python vulnforge.py -d example.com --only 149-LLMSEC --dry-run` — Phase wird gelistet
6. Reale Target-Tests auf bekannt vulnerablen Apps (DVWA, Juice Shop, deliberately-vulnerable LLM)
