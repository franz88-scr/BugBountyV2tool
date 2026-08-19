# Phase Review — BugBountyV2tool (VulnForge v3.1.0)

Bewertung aller ~197 Phasen durch 6 parallele Review-Subagenten. Ziel: mehr gefundene
Vulns (False Negatives beseitigen) und weniger False Positives. Jede Zeile referenziert
`file:line` und wurde gegen den Code verifiziert.

- [Querschnitts-Themen](#querschnitts-themen)
- [Gruppe 1 — Recon & Discovery](#gruppe-1--recon--discovery)
- [Gruppe 2 — Injection & Server-Side](#gruppe-2--injection--server-side)
- [Gruppe 3 — Auth, Session & Access Control](#gruppe-3--auth-session--access-control)
- [Gruppe 4 — Client-Side & Web Platform](#gruppe-4--client-side--web-platform)
- [Gruppe 5 — Infra, Cloud, CMS & Secrets](#gruppe-5--infra-cloud-cms--secrets)
- [Gruppe 6 — Advanced & Spezialisiert](#gruppe-6--advanced--spezialisiert)

Kategorien: `FALSE-NEG` = verpasste Vulns, `FALSE-POS` = erfundene Findings, `BUG` = Code-Fehler.

---

## Querschnitts-Themen

Diese Fehler wiederholen sich über viele Phasen und haben den größten Gesamteffekt.

1. **`host.split(":")[0]` auf httpx-`hosts.txt`-Format.** Zeilen sind
   `https://example.com [200] [title] [tech]`. Der Split ergibt `"https"`, Requests gehen
   an `https://https` und scheitern still. Betroffen: `113-WEBDAV` (network.py:215),
   `114-SNMP` (network.py:359-371), `63-DOC-ATTACK` (email_misc.py:393),
   `57-DEFAULT-CREDS` (web_infra.py:1021). Zusätzlich **zerstört `00-SCOPE` die
   `hosts.txt` komplett** (scope.py:70-81) und `04-SCAN` skippt alle Port-Hosts
   (scan.py:268-279), weil der Status-Bracket `[200` ins Parsing leckt.
   Fix: `urllib.parse.urlparse(...).hostname` bzw. `_load_live_hosts()` verwenden.

2. **Nicht registrierte Artefakt-Dateinamen.** Findings landen in Dateien, die nicht in
   `vulnforge/artifacts.py` (`ARTIFACTS`) registriert sind → Reporting, Triage und
   Exploit-Chain lesen sie nie. Reiner Findings-Verlust. Betroffen u.a.:
   `ldap_injection_42.txt` statt `ldap_injection.txt` (injection_misc.py:835),
   `bucket_enum.txt` (origin_cloud.py:502), `k8s_exposure.txt` (cloud.py:160),
   `cdn_detection.txt` (web_infra.py:47), alle `sso_*.txt` (sso.py),
   `bizlogic_*.txt`, `llm_*.txt`, `electron_*.txt`, `supplychain_*.txt`,
   `modern_*.txt` (modern_proto.py:40,99,158), `websocket_deep.txt` (smuggling.py:1336).

3. **Baseline-lose Detektion = Massen-False-Positives.** JWT-Acceptance bei jedem
   HTTP 200 (auth.py:1223-1227), MASSASSIGN bei jedem 200-POST (auth.py:402-410),
   NOSQLI/SSPP/DESERIAL bei jeder JSON-API (injection_misc.py:186-215, 680-706,
   1048-1091), `26-CMDINJECT` flaggt Seiten mit "Linux"/"root:" (injection_misc.py:543-562),
   `12-SSTI` matcht Payload-Substrings gegen reine Reflektion (injection.py:906-920).

4. **`prev`-Dict wird als Dateipfad statt Zeilenliste gelesen.** `179-WAFBYPASS`
   (advanced_inject.py:474) und `184-SSRFPARTIAL` (advanced_inject.py:1099) iterieren
   einzelne Zeichen des Pfads statt Endpoints. Beide Phasen nullifiziert.
   Fix: `prev[...]` als Pfad auflösen und mit `read_lines()` lesen.

5. **`HTTPError` statt Status-Rückgabe** (utils.py:666-691). Alle 401/403/405-Branches
   sind unerreichbar → `17-IDOR` Privilege-Escalation (auth.py:582),
   `96-METHODOVERRIDE`, `98-CASEBYPASS`, `97-FORCEDBROWSE` melden "keine Bypasses",
   ohne je getestet zu haben.

6. **Race-Tests sind nicht echt konkurrent.** `23-RACE` wird vom Throttle serialisiert
   (100 ms Abstand, smuggling.py:153,313), `181-MFABYPASS` nutzt 5 verschiedene
   Device-IDs (advanced_inject.py:820-846). Races sind damit prinzipiell nicht
   nachweisbar.

---

## Gruppe 1 — Recon & Discovery

Dateien: `recon/` (scope, subdomain, dns, scan, harvest, jsintel, params, osint),
`fuzzing.py`, `vuln_scan.py`, `extended.py`, `graphql_chain.py`.

- **04b-TAKEOVER-VALIDATE | recon/scan.py:392-393 | BUG |** `ln.split()[0]` nimmt das
  erste Token einer nuclei-`-o`-Zeile als URL, aber das ist die Template-ID
  (`[http-takeover] <url> [status]`). Der Candidate ist dadurch `[http-takeover]`-artig,
  fällt durch den `startswith("http")`-Filter oder wird als Müll-Host geprobt.
  | Die ganze Validierung berührt nie die echte Takeover-URL. | URL-Token per
  Regex/`next(tok for tok in ln.split() if tok.startswith(("http://","https://")))` extrahieren.
- **04b-TAKEOVER-VALIDATE | recon/scan.py:430-431 | FALSE-POS |** `[confirmed] ... (likely
  vulnerable)` bei Status 404 oder beliebigen Substrings ("not found", "does not exist", …),
  ohne DNS/CNAME/Fingerprint-Check. `takeover_confirmed.txt` ist
  `severity_hint="critical"` (artifacts.py:137-144) und wird von 45-EVIDENCE als PoC
  geerntet → normale 404er werden als bestätigte kritische Takeover gemeldet. |
  Vor `[confirmed]`: dangling CNAME zu Cloud-Provider-Domain + Provider-spezifische
  "no such bucket"-Signatur verlangen.
- **00-SCOPE | recon/scope.py:70-81 | BUG/FALSE-NEG |** Hostname-Parsing mit
  `split("://")[-1].split("/")[0]` lässt den httpx-Suffix (`[200] [title]`) im Wert →
  `fnmatch` schlägt fehl → Zeile 81 **überschreibt `hosts.txt` mit leer**. |
  Jeder `--force`/Resume-Lauf mit Scope-Datei zerstört die Live-Host-Liste. |
  `urllib.parse.urlparse(...).hostname` bzw. `_target_token()` nutzen.
- **04-SCAN | recon/scan.py:268-272, 277-279 | BUG/FALSE-NEG |** `_ln.split("]")[0].split("//")[-1]`
  ergibt `example.com [200` (Status-Bracket leckt). `_live_hosts` matcht nie gegen
  `ports.txt`-Hosts → alle Port-Hosts geskippt. | nmap `-sV` läuft nie, `services.txt`
  bleibt leer. | Hostname aus `urllib.parse.urlparse(_ln.split()[0]).hostname` bauen.
- **09-VULNSCAN | vuln_scan.py:158-167 | BUG/FALSE-NEG |** WAF-Dedup-Key aus
  `parts2[-1]` (Status-Token) → `waf-detect:[200]` für jeden Host → nur der erste
  WAF-Finding überlebt. | WAF-Abdeckung unterberichtet, 21b-WAFBYPASS verhungert. |
  URL-Token als Key verwenden.
- **68-DEPCVE | vuln_scan.py:467-479, 497-517 | FALSE-POS + FALSE-NEG |** Version aus
  beliebigem nächsten Pfadsegment → `jquery@dist`, und safe-Thresholds widersprechen
  den Fixed-Versionen (jquery ≥3.0.0 vs. CVE fixed in 3.5.0). | Falsche Dep-CVEs
  hochgezogen UND echte jquery-CVEs unterdrückt. | Version nur bei
  `v?\d+(\.\d+)+`-Match akzeptieren, Thresholds angleichen.
- **86-DORK | recon/osint.py:261, 267-281 | BUG/FALSE-NEG |** DuckDuckGo liefert
  protocol-relative `href="//duckduckgo.com/l/?uddg=…"`, Regex matcht nur `https?://`.
  | Dorking-Phase komplett tot. | `uddg=`-Redirect-Target unescaped extrahieren.
- **21-WAF / 21b-WAFBYPASS | fuzzing.py:354-357, 382-384, 513-531, 572-573 | FALSE-POS |**
  Kein Baseline-Request: "blocked/denied/security" im Body → `[active-blocked-content]`;
  nicht-geblockte Payload → `[waf-bypass]`. | Ergebnis flippt globales
  `waf_detected`-Flag (fuzzing.py:382-384), das Sampling aller Downstream-Phasen
  drosselt → ein FP degradiert den ganzen Lauf. | Benignen Kontroll-Request als
  Baseline, Block nur bei Differenz melden.
- **05b-APISPEC | recon/harvest.py:398-408 | FALSE-POS |** Jeder 200er >50 Bytes ohne
  Swagger/OpenAPI-Marker wird `[api-spec]`, jedes Body mit "graphql" `[graphql-sdl]`. |
  `api_specs.txt` voll mit HTML-Seiten. | Strukturelle Signatur verlangen
  (JSON mit `paths`/`components`), Catch-all-Fallback entfernen.
- **06-JSINTEL | recon/jsintel.py:229-232 | FALSE-NEG |** FP-Filter verwirft alle
  Secrets <16 Zeichen ohne Space/Underscore. | Echte 12-15-Zeichen-Keys gehen verloren. |
  Nur Platzhalter/Entropy-Patterns filtern.
- **06-JSINTEL | recon/jsintel.py:76, 89-97 | FALSE-NEG |** `urls_sourcemap.txt` wird
  befüllt und `_SOURCE_MAP_RE` existiert, aber Source-Maps werden nie gescannt. |
  Reiner Findings-Verlust (Source-Maps enthalten oft Credentials). | Source-Maps in
  SecretFinder/nuclei speisen oder Sammlung entfernen.
- **20-GRAPHQL | graphql_chain.py:67-71 | FALSE-NEG |** `_gql_precheck` akzeptiert nur
  `application/json`/`text/json`; moderne Spec nutzt `application/graphql+json` /
  `application/graphql-response+json`. | Gültige GraphQL-Endpoints nie getestet. |
  Content-Type-Liste erweitern oder Body-Inspection (`"data"`/`"errors"`) nutzen.
- **44-CHAIN | graphql_chain.py:816-838, 881-884 | FALSE-POS |** `[credential-hit]` bei
  jedem 200 mit `Bearer <secret>`, `[idor-massassign]` bei jedem 200/201/302. | 45-EVIDENCE
  erntet das als PoC → "Credential-Kompromittierung" bei öffentlichen Login-Seiten. |
  Baseline 401/403 vs. 200-mit-Secret, State-Change verifizieren.
- **03-PERMUTE | recon/subdomain.py:263, 275 | FALSE-NEG |** `head -500` kappt
  alterx/dnsgen hart, ohne Config oder Warnung. | Permutations-Abdeckung still
  abgeschnitten. | Cap konfigurierbar machen oder batchen.

### Gruppe 1 — Top 5

1. **00-SCOPE löscht `hosts.txt`** (scope.py:70-81) — datenzerstörend bei jedem
   `--force`/Resume mit Scope-Datei.
2. **04b-TAKEOVER-VALIDATE doppelt kaputt** (scan.py:392 + 430-431) — falsches Token-
   Parsing + 404 = bestätigtes kritisches Takeover.
3. **nmap `-sV` läuft nie** (scan.py:268-279) — `services.txt` leer, Service-
   Fingerprinting-Phasen verhungern.
4. **68-DEPCVE korrupt** (vuln_scan.py:467-517) — `jquery@dist`-FPs + echte jquery-CVEs
   unterdrückt.
5. **WAF-Claims ohne Baseline** (fuzzing.py:354-357) + Status-Code-only Credential/
   Mass-Assign-Hits (graphql_chain.py:816-838) — inkl. globalem Throttle-Schaden.

---

## Gruppe 2 — Injection & Server-Side

Dateien: `injection.py`, `injection_misc.py`, `encoding.py`, `network.py`, `redos.py`,
`email_misc.py`.

- **12-SSTI | injection.py:906-920 | FALSE-POS |** Eval-Map enthält Payloads, deren
  Erwartungs-String Teil des Payloads selbst ist (`{{ ''.__class__.__mro__[2].__subclasses__() }}`
  → `"subclasses"`). `body.count(expected)` schlägt bei **reiner Reflektion** an.
  | Bestätigt-aussehende High/Critical-SSTI auf jedem reflektierenden Endpoint. |
  `body.replace(payload,"").count(expected)` und `expected != payload`-Substring fordern.
- **12-SSTI | injection.py:948-963 | FALSE-POS |** Blind-OOB hängt `[SSTI-blind-oob]`
  für jeden fehlerfreien Request an, ohne Callback-Check. | SSTI-Artefakt flutet. |
  Gegen Interactsh-Callback-Log filtern.
- **26-CMDINJECT | injection_misc.py:543-562 | FALSE-POS |** Body-Scan nach generischen
  Wörtern ("linux", "windows", "root:", "bin/") ohne Ursprungscheck. | Eine Seite mit
  "Linux" im Footer → Critical-Finding. | Einzigartige Canary-Marker
  (`; id; echo X<random>` + `X<random>uid=`) verlangen.
- **26-CMDINJECT | injection_misc.py:596-605 | FALSE-POS |** Time-based ohne Baseline
  (`elapsed >= min_seconds * 0.8`). | Jeder langsame Endpoint → `[cmdi-time-delay]`. |
  Baseline messen, `elapsed > baseline + expected_delay` mit Wiederholungen.
- **25-XXE | injection_misc.py:397-410 | FALSE-POS |** `xxe_indicators` enthält
  `"ENTITY"` und `'SYSTEM "file://'` — Substrings jedes Payloads. Body-Echo → Treffer
  ohne Entity-Resolution. | XXE-FPs auf jedem Input-echoenden Endpoint. | Nur
  Resolver-Output (`root:x:0:0`, OAST-Callback) erkennen + Kontroll-Request mit
  unaufgelöstem Platzhalter.
- **66-SSRF-FULL | injection_misc.py:1189-1197 | FALSE-POS |** `[ssrf-oob-tested]` bei
  jedem 200/301/302, `[ssrf-oob-error]` bei jeder Exception ohne "timeout". Kein
  OAST-Callback-Check. | SSRF-Artefakt flutet mit unbestätigten Zeilen. | Mit
  Callback-Log korrelieren (`_oob_callback_identifiers`, injection_misc.py:78).
- **66-SSRF-FULL | injection_misc.py:1311, 1366, 1424-1426 | FALSE-NEG |** Time-based,
  IMDSv2- und PDF-SSRF sind an `"urls" in dir()` gekoppelt; `urls` wird nur im
  `else:`-Zweig gesetzt, wenn `oast_domain` truthy ist (Zeile 1131). Ohne
  `--oast-domain` laufen sie nie. | SSRF-Coverage kollabiert ohne OAST-Domain. |
  `urls_file` unbedingt lesen, Guards entfernen.
- **66-SSRF-FULL | injection_misc.py:1266-1269, 1358-1365 | BUG |** Statische Advisory-
  Texte (~30 Metadata-URLs + IMDSv2-Anleitung) als Findings. | Zählt als Findings,
  verschmutzt Triage. | In Log/Notes-Datei verschieben.
- **11-INJECT | injection.py:214-254 | FALSE-NEG |** Generiertes `ssrf_probe.py` testet
  `169.254.169.254`, `file://`, `gopher://`, aber verwirft alle Responses und schreibt
  nichts. OAST-Token wird nie auf URL/Param gemappt. | Cloud-Metadata-SSRF — der
  wertvollste Finding — bleibt unsichtbar. | Per-URL-Status in registriertes Artefakt
  schreiben, per-Param-Token (`ssrf/{md5(url|param)}`) für Callback-Korrelation.
- **11a-DOMXSS | injection.py:584-609 | FALSE-POS + FALSE-NEG |** Nach zweiter
  `page.goto` ist es ein frisches Dokument ohne Instrumentierung; `c` ist `undefined`,
  wird zu `"undefined"` gecoerced → jede Seite mit dem Text "undefined" = DOM-XSS-Sink.
  Außerdem wird nie `location.search`/`referrer`/Cookie als Quelle getestet. | Erfundene
  Findings + verpasste echte Query-Param-DOM-XSS. | Nach zweitem Navigieren Hooks neu
  injizieren bzw. einmal mit Canary-Hash navigieren; Search-Param-Quelle ergänzen.
- **22-NOSQLI | injection_misc.py:186-215 | FALSE-POS |** GET-Baseline ohne Body vs.
  POST-mit-JSON-Body → jede 200-API flaggt `[nosqli-json]`; GET-Param-Pfad genauso.
  | NoSQLi-FPs auf fast jedem API-Endpoint. | Baseline = gleiche Methode mit benignem
  Wert; Operator-Signale fordern, nicht Body-Ungleichheit.
- **27-SSPP | injection_misc.py:680-706 | FALSE-POS |** `[sspp-candidate]` bei jedem
  200/201/302 auf `{"__proto__": {"admin": true}}`-POST; `[sspp-crash-candidate]` bei
  jedem 5xx. | Fast jede JSON-API flaggt. | Gegen benignen POST-Vergleich differenzieren.
- **43-DESERIAL | injection_misc.py:1048-1091 | FALSE-POS |** Jeder 500/502/503/504
  → `[deserial-crash]`; generische Wörter ("error", "class", "stack") → Findings.
  | Deserialisierung (critical) flutet Triage. | Content-Type-Verarbeitung verifizieren,
  Deserial-spezifische Signale/OAST fordern.
- **42-LDAP | injection_misc.py:835 | BUG |** Schreibt `ldap_injection_42.txt`, registriert
  ist nur `ldap_injection.txt` (artifacts.py:375). | **Jeder LDAP-Finding wird still
  verworfen.** | Dateinamen angleichen oder registrieren.
- **118-ERRORLEAK | network.py:818 | FALSE-NEG |** `_ERRORLEAK_PAYLOADS[:sample_endpoints_post]`
  kappt 21 Payloads auf 2-5 (alle SQLi); xml/path/null/long/format-Overflow-Probes
  laufen nie. | Fehlerklassen bleiben ungetestet. | Slice auf Payloads entfernen,
  korrekten Sampling-Knob nutzen.
- **112-RFI | network.py:180-187 | FALSE-POS |** `if hints or status not in (404, 403)`
  + Substring-Echo von "example.com" → RFI bei Reflektion des Params. | RFI (RCE-Klasse)
  bei reiner URL-Reflektion. | Content der gefetchten Datei oder OAST-Fetch fordern.
- **100-SSI | encoding.py:94-100 | FALSE-POS |** `_ssi_indicators` enthält die Payloads
  selbst (`<!--#exec` …). Reflektion ohne Ausführung = `[ssi-injection]`. | SSI-FPs
  bei Verbatim-Reflektion. | Nur Server-Ausführung (`uid=`, `DOCUMENT_ROOT`) melden.
- **101-JSONINJECT | encoding.py:234-264 | FALSE-POS |** `[nosql-operator]`/
  `[mass-assignment]` bei jedem 200/302 auf JSON-POST, ohne Baseline. | Bis zu 9
  Findings pro Endpoint. | Differential: benigner vs. Operator-Body, Response-Feld-
  Reflektion für Mass-Assignment fordern.
- **113-WEBDAV / 63-DOC-ATTACK / 114-SNMP | network.py:215, email_misc.py:393 | BUG |**
  `host.split(":")[0]` auf `https://…`-Zeilen → Requests an `https://https`. |
  Drei Phasen komplett tot. | `urllib.parse.urlparse(...).hostname` nutzen.
- **114-SNMP | network.py:359-371 | FALSE-NEG |** nmap-Branch übergibt
  `snmp-brute.communitiesdb={community}` (einzelner String), NSE erwartet eine Datei →
  scheitert; der funktionierende Socket-Fallback läuft nur ohne nmap. | SNMP-Enumeration
  ist bei installiertem nmap tot. | Communities in Temp-Datei schreiben.
- **60-SMTP-ENUM | email_misc.py:214-222 | FALSE-NEG |** `VRFY`/`EXPN`/`RCPT TO` ohne
  `EHLO`/`MAIL FROM` → RFC-konforme MTAs antworten 503. | User-Enumeration nie
  funktional. | Greeting → EHLO → VRFY/EXPN/MAIL+RCPT-Sequenz pro Verbindung.
- **62-LOG-INJECT | email_misc.py:305-324 | FALSE-NEG + FALSE-POS |** CRLF in
  Header-Werten wird von `http.client` abgelehnt (ValueError, geschluckt) → Header-
  Vektor nie getestet; Param-Vektor flaggt bei jedem 200/201/302. | Header-Vektor tot,
  Param-Vektor rauscht. | Header via Raw-Socket, Param nur bei Log-Format-Bruch melden.
- **77-CACHEKEY | email_misc.py:1094-1149 | FALSE-POS |** `_cache_key_signature` enthält
  `Age`-Header und zwei Einzel-Requests ohne Kontrolle → praktisch jede Injektion ergibt
  andere Signatur. | Cache-Poisoning auf jedem Pfad. | Baseline über N Wiederholungen
  (Median), Noise-Floor verlangen.
- **72-ACCOUNTENUM / 81-IDORFUZZ | email_misc.py:807-813, 1560-1583 | FALSE-NEG |**
  Loggen nur Probe-Zeilen für nichtexistente User bzw. Status/Länge pro Session —
  kein Differenz-Vergleich. | Enumeration/IDOR nie erkannt. | Known-valid vs.
  known-invalid vergleichen bzw. `body_a` vs `body_b` diffen.

### Gruppe 2 — Top 5

1. **26-CMDINJECT (critical) aus Body-Wörtern und ohne Baseline-Timing** (injection_misc.py:543-562).
2. **12-SSTI "evaluated" bei reiner Reflektion von Payload-Substrings** (injection.py:906-920).
3. **43-DESERIAL + 22-NOSQLI + 27-SSPP: Status/Fehler-Wort-Detektion ohne Differential**.
4. **66-SSRF-FULL: unbedingte Findings + Time-based/IMDS ohne OAST-Domain tot** (injection_misc.py:1131).
5. **11-INJECT SSRF-Probe verwirft interne Ergebnisse** (injection.py:214-254).

---

## Gruppe 3 — Auth, Session & Access Control

Dateien: `auth.py`, `auth_bypass.py`, `sso.py`, `account.py`.

- **17-IDOR / 96-METHODOVERRIDE / 98-CASEBYPASS / 97-FORCEDBROWSE / 16a-AUTHZ |
  utils.py:666-691, auth.py:530-539 & 582, auth_bypass.py:556-560, 725-729, 669-691 | BUG |**
  `_async_urlopen` lässt `urllib` `HTTPError` für 4xx/5xx werfen statt den Status zu
  liefern → alle `status in (401,403,405)`-Branches unerreichbar. | Genau die Phasen,
  die 401/403→200-Übergänge finden sollen, melden "keine Bypasses". | Status in
  Shared-Helper zurückgeben (wie `_jwt_acceptance_verdict`, auth.py:870-887).
- **158-SSO / 159-SAMLADV / 160-SSOCONF | sso.py:131-135, 199-201, 249-254 | BUG |**
  Die OAuth/SAML/IdP-Probes hängen nur Strings an — **kein HTTP-Request wird gesendet**.
  Dazu schreiben alle drei in nicht registrierte Artefakte (`sso_oidc.txt`,
  `sso_saml.txt`, `sso_token_confusion.txt`). | SSO-Modul produziert "Tests-to-run"-
  Text als Findings und landet nirgends. | Requests tatsächlich senden + Artefakte
  registrieren.
- **17b-SSRFMETA | auth.py:802-816 | FALSE-POS |** URL-Param durch Metadata-URL ersetzt,
  Response 200 + `len > 20` → `[credential-exfil]` ohne Baseline und ohne Metadata-
  Marker. | Kritische "SSRF zu Cloud-Metadata"-Findings auf normalen Seiten. |
  Baseline-Differential + Marker (`instance-id`, `ami-id`, `computeMetadata`) fordern.
- **16b-MASSASSIGN | auth.py:402-410, 430-432 | FALSE-POS |** Jeder POST/PUT mit
  Privileg-Feld, der 200/201/302 liefert → Finding. Keine Baseline, keine Cookies. |
  `mass_assign.txt` flutet mit unauthentifizierten FPs. | Identischer Baseline-POST,
  Response-Differenz + `_extra_headers_dict()`.
- **24-JWT / 36-JWTADV | auth.py:1223-1227, 1291-1295, 1330-1334, 1393-1397, 1467-1477,
  1649-1653, 1688-1692, 1758-1762, 1828-1831, 1862-1868 | FALSE-POS |** JWK/JKU/KID/alg-none
  -Tests behandeln jedes HTTP 200 als "accepted", ohne No-Token-Baseline. | Ein
  öffentlicher Endpoint erzeugt einen Schwarm kritischer JWT-Findings
  (`jwt_analysis.txt` ist in_triage/in_exploit_chain, artifacts.py:446-454). |
  `_jwt_acceptance_verdict`-Differential für jede Forgery-Probe.
- **36-JWTADV / 24-JWT | auth.py:1572-1575, 1042-1043 | FALSE-POS |** `[jwt-confirm-none]
  alg=none accepted (CRITICAL)` aus bloßem Decodieren eines Tokens im Body — kein Request
  mit dem Token. | Demo/Beispiel-Token in einer Seite = bestätigte Vuln. | Nur nach echtem
  Acceptance-Test als "accepted" labeln, sonst `[jwt-observed]`.
- **24-JWT / 36-JWTADV | auth.py:953-986, 1143-1151, 1661-1665 | FALSE-NEG + FALSE-POS |**
  Der einzige korrekte RS256→HS256-Primitiv `_jwt_fetch_public_key` wird nie aufgerufen;
  Confusion-Tests signieren mit dem Base64-Header des Tokens oder hartkodierten
  Truncated-PEMs. | Echtes Confusion-Attack nie getestet, Fake-Keys liefern Rauschen. |
  `_jwt_fetch_public_key` verdrahten + Baseline-Check.
- **90-CSRF | auth_bypass.py:97-118 | FALSE-POS |** "csrf-bypass" leert das Token im
  Query-String und sendet GET; 200/302 = akzeptiert. | GET beweist nichts über
  State-changing POSTs. | Form-action/-method extrahieren, echten POST mit falschem
  Token senden.
- **91-SESSIONFIX | auth_bypass.py:182-208 | FALSE-POS |** POST mit Fake-Credentials,
  unveränderte Session = `[session-fixation]`. | Failed Login rotiert Session korrekt
  nicht; dazu wird die echte Cookie geladen. | Nur nach erfolgreichem Login prüfen,
  bestehende Cookie aus dem Jar entfernen.
- **97-FORCEDBROWSE | auth_bypass.py:650-652, 675-683 | FALSE-POS |** `robots.txt`,
  `sitemap.xml`, `/.well-known/` in `admin_paths`; 200 ohne "login" = Finding. |
  Jeder Host mit robots.txt → FP. | Public-by-design-Pfade entfernen, authenticated-
  vs-anonymous-Differential fordern.
- **99g-AUTHBYPASSADV | auth_bypass.py:1439-1474, 1482-1489 | FALSE-POS + BUG |**
  Header/Path-Bypass bei jedem 200 ohne Baseline; JWT-Test setzt `payload["alg"]="none"`
  statt im Header → Angriff kann nie triggern. | Erfundene Findings + echter alg-none
  verpasst. | 401/403-vs-200-Baseline + `header["alg"]="none"`.
- **99e-XSSSTORED | auth_bypass.py:1252-1267, 1272-1290 | FALSE-NEG + BUG |** Marker nur
  von der Submission-URL refetched statt von der Rendering-Seite; unauthentifizierte
  POSTs no-open still; Methodik-Notizen landen als Findings in `stored_xss_verified.txt`. |
  Findet weder echte Stored-XSS noch bleibt das Artefakt ehrlich. | Nach Submit
  Listen/Detail-Seiten refetchen + Notizen separieren.
- **99d-LOGTRIGGER | auth_bypass.py:1152-1155, 1175-1179 | FALSE-NEG + BUG |**
  Query-CRLF wird via `urlencode` doppelt-encodiert (`%0d%0a` → `%250d%250a`);
  UA-Payload mit literalem `\r\n` wird von `http.client` abgelehnt (Exception
  geschluckt). | Kein Vektor wird wirklich getestet. | Raw-Socket für Header,
  Single-Encoding + Reflektion prüfen.
- **191-ATO | account.py:104-110, 130-133, 153-156, 184-193 | FALSE-POS |** `token=`/
  `code=`-Substring (oft CSRF-Token) = vorhersagbarer Reset-Token; "keine Re-Auth" aus
  unauthentifiziertem GET ohne zwei Wörter; Default-Creds bei 200 ohne "invalid"/"error".
  `ato_findings.txt` ist critical + in_triage (artifacts.py:942-950). | Schwache
  Evidenz = bestätigte ATO-Findings. | Echte Reset-Tokens testen, authenticated GET/
  State-Change fordern.
- **16a-AUTHZ / 16b-MASSASSIGN | auth.py:166, 402-407 | FALSE-NEG |** Requests ohne
  `_extra_headers_dict()` → keine Cookies → Login-Walled-Apps testen den anonymen
  Kontext. | Authentifizierte Authz-Bugs per Design verpasst. | Cookies an Baseline
  und Probes hängen.
- **24-JWT / 39-OAUTH / 40-PWRESET / 65-SESSION / 191-ATO | auth.py:1009, 1936, 2155,
  account.py:87 | BUG |** Fallback auf rohe `hosts.txt`-Zeilen (`https://example.com
  [200] …`) ohne Hostname-Parsing → Requests an `https://example.com [200] …` scheitern,
  Exception geschluckt. | Fünf Phasen still leer. | Erstes Whitespace-Token + Bracket
  strippen bzw. `_load_live_hosts`.

### Gruppe 3 — Top 5

1. **`HTTPError` statt Status** (utils.py:666-691) — 17-IDOR/96/98/97/16a sind Dead Code
   für genau die 401/403→200-Übergänge, die sie finden sollen.
2. **SSO-Modul sendet nichts und shippt nichts** (sso.py:131-135 + unregistrierte Artefakte).
3. **17b-SSRFMETA `[credential-exfil]` bei jedem 200 >20 Bytes** (auth.py:802-803).
4. **Baseline-lose JWT-Forgery-Tests flaggen jeden 200 als "accepted"/critical**,
   während `_jwt_fetch_public_key` nie aufgerufen wird.
5. **16b-MASSASSIGN meldet jeden 200-POST** + 16a/16b unauthentifiziert.

---

## Gruppe 4 — Client-Side & Web Platform

Dateien: `client_side.py`, `client_side_v2.py`, `third_party.py`, `modern_web.py`,
`cookie_security.py`, `pwa_security.py`, `webrtc.py`.

- **80-STOREXSS | client_side.py:1999-2040 | FALSE-POS |** ~15 statische Methodik-Zeilen
  (OOB-Notizen, DOM-Clobbering, mXSS, Scriptless-XSS) werden in `stored_xss.txt`
  geschrieben — severity_hint=high, in_exploit_chain/in_triage (artifacts.py:426-434).
  | Ein Scan mit **null** Stored-XSS emittiert ~15 High-Findings. | Boilerplate raus,
  in Log/Notes-Datei.
- **80-STOREXSS | client_side.py:1948-1969 | FALSE-NEG |** Nach Submit wird der Canary
  nur auf anderen URLs (`form_urls[:5]`) geprüft; die POST/POST-Redirect-Response — der
  wahrscheinlichste Reflektionspunkt — wird nie inspiziert. SPA-Forms lassen den Canary
  im `<input>` stehen → `innerHTML.includes(_CANARY)` feuert auf der stale Form-Seite.
  | Primäre Stored-XSS-Location verpasst + FP-Kandidaten. | Navigations-Result nach
  Submit inspizieren, Canary nach jedem Form resetten.
- **30-LFI | client_side.py:638 | FALSE-NEG |** `lfi_payloads[:10]` sendet nur 10 von
  ~100 Payloads; `php://filter`, `data://`, `expect://`, double-encoded, `/WEB-INF/
  web.xml`, `/proc/self/cmdline` — alle >Index 10 — laufen nie. | Die wertvollsten
  Bypasses sind tot. | Slice entfernen.
- **30-LFI | client_side.py:577-616, 658 | FALSE-POS |** `lfi_indicators` enthält
  `"localhost"`, `"127.0.0.1"`, `"uid="`, `"cgroup"`, `"::1"`. Jede Seite mit "localhost"
  → `[lfi-confirmed]`. Log-Poisoning: `[log-poison-injected]` bei jedem fehlerfreien
  Request, `[log-poison-candidate]` bei jedem 200 >500 Bytes. | Bestätigte LFI/RCE auf
  harmlosen Seiten. | `root:x:0:0:`-Kombination + injizierte UA im Log-Body fordern.
- **35-CORSADV | client_side.py:1173 | FALSE-POS |** `origin in acao or "*" in acao` →
  `[cors-misconfig]` bei `ACAO: *` ohne `Access-Control-Allow-Credentials: true`
  (nicht ausbeutbar) und bei Substring-Match (`evil.com` vs. `evil.com:8080`). |
  FPs auf jedem CDN-`*`. | Exakter Origin-Gleichheit + `*` nur mit `ACAC: true`.
- **35-CORSADV | client_side.py:1162-1182 | FALSE-NEG |** Nur `OPTIONS` gesendet. Das
  klassische Muster — Origin-Reflektion in ACAO nur auf GET — wird verpasst. | Häufigster
  ausbeutbarer CORS-Bug nie gefunden. | Auch GET mit Origin testen.
- **28-CACHED | client_side.py:87-93 | FALSE-NEG |** `base_cached` gate die Probes auf
  `x-cache`/`age:`/`cf-cache` im Basis-Response. Bei Cache-MISS (Normalfall) kein Header
  → Phase bricht ab und testet **null** Poison-Probes. | Meiste Targets nie getestet. |
  Caching über zwei identische Requests erkennen oder Probes immer laufen lassen.
- **28-CACHED | client_side.py:157-159, 109-114 | FALSE-NEG + FALSE-POS |** `wcd_url =
  url.rstrip("/") + ext` baut kaputte URLs (`https://host/path?x=y.css`, `https://host.css`);
  Poison-Detektion scannt nur Header, nicht den HTML-Body. | WCD + Host-Header-Body-
  Poisoning effektiv tot. | Extension ans `parsed.path` vor dem Query hängen, Body prüfen.
- **28-CACHED | client_side.py:185-227, 322-357 | FALSE-POS |** `[cache-key-confusion]`
  bei jeder Body-Differenz; `[cache-cookie-unkeyed]` wenn Cookie keine Änderung bringt
  (normal für Cookie-lose Seiten); `[cache-vary-bypass]` bei identischen Bodies. Kein
  `Vary`/`Cache-Control`-Header-Analyse. | Hoher FP-Load, echte Key-Design-Poisoning
  verpasst. | Poison-Signal in gepoisonter UND gecachter Response fordern.
- **31-OPENREDIR | client_side.py:781-804, 837-844 | FALSE-NEG |** Nur ~21 feste
  Param-Namen (`url`, `next`, `redirect`, …); `continue`, `callback`, `redirect_to`,
  `returnUrl`, `ret`, `destination` fehlen. Payloads nur `https://evil.com` und
  `//evil.com` — keine Backslash/encodierten Varianten. | Mehrheit der Redirect-Params
  und Encodings nie getestet. | Param-Liste erweitern + generischer Reflection-Pass.
- **31-OPENREDIR | client_side.py:858-864 | FALSE-POS |** Substring-Test `"evil.com" in
  location` — ein same-origin Error-Redirect mit `?url=https://evil.com` flaggt, obwohl
  der Browser auf dem eigenen Origin bleibt. | Nicht-ausbeutbare Redirects als Findings. |
  Location-Host parsen und gegen Payload-Host vergleichen.
- **32-CLICKJACK | client_side.py:917-919 | FALSE-NEG |** Jede Präsenz von
  `frame-ancestors`/`XFO` = geschützt. `frame-ancestors *`, `XFO: ALLOW-FROM <url>`
  (von Chrome/Firefox ignoriert) gelten als sicher. | Clickjackbare Seiten als sicher
  gemeldet. | Directive-Werte parsen: nur `'none'`/`'self'`/same-origin bzw. `DENY`/
  `SAMEORIGIN`.
- **32-CLICKJACK | client_side.py:923-926 | FALSE-POS |** `[clickjacking-csp-only]` als
  Finding (medium), obwohl gültiges `frame-ancestors` voller Schutz ist. | FPs auf gut
  geschützten Seiten. | Als Informational loggen.
- **110-THIRDPARTYJS | third_party.py:284-308 | FALSE-NEG (BUG) |** Unconditional
  `break` bei Zeile 308 nach dem **ersten** `<script>`-Tag. Ist der erste same-origin,
  wird nie ein Third-Party-Script (inkl. SRI-Status) geprüft. | Kernzweck der Phase
  kollabiert auf ein Tag pro Seite. | `break` entfernen.
- **174-WASMSEC / 196-PUSHAPI / 193-WEBRTC | modern_web.py:169, pwa_security.py:73,
  webrtc.py:80 | BUG |** Lesen `js_urls.txt`, Pipeline schreibt/liest überall
  `urls_js.txt` (artifacts.py:146; jsintel.py:75). | 174-WASMSEC fällt auf hartkodiertes
  `https://example.com/app.wasm` zurück, 196/193 scannen nichts. | `urls_js.txt` nutzen,
  Fallback entfernen.
- **73-CSPBYPASS | client_side.py:1802-1808, 1856-1858, 1860-1864 | FALSE-POS |**
  Substring-Match über den ganzen Header: `"http://"` irgendwo (z.B. `connect-src`) =
  "script-src erlaubt http://"; `"*"` irgendwo = "ganze CSP bypassbar"; `'unsafe-inline'`
  trotz Nonce/Hash; `youtube.com` in jedem Directive = JSONP-Warnung. | Jede
  Nonce-CSP/wildcard-CSP als degradiert gemeldet. | Per-Directive-Source-Listen parsen.
- **176-JWT2SELF | modern_web.py:329-336 | FALSE-NEG (BUG) |** `{"Authorization":
  f"Bearer {forged}", **jwt_extra_headers}` — wenn `auth_bearer` gesetzt, überschreibt
  `jwt_extra_headers` (utils.py:498-499) den gefälschten Token. Signatur ist Fake. |
  Phase funktioniert nur ohne Signatur-Validierung. | `jwt_extra_headers` zuerst anwenden,
  Forgery gewinnt.
- **194-COOKIETOSS | cookie_security.py:55-76 | FALSE-POS |** `[cookie-no-prefix]` für
  jedes Cookie ohne `__Host-`/`__Secure-` (optionales Hardening, keine Vuln);
  `parent_domain` = letzte zwei Labels → bei `example.co.uk` falsch. | Mass-FPs +
  falsche Domain-Analyse. | PSL-aware eTLD+1.
- **173-SERVICEWORKER | modern_web.py:83-97, 122 | FALSE-POS + BUG |** `[sw-hardcoded-
  secret]` bei jedem "token"/"auth"/"secret" im SW-File; `"addEventListener.*message"`
  ist Literal-String-Suche → Origin-Branch toter Code. | FP-Secrets + toter Check. |
  Assignments matchen, `re.search` nutzen.
- **109-HSTSPRELOAD | third_party.py:223-226 | FALSE-POS + FALSE-NEG |** `[hsts-insufficient]`
  bei `max-age < 31536000` **oder** fehlendem `includeSubDomains` — max-age=31536000 ohne
  includeSubDomains ist valide/sicher, nur nicht preload-fähig. Preload-fähige, aber nicht
  eingereichte Hosts bekommen nichts (innerer `except: pass`). | FP-"insufficient" +
  verpasste Preload-Gelegenheit. | Nur fehlendes/trivial kleines HSTS melden.

### Gruppe 4 — Top 5

1. **80-STOREXSS: ~15 statische Methodik-Zeilen als High-Findings in Triage/Exploit-
   Chain** (client_side.py:1999-2040), echte Probe prüft die Post-Submit-Seite nie.
2. **30-LFI: `[:10]`-Slice kappt php-Wrapper/data/proc-Payloads + schwache Indicators
   (`localhost`, `uid=`) erfinden `[lfi-confirmed]`** (client_side.py:638, 577-616).
3. **35-CORSADV: `*`-ohne-Credentials + Substring-Match FPs, OPTIONS-only verpasst
   GET-Reflektion** (client_side.py:1173, 1162-1182).
4. **28-CACHED: Cache-Erkennungs-Früh-Return, kaputte WCD-URLs, kein Body-Check, keine
   Vary/Cache-Control-Analyse** (client_side.py:87-93, 159, 109-114).
5. **31-OPENREDIR: feste ~21-Param-Whitelist + 2 Payloads + Substring-`evil.com`-FP**
   (client_side.py:781-804, 858-864).

Zusätzlich: Filename-Bug `js_urls.txt` vs `urls_js.txt` (modern_web.py:169,
pwa_security.py:73, webrtc.py:80) schaltet die JS-Analyse-Pfade von 174/193/196 ab.

---

## Gruppe 5 — Infra, Cloud, CMS & Secrets

Dateien: `origin_cloud.py`, `cloud.py`, `web_infra.py`, `cms.py`, `cms_deep.py`,
`secrets_git.py`.

- **57-DEFAULT-CREDS | web_infra.py:994-1028 | BUG |** `host.split(":")[0]` auf
  httpx-URLs → `"https"` → `https://https/login`. Phase testet nie ein Credential,
  schreibt aber "No default credentials accepted". | Hochwertige Phase still tot. |
  `_load_live_hosts(outdir)` nutzen.
- **134-LBDETECT | cloud.py:454-488 | FALSE-POS |** `"server"` in den Signatur-Listen
  von Cloudflare/F5/HAProxy/Akamai; `headers` ist lowercased und fast jede Response hat
  einen `Server`-Header → **jeder Host ist "Cloudflare"**. | `lb_bypass`-Artefakt flutet. |
  `"server"` entfernen bzw. nur Wert-Enthält-Provider matchen.
- **134-LBDETECT | cloud.py:465-514 | BUG |** `origin_ips` aus `origin.txt`, dessen erste
  Zeile fast immer ein Label ist (`favicon_hash=…`, `crt.sh: …`) → `origin_ip` =
  `favicon_hash=1234…`, Phase emittiert `[lb-bypass] origin=favicon_hash=… diff=UNREACHABLE`.
  `diff=YES` (Zeile 511) heißt nur "Response-Text unterscheidet sich" (bei jeder IP normal).
  | FPs für jeden erkannten LB. | Nur `origin_candidate=`/`non_cloudflare_ip=` parsen,
  Origin per Title/Fingerprint bestätigen.
- **50-BUCKET-PERMS | origin_cloud.py:632-663 | BUG |** Input `cloud_buckets.txt`-Zeilen
  mit Provider-Präfix + Status (`[AWS] http://base.s3.amazonaws.com (HTTP 200)`).
  `base = entry.split(".s3")[0]` ergibt `[AWS] http://base` → invalide URL → alle Probes
  geschluckt. | Phase kaputt für eigenen Upstream. | Tag/Suffix strippen.
- **50-BUCKET-PERMS | origin_cloud.py:596-625 | FALSE-POS |** Jeder generische 200-Body
  ohne Listing-Marker → `[bucket-public-access]` (S3-Static-Site reicht); PUT mit 405 →
  `[bucket-write-allowed] … PUT not allowed (expected)` — 405 heißt *nicht erlaubt*,
  wird aber als Write-Finding getaggt. | Falsche Read-/Write-Findings. | 200 + Listing-
  Marker bzw. nur 200/201/204 für Write.
- **46-BUCKET | origin_cloud.py:502, 545-548 | BUG + FALSE-POS |** Schreibt
  `bucket_enum.txt` (nicht in `ARTIFACTS`) → Findings still verworfen. `code < 400`
  (545) meldet 3xx/304/403 als `[open]`/`[restricted]` per HEAD ohne GET-Bestätigung und
  ohne Ownership-Check. | Findings-Verlust + fremde Buckets als eigene gemeldet. |
  Registrierten Namen nutzen + GET + S3-XML-Signatur fordern.
- **14-ORIGIN | origin_cloud.py:219-246 | FALSE-NEG |** SPF/DMARC/DKIM werden geholt und
  geloggt, aber `ip4:`/`ip6:`-Mechanismen nie als Origin-Candidates geparst; keine
  Header-basierten Tests (X-Forwarded-Host/Via), keine Mixed-Content-Probes. |
  Klassischer Origin-IP-Leak verpasst. | `ip4:`/`ip6:` extrahieren + Header-Echo-Tests.
- **14-ORIGIN | origin_cloud.py:287-293 | FALSE-POS |** Nur "cloudflare"/"13335" als CDN
  klassifiziert; jeder andere CDN-Edge (Akamai, Fastly, Sucuri, Imperva) → `non_cloudflare_ip=`
  (Origin-Leak). | Hosts hinter CDN als Origin-Leak gemeldet. | CDN/ASN-Blocklist pflegen.
- **19-GIT | secrets_git.py:356-373 | FALSE-POS |** `.git`-Exposure aus HEAD-only 200 auf
  `/.git/config` oder aus HTTPError 301/302 ohne GET-Body-Verifikation. | SPA-Catch-all
  oder http→https-Redirect → `[.git-exposed]`. | GET + `[core]`/`repositoryformatversion`/
  `ref:`-Body fordern.
- **19-GIT | secrets_git.py:305-318, 440-482 | FALSE-NEG |** Recovery nur über
  `refs/heads/{master,main,dev,develop}`; `packed-refs`, `info/refs`, `objects/info/packs`,
  Tags, `refs/remotes` und Backup-Artefakte (`.git.zip`, `.git.bak`, `*.git~`) nie
  getestet. | Exposed Repos mit packed refs → keine SHA-Recovery. | `packed-refs`/
  `info/refs` proben + SHA-Liste parsen.
- **15-SECRETS | secrets_git.py:120-147 | BUG |** "API key live validation"-Block ist
  toter Code: die frühere Regex-Loop (97-102) hat jeden Match schon in `seen_secrets`
  → `if val in seen_secrets: continue` (125) skippt immer. Pattern-Set (jsintel.py:28-57)
  verpasst `sk-`(OpenAI), Discord/Telegram-Bot, Twilio `AC…`, `BEGIN PRIVATE KEY`. |
  Live-Check nie ausgeführt, gängige Secret-Formate unreported. | Guard entfernen bzw.
  Live-Check-Werte separat tracken, Patterns erweitern.
- **56-EXPOSED-DB | web_infra.py:890-899 | FALSE-NEG |** Alle DB-Probes hängen an
  `ports.txt` (naabu/nmap `-top-ports 1000`), das 5984/50070/2375/6443/10250 nicht
  abdeckt. `[exposed-db-port]` für jeden offenen TCP-Port ohne Auth/Banner-Bestätigung. |
  CouchDB/HDFS/Docker/k8s nie geprobt + FP-Offenheit. | `_EXPOSED_DB_PORTS` unbedingt
  proben + Banner-Signatur.
- **51-HPP | web_infra.py:499-531 | FALSE-POS |** Test-QS baut `{param_name: [...]}` und
  lässt **alle anderen** Original-Params weg, `ref_qs` behält sie → jeder Multi-Param-URL
  = HPP-FP. | Mass-FPs. | `qs` kopieren und nur die Wertliste des Ziel-Params ersetzen.
- **129-K8S | cloud.py:160 | BUG |** Schreibt `k8s_exposure.txt` (nicht in `ARTIFACTS`)
  → alle K8s-Findings (kubelet/etcd, kritisch) verschwinden. | Registrieren.
- **136-RATELIMITBYPASS | cloud.py:918-951 | FALSE-POS + FALSE-NEG |** Technique 8 läuft
  auf jeder URL und emittiert immer eine Zeile — inkl. `no rate limiting observed` für
  jede nicht-429-URL; da nie selbst limitiert wird, sind die Bypass-Techniken No-Ops. |
  Rauschen + keine echten Tests. | Nur bei echtem Limit aktivieren + Burst zuerst.
- **123-NODEJS | cms.py:277-288 | FALSE-POS |** SSTI-Check `if "49" in body_str or "7*7"
  in body_str` — die Zahl 49 irgendwo in der Seite reicht. | `[nodejs-ssti]` auf jeder
  Node-Seite mit Preisen/IDs. | Kontext der injizierten Param-Echo prüfen.
- **124-LARAVEL | cms.py:323-366 | FALSE-POS |** Jeder 200 auf `/.env` (ohne
  `KEY=VALUE`-Verifikation), `/storage/logs/laravel.log`, `/telescope`, `/horizon`
  → Laravel-Exposure. SPA-Catch-all = jeder Host. | Kein Laravel-Fingerprint vor den
  Probes. | Fingerprint-Gate + env-Syntax/Log-Content fordern.
- **47-CDN | web_infra.py:47, 71, 83 | BUG |** Schreibt `cdn_detection.txt` (nicht in
  `ARTIFACTS`) → verworfen. Incapsula-Signatur `"X-Iinfo"` ist mixed-case, Match auf
  lowercased Header-Blob → nie matchbar. | Findings unsichtbar + Incapsula nie erkannt. |
  Registrieren + case-insensitive Signaturen.

### Gruppe 5 — Top 5

1. **57-DEFAULT-CREDS tot im Standard-Pipeline** (web_infra.py:1021).
2. **50-BUCKET-PERMS kann eigenen Upstream nicht parsen** (origin_cloud.py:637) + mislabelt
   405 als write-allowed (origin_cloud.py:624).
3. **134-LBDETECT: `"server"` in Signaturen → jeder Host ist Cloudflare** (cloud.py:457-460),
   Origin-IP-Lookup liest Label-Zeilen (465-498).
4. **46-BUCKET + 129-K8S + 47-CDN + 48-CONTENT schreiben unregistrierte Artefakt-Namen**.
5. **19-GIT/15-SECRETS: FPs + toter Code auf den wertvollsten Discovery-Zielen**.

---

## Gruppe 6 — Advanced & Spezialisiert

Dateien: `smuggling.py`, `bizlogic.py`, `llm_ai.py`, `electron.py`, `supplychain.py`,
`modern_proto.py`, `protocol.py`, `advanced_inject.py`.

- **149-LLMSEC / 150-LLMLEAK / 151-RAGPOISON / 152-LLMADV | llm_ai.py:185-198, 252-253,
  294-309, 345-357 | FALSE-POS |** Detektions-Keywords sind Refusal-Sprache: 149 flaggt
  `"i cannot"`, `"i'm sorry"`, `"as an ai"`, `"apologize"` — exakt was ein sicheres Modell
  beim Refusen sagt; 151 matcht `"secret key"`/`"admin password"`, die verbatim im Probe-
  Text stehen. | Jedes korrekt arbeitende Modell wird als kompromittiert gemeldet. |
  Auf Erfolgs-**Verhalten** matchen (Echo des System-Prompts mit Markern), Refusals als
  Negativ-Evidenz.
- **153-BIZLOGIC / 154-PAYMENT / 155-COUPON / 156-MTENANT / 157-2FA | bizlogic.py:236-239,
  272-279, 331-339, 398-413, 488-502, 574-583 | FALSE-POS |** Jeder 2xx auf spekulativen
  Payload (`{"step":"payment","skip":true}`, `{"amount":-1}`, `{"otp":"000000"}`) =
  Bypass; 5 unauthentifizierte 200-POSTs = "payment race". | Benigne 200-Form-Reloads als
  Financial/Auth-Bypass. | Per-Endpoint-Erfolgskriterien + Kontroll-Request.
- **175-OAUTHDEVICE | advanced_inject.py:126-141 | BUG |** `verification_uri`-Check
  invertiert: `if "evil" not in ver_uri.lower()` flaggt genau die **legitime** URI.
  Dup-Regex bei 130-133 toter Code. `[no-csrf-poll]` (164-171) fordert CSRF im RFC-8628-
  Polling (existiert nicht). | Jeder funktionierende Device-Flow flaggt. | Bedingung
  umkehren, Dup löschen, CSRF-Check entfernen.
- **177-SELENIUMXSS | advanced_inject.py:278, 261-263 | BUG |** Playwright-Input wird aus
  `param_urls[:10]` geschrieben — die **unmodifizierten** Original-URLs → Browser navigiert
  zu bereits gecrawlten Seiten, kein injizierter Handler beobachtbar. Nicht-Browser-Check
  prüft nur, ob "onerror" irgendwo im Body steht (Reflektion, kein DOM-XSS). | Headline-
  Feature validiert nichts, static Check flutet `dom_xss_dynamic.txt` (high). |
  Payload-injizierte URLs (test_url bei 250-251) an Playwright geben + Sink-Kontext fordern.
- **179-WAFBYPASS | advanced_inject.py:474, 484-487, 507, 532-534 | BUG + FALSE-POS |**
  `prev["21-WAF"]` ist ein Pfad-String, keine Liste → `for wf in waf_findings[:5]`
  iteriert die ersten 5 Zeichen des Pfads. Nur `param_urls[0]` getestet, kein Control;
  Chunked-Test setzt `Transfer-Encoding: chunked` als Header auf GET (urllib sendet keine
  Chunked-Body). | WAF-Kontext Müll, Bypass nie bestätigt/verneint. | `read_lines()`
  auf Pfad, alle Param-URLs, Control-Request.
- **184-SSRFPARTIAL | advanced_inject.py:1099, 1100, 1180 | BUG |** `prev["66-SSRF-FULL"]`
  ist Pfad-String; `if not ssrf_endpoints` passiert nie, `for u in ssrf_endpoints[:10]`
  iteriert Pfad-Zeichen → `_probe_smuggle` bekommt Zeichen. Da 66 als Dependency
  deklariert ist, ist der Key immer da → Phase nullifiziert. | `read_lines()` auf Pfad.
- **23-RACE | smuggling.py:150-164, 311-326, 153, 313 | FALSE-NEG |** Bursts werden vom
  Throttle serialisiert: `await _throttle_rate()` in der Concurrent-Coroutine, Default
  rate_limit=10 mit TokenBucket burst=1 → 5 "simultane" Requests 100 ms versetzt. TOCTOU-
  "Write" ist ein GET mit Query-Mutation (kein State-Change); Baseline+Burst-Vergleich
  flaggt benignen GET-Variance. | Races prinzipiell nicht nachweisbar. | Throttle im Burst
  umgehen, state-changing authenticated Request, N Wiederholungen.
- **38-SMUGGLE | smuggling.py:464, 459-462, 492 | FALSE-NEG |** `port = 443 if "https" in
  str(host) else 80` — bare `example.com` wird als HTTP/1.1 auf Port 80 gesendet;
  HTTPS-only-Targets antworten mit TLS-Bytes → Marker nie gefunden. Nur CL.TE/TE.CL
  (354-383); TE.TE, CL.CL, CL.0 fehlen; Detektion via Literal-Substring. | Mehrheit der
  realen HTTPS-Targets + gängigste Techniken verpasst. | 443+TLS, weitere Familien,
  Response-Count-Heuristik.
- **38-SMUGGLE / 38b-H2SMUGGLE / 23-RACE | smuggling.py:496-499, 515-516;
  artifacts.py:74-78, 754-762 | FALSE-POS |** `[smuggling-tested] … no desync (expected)`
  und `[smuggling] No request smuggling candidates detected (expected)` landen in
  `smuggling.txt` (in_triage + in_exploit_chain); `guess_severity` mappt "smuggling" auf
  **high**; `severity.py` filtert nur Zeilen, die mit "No" beginnen — `[smuggling-tested]`
  nicht. | Bereinigte Hosts werden als High-"Vulns" gemeldet. | Non-Findings in separates
  Log, Severity-Filter auf "no … detected/expected/tested" erweitern.
- **41-WEBSOCKET | smuggling.py:714-723, 756-765, 771-784 | FALSE-POS |** `[ws-auth-bypass]`
  feuert, wenn der Server irgendeinen Frame beantwortet (`{"type":"ping"}`) — kein Session/
  keine privilegierte Operation. `[ws-long-frame]` bei normalem Large-Frame-Echo.
  `[ws-subprotocol]` ohne Verifikation des 101-Echos. | Jeder responsive Socket = mehrere
  Findings. | Privilegierte Aktion ohne Credentials fordern, 101-Header prüfen.
- **38b-H2SMUGGLE | smuggling.py:896-929 | FALSE-NEG |** Rapid-Reset-Metrik misst
  `rapid_duration` = Zeit zum Bauen+Senden von 500 In-Memory-Frames (Client-Operation),
  verglichen mit `baseline_latency` (Server-RTT) → `rapid_duration > baseline*3` feuert
  fast nie → immer `[h2-rapid-reset-safe]`, CVE-2023-44487 nie erkannt. HPACK-Bomb und
  Malformed-Preface melden normales GOAWAY als Finding. | Wichtigster H2-Angriff effektiv
  ungetestet. | Server-Antwortzeit nach Storm messen, GOAWAY-Findings streichen.
- **167-H2RAPID / 168-H3QUIC / 169-WEBTRANSPORT | modern_proto.py:59-82, 118-127, 174 |
  FALSE-NEG + FALSE-POS |** 167 sendet nie einen Rapid-Reset-Storm (nur Settings-Frame +
  `[manual]`-Notiz). 168 flaggt *jede* UDP-Antwort auf ein absichtlich kaputtes Packet
  (Version `0xffffffff`) als "QUIC/H3 supported" — Version-Negotiation heißt, dass die
  Version **nicht** unterstützt wird. 169 grept nur URL-Korpus, fragt nie
  `/.well-known/webtransport`. | H2/H3/WT als "getestet" gemeldet, H3-Support falsch
  erkannt. | Echten Angriff implementieren, gültige Version proben, echte Probes.
- **175a-WS-DEEP | smuggling.py:1571-1576, 1622-1637 | FALSE-POS |** Defensives Verhalten
  als DoS-Vuln: Ping-Flood überleben = `[ws-ping-flood-tolerant]`, Disconnect =
  `[ws-ping-flood-closed] (DoS risk)`; Large-Frame-Antwort = `[ws-large-frame-accepted]`,
  sauberes Schließen = `[ws-large-frame-closed] … caused disconnect`. | Server, die sich
  korrekt schützen, erzeugen Findings. | Nur Sustained-Failure **vor** dem Flood-Threshold.
- **180-SWAGGERABUSE | advanced_inject.py:668-675, 707-714 | FALSE-POS |** `[auth-bypass]`
  bei jedem GET 200 ohne die Wörter "unauthorized"/"forbidden" — jede öffentliche API;
  `[idor-candidate]` bei jedem 200 nach Ziffer→`1`-Ersetzung ohne Baseline.
  (artifacts.py:262-270: in_triage, severity_hint=high). | Eine OpenAPI-Spec = dutzende
  High-FPs. | Authentifizierte Baseline fordern + Response-Differenz.
- **181-MFABYPASS | advanced_inject.py:839-846, 847-873, 878-908 | FALSE-POS |** Enroll-
  Race mit 5 distincten Device-IDs; >1 HTTP 200 ist das **korrekte** Verhalten eines
  funktionierenden Endpoints. OTP-Timing gegen feste 0.5s ohne Baseline; Backup-Code-
  Check: 10 von 1M Codes, "kein Rate-Limit" aus fehlendem 429. | Jeder funktionierende
  MFA-Endpoint flaggt. | Gleiche Device-ID parallel, Timing-Baseline known-good vs
  known-bad, sinnvolle Scale.
- **182-CAPTCHABYPASS | advanced_inject.py:979-1002, 1022, 1039, 1061 | FALSE-POS |**
  `test_token` ist nie gültig, "reuse" flaggt bei 200 ohne "invalid"/"error" (Form-Reload);
  `[captcha-missing]`/`[captcha-method-bypass]`/`[captcha-content-type-bypass]` bei 200
  ohne Substring "captcha" — ein GET auf `/login` reicht. | Jeder Login flaggt als
  Captcha-bypassed. | Erst echten Token erfassen, gültigen wiederverwenden, Challenge-
  Abwesenheit nach vorheriger Anwesenheit fordern.
- **190-BROTLIORACLE | advanced_inject.py:1241-1297 | FALSE-POS |** Kein Check auf
  `Content-Encoding: br` oder Reflektion des Parameters; ein Sample pro Variante; jede
  Größen-Differenz = `[compression-oracle]`/`[char-oracle]`. | Network-Jitter/Rotating-
  Tokens = bestätigter BREACH-Oracle (artifacts.py:934-941). | Encoding+Reflektion
  verifizieren, N Samples, konsistente Delta vs. Kontrolle.
- **166-TYPOSQUAT | supplychain.py:231, 234, 236, 240, 278-283 | BUG |** Die Squat-Tabelle
  enthält Selbst-Mappings (`("flask","flask")`, `("numpy","numpy")`, …) plus falsches
  `("uuidv4","uuid")`; Exact-Match-Check flaggt die legitimen Pakete selbst. Mutationen
  komplett statisch. | Legitime Abhängigkeiten als Supply-Chain-Attack gemeldet, echte
  Squats verpasst. | Selbst-Mappings raus, Mutationen generieren.
- **165-DEPCONF | supplychain.py:154-164, 189-193 | FALSE-NEG |** Scoped-Packages werden
  ausgeschlossen (`not startswith("@")`) — genau die Dependency-Confusion-Klasse — und
  Python-Pakete werden gegen den **npm**-Registry geprüft. | Scoped+Pypi-Confusion
  unerkannt, Python-Verdikte sinnlos. | Scope strippen, PyPI vs npm routen.

### Gruppe 6 — Top 5

1. **Unregistrierte Artefakt-Namen verwerfen 14 von 25 Phasen komplett**
   (`bizlogic_*.txt`, `llm_*.txt`, `electron_*.txt`, `supplychain_*.txt`,
   `modern_*.txt`, `websocket_deep.txt` — alle nicht in `ARTIFACTS`).
2. **`prev`-Pfad-Missbrauch nullifiziert 184-SSRFPARTIAL (advanced_inject.py:1099) und
   179-WAFBYPASS (474)** — beide iterieren Zeichen des Pfads statt Endpoints.
3. **Race-Phasen können keine Races erkennen** — 23-RACE durch Throttle serialisiert,
   181-MFABYPASS mit distincten Device-IDs; FPs auf normalen Servern.
4. **High-Severity-FPs dominieren das Risikomodell** — `[smuggling-tested]/…expected`-
   Zeilen in Exploit-Chain-Artefakt (guess_severity="high"), LLM-Refusal-Inversion,
   SWAGGERABUSE/CAPTCHA/MFA/BIZLOGIC flaggen jeden 2xx.
5. **HTTPS/Modern-Protocol-Lücken** — 38-SMUGGLE plaintext Port 80 + nur 2 CL/TE-
   Familien; 38b Rapid-Reset misst Client-Zeit (immer "safe"); 167/168/169 sind
   Checklisten.

---

## Priorisierte Fix-Liste

1. **Artefakt-Registry:** alle nicht registrierten Ausgabedateien registrieren oder
   umbenennen (verantwortlich für den größten Findings-Verlust).
2. **Host-Normalisierung:** `host.split(":")[0]` durch `_load_live_hosts()` bzw.
   `urlparse(...).hostname` ersetzen; `00-SCOPE`-`hosts.txt`-Zerstörung fixen.
3. **`prev`-Handling:** in 179-WAFBYPASS/184-SSRFPARTIAL Pfad per `read_lines()` auflösen.
4. **`HTTPError`-Handling** in `_async_urlopen`/`_async_urlopen_no_redirect`, damit
   401/403/405-Branches in IDOR/METHODOVERRIDE/CASEBYPASS/FORCEDBROWSE erreichbar sind.
5. **Baseline-Differential-Checks** in JWT/MASSASSIGN/NOSQLI/SSPP/DESERIAL/CAPTCHA/
   MFA/BIZLOGIC/SWAGGERABUSE (statt Status-Code-only).
6. **Race-Phasen** vom Throttle befreien + echte State-Change-Requests.
7. **Interactsh-Callback-Korrelation** für SSRF/SSTI-OOB-Findings.
8. **`hosts.txt`-Format-Fehler** in WEBDAV/SNMP/DOC-ATTACK/DEFAULT-CREDS/24-JWT/39-OAUTH/
   40-PWRESET/65-SESSION beheben.
9. **Payload-Caps** (`lfi_payloads[:10]`, `_ERRORLEAK_PAYLOADS[:n]`, `head -500`) entfernen
   bzw. konfigurierbar machen.
10. **`_jwt_fetch_public_key`** in die RS256→HS256-Confusion-Tests verdrahten.