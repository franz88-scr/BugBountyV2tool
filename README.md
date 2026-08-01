# VulnForge v3.1.0

A stdlib-first Python orchestrator for chained bug-bounty reconnaissance and vulnerability discovery. Given a target domain, VulnForge runs **213 phases** across **45 DAG stages**, coordinating **40+ optional external tools** into a single resumable pipeline with adaptive resource management. Most phases are shallow heuristic probes; the pipeline's value is the dependency ordering, state persistence, and resource safety, not the depth of any single check.

```bash
vulnforge -d example.com                      # full scan
vulnforge -i                                  # interactive wizard
vulnforge -d example.com --fast               # quick recon (5 phases)
vulnforge -d example.com --safe               # conservative VM/container mode
vulnforge -d example.com,test.org             # multi-domain scan
vulnforge --batch targets.txt                 # batch scan from file
vulnforge -d example.com --profile quick      # skip low-signal phases
vulnforge -d example.com --resume             # resume from saved state
vulnforge -d example.com --attack-graph       # attack surface graph
vulnforge -d example.com --format sarif       # CI/CD-friendly output
```

The `reconchain` command is retained as a backward-compatible alias for `vulnforge`.

**Naming.** The product is named **VulnForge** (`vulnforge` package + CLI). The `reconchain` CLI alias and this repository's container name (`BugBountyV2tool`) are historical names kept for backward compatibility; new work should use `vulnforge`.

## Installation

Requires Python 3.9+.

```bash
python3 -m pip install -e ".[dev]"     # install package (+ dev tooling)
./install.sh                            # install the external security tools
```

Optional extras:

| Extra | Provides |
|-------|----------|
| `.[progress]` | `tqdm` progress bars |
| `.[ai]` | OpenAI and Anthropic SDKs for AI triage |
| `.[bot]` | `aiohttp` for the Discord/Slack companion bot |
| `.[all]` | everything above |

Or with Docker:

```bash
docker build -t vulnforge .
docker compose run --rm vulnforge -d example.com
```

The Dockerfile builds the Go/Python/Ruby toolchain and ships a hardened, read-only image (non-root user, dropped capabilities, SHA256-verified binaries, 8 GB memory cap).

## Features

- **213 phases across 45 DAG stages** — explicit dependency ordering, parallel stage execution, state persisted to `state.json` after every phase; `--resume` picks up where a scan stopped
- **40+ integrated tools** — subfinder, nuclei, httpx, naabu, ffuf, sqlmap, dalfox, katana, and more; detected on `PATH`, missing tools simply skip their phases
- **Adaptive resource monitor** — concurrency auto-scales on real-time CPU/RAM; circuit breaker pauses after repeated failures; emergency kill below free-RAM thresholds
- **Multi-format reporting** — HTML, Markdown, JSON, SARIF (CI/CD), Faraday (JSONL), and a self-contained `dashboard.html`
- **AI triage** — OpenAI, Anthropic, or Ollama for finding classification and exploit-chain suggestions (post-scan; off by default)
- **Compliance reports** — PCI-DSS v4.0, HIPAA, and SOC2 control assessment from findings (`--compliance`)
- **Threat intelligence** — MITRE ATT&CK technique mapping plus optional threat-feed indicator matching (`--threat-intel` / `--threat-feed`)
- **ML classification & phase selection** — rule-based vulnerability classification with confidence scores (`--ml-classify`) and data-driven phase ranking (`--ml-select N`)
- **Encrypted credential store** — Fernet-encrypted API keys/cookies with rotation and expiry (`--cred-set/--cred-get/--cred-rm/--cred-list`)
- **REST API** — stdlib HTTP server for querying scan results after a run (`--api-port N`)
- **Exploit chain analysis** — cross-phase attack-path detection with severity escalation (on by default)
- **Attack surface graph** — interactive HTML + JSON graph of subdomain/host relationships
- **Risk and confidence scoring** — A–F risk grades, per-finding confidence, CWE-to-remediation mappings
- **Target profiling** — auto-tunes sample sizes based on observed scope size and detected tech stack
- **Plugin system** — custom phases loaded from a directory at runtime; plugins inherit pipeline safety features
- **Distributed scanning** — SSH-based multi-host orchestration
- **Live dashboard and bot** — SSE web dashboard, Discord/Slack companion bot, Slack/Discord/Telegram notifications
- **Secure by default** — RLIMIT caps, rate limiting, secret redaction, input sanitization, JSONL audit log
- **CLI ergonomics** — 185 flags in 8 groups, interactive wizard, `--daemon`/`--status`, `--compare`, `--review`, batch mode

## Quick Start

| Command | Description |
|---------|-------------|
| `vulnforge -d example.com` | Full reconnaissance and vulnerability scan |
| `vulnforge -d example.com --fast` | Quick recon only (scope, recon, resolve, scan, harvest) |
| `vulnforge -d example.com --profile quick` | Full pipeline minus ~37 low-signal phases |
| `vulnforge -d example.com --safe` | Conservative settings for VMs/containers |
| `vulnforge -d example.com --dos` | Enable DoS-style phases (disabled by default) |
| `vulnforge -d example.com --resume` | Resume from saved state |
| `vulnforge -d example.com --only 01-RECON,02-RESOLVE` | Run selected phases only |
| `vulnforge -d example.com --skip 23-RACE,93-PWDSPRAY` | Skip specific phases |
| `vulnforge -i` | Interactive setup wizard (presets, profiles) |
| `vulnforge --batch targets.txt` | Batch scan multiple domains |
| `vulnforge -d example.com --daemon` | Run in background; check with `--status` |

### Advanced

```bash
vulnforge -d example.com --proxy socks5://127.0.0.1:9050     # proxy all phases
vulnforge -d example.com --vuln-proxy socks5://127.0.0.1:9050  # proxy vuln phases only
vulnforge -d example.com --cookie-a 'session=u1' --cookie-b 'session=u2'  # IDOR diffing
vulnforge -d example.com --ai-provider ollama --ai-model llama3  # AI triage
vulnforge -d example.com --compliance                            # PCI-DSS/HIPAA/SOC2 reports
vulnforge -d example.com --threat-intel --threat-feed feeds.json # MITRE ATT&CK + feed matches
vulnforge -d example.com --ml-classify                           # ML classification + confidence
vulnforge -d example.com --ml-select 15                          # run only the top-15 predicted phases
vulnforge -d example.com --api-port 8080                         # serve results over REST after scan
vulnforge --cred-set github_token ghp_xxx                        # store a credential
vulnforge --cred-get github_token                                # retrieve a credential
vulnforge --distributed --distributed-hosts host1 host2  # SSH cluster
vulnforge -d example.com --plugins-dir ./plugins             # load custom phases
vulnforge -d example.com --notify https://hooks.slack.com/... # notify webhook
vulnforge -d example.com --bot discord --bot-token TOKEN     # companion bot
vulnforge -d example.com --compare ./out/a ./out/b           # diff two scans
vulnforge -d example.com --review                            # interactive review
vulnforge --dry-run -d example.com                           # preview commands
vulnforge --gen-config                                       # write example config
```

## Phases (213)

```
00-SCOPE              01-RECON            02-RESOLVE          03-PERMUTE
04-SCAN               04b-TAKEOVER-VALIDATE  05-HARVEST          05b-APISPEC
06-JSINTEL            07-PARAMS           08-FUZZ             09-VULNSCAN
10-TLSCMS             11-INJECT           11a-DOMXSS          11b-SQLMAP
12-SSTI               13-OOB              14-ORIGIN           15-SECRETS
16a-AUTHZ             16b-MASSASSIGN      17-IDOR             17b-SSRFMETA
18-CLOUD              19-GIT              20-GRAPHQL          21-WAF
21b-WAFBYPASS         22-NOSQLI           23-RACE             24-JWT
25-XXE                26-CMDINJECT        27-SSPP             28-CACHED
29-DEPCHECK           30-LFI              31-OPENREDIR        32-CLICKJACK
33-CRLF               34-RATELIMIT        35-CORSADV          36-JWTADV
37-FILEUPLOAD         38-SMUGGLE          38b-H2SMUGGLE       39-OAUTH
40-PWRESET            41-WEBSOCKET        42-LDAP             43-DESERIAL
44-CHAIN              45-EVIDENCE         46-BUCKET           47-CDN
48-CONTENT            49-FRAMEWORKS       50-BUCKET-PERMS     51-HPP
52-SERVERLESS         53-CSP              54-WS-FUZZ          55-CSV-INJECT
56-EXPOSED-DB         57-DEFAULT-CREDS    58-HOST-INJECT      59-EMAIL-SEC
60-SMTP-ENUM          61-OAUTH-ADV        62-LOG-INJECT       63-DOC-ATTACK
64-IDEMPOTENCY        65-SESSION          66-SSRF-FULL        67-PATHNORM
68-DEPCVE             69-DNSZT            70-PORTFULL         71-EMHARVEST
72-ACCOUNTENUM        73-CSPBYPASS        74-GHTOOLS          75-MOBILEAPI
76-WORKFLOW           77-CACHEKEY         78-FILEUPLOADADV    79-SECRETDIFF
80-STOREXSS           81-IDORFUZZ         82-OAUTHDEEP        83-RACEBURST
84-WHOIS              85-ASN              86-DORK             87-SHODAN
88-EMPLOYEE           89-PASSIVEDNS      90-CSRF              91-SESSIONFIX
92-SAML               93-PWDSPRAY        94-COOKIEAUDIT       95-POSTTEST
96-METHODOVERRIDE     97-FORCEDBROWSE    98-CASEBYPASS        99-APIPAGE
99a-TABNAB            99b-APIKEYLEAK     99c-REDIRABUSE       99d-LOGTRIGGER
99e-XSSSTORED         99f-HOSTABUSE      99g-AUTHBYPASSADV    100-SSI
101-JSONINJECT        102-NULLBYTE       103-DOUBLEENCOD      104-UNICODE
105-POSTMSGXSS        106-JSONP          107-SRI              108-MIXEDCONTENT
109-HSTSPRELOAD       110-THIRDPARTYJS   111-BROWSERSTORAGE   112-RFI
113-WEBDAV            114-SNMP           115-BANNER           116-PHPINFO
117-SRVSTATUS         118-ERRORLEAK      119-WILDCARDDNS      120-DNSREBIND
121-IISASPNET         122-TOMCAT         123-NODEJS           124-LARAVEL
125-DJANGO            126-SYMFONY        127-CICD             128-DOCKER
129-K8S               130-TERRAFORM      131-ENVDEEP          132-GQLABUSE
133-APIVERSION        134-LBDETECT       135-VHOST            136-RATELIMITBYPASS
137-EMAILFINDER       138-METAGOOFIL     139-PORCHPIRATE      140-DORKHUNTER
141-CRTSH             142-GITHUBSUB      143-TLSX             144-ANALYTICSRELS
145-FAVIRECON         146-JSLUICE        147-SHORTSCAN        148-GRPCURL
149-LLMSEC            150-LLMLEAK        151-RAGPOISON        152-LLMADV
153-BIZLOGIC          154-PAYMENT        155-COUPON           156-MTENANT
157-2FA               158-SSO           159-SAMLADV           160-SSOCONF
161-ELECTRON          162-ELECTRONRCE   163-ELECTRONPROTO     164-ELECTRONUPD
165-DEPCONF           166-TYPOSQUAT     167-H2RAPID           168-H3QUIC
169-WEBTRANSPORT      170-CLIENTPP      171-CSSINJECT         172-DANGLING
173-SERVICEWORKER     174-WASMSEC       175-OAUTHDEVICE       175a-WS-DEEP
176-JWT2SELF          177-SELENIUMXSS   178-APIRACE           179-WAFBYPASS
180-SWAGGERABUSE      181-MFABYPASS     182-CAPTCHABYPASS     183-CACHEDIG
184-SSRFPARTIAL       185-MAGENTO       186-SHAREPOINT        187-CONFLUENCE
188-CICD              189-TOMCAT        190-BROTLIORACLE      191-ATO
192-REDOS             193-WEBRTC        194-COOKIETOSS        195-MIMESNIFF
196-PUSHAPI
```

DoS-style phases (race bursts, request smuggling, GraphQL depth attacks, H2 rapid reset, credential spray) are gated behind `--dos` and are off by default.

Not all phases are equal: 32 shell out to real external tools, 3 drive a browser, 174 are active heuristic probes, and 4 are local aggregation. See [Phase Classification](docs/phase-classification.md) for the per-phase breakdown (generated from the source).

## Responsible Use

VulnForge performs **active scanning** against targets. You may only use it against systems you own or are **explicitly authorized** to test. The operator — not the tool — is responsible for complying with all applicable laws and with the scope defined in any engagement contract or bug-bounty program's rules of engagement.

By running VulnForge you agree that:

- You have written authorization for every target you scan.
- You will not exceed the authorized scope (avoid `--dos` on production systems unless explicitly permitted, and respect rate limits).
- You will handle all findings and any credentials collected by the tool confidentially and disclose them only through the program's responsible-disclosure process.

The project is distributed under the MIT license with no warranty (see `LICENSE`); misuse of the tool is solely the responsibility of the user.

## Integrated Tools (40+)

All tools are optional and auto-detected on `PATH`.

**Go:** subfinder, alterx, dnsx, naabu, httpx, nuclei, gau, gospider, katana, subjs, ffuf, dalfox, interactsh-client, kxss, Gxss, gitleaks, httprobe, trufflehog, unfurl, qsreplace, puredns, gowitness, cloudfox, crlfuzz, tlsx, smuggler

**Python:** dnsgen, waymore, xnLinkFinder, SecretFinder, wafw00f, inql, clairvoyance, graphinder, arjun, corsy, commix, wpscan, sqlmap, cloud_enum

**Rust:** findomain (CT logs + 14 APIs, DNS, port scan)

**System:** nmap, massdns, dig, whois, testssl.sh, trivy, gitdumper, playwright/Chromium (DOM XSS automation)

## Configuration

VulnForge reads a TOML file named `vulnforge.cfg`. Lookup order: `--config PATH`, then `./vulnforge.cfg`, then `~/.config/vulnforge/vulnforge.cfg`. CLI flags always override config values. Run `vulnforge --gen-config` to print an annotated example.

```ini
[general]
proxy = "socks5://127.0.0.1:9050"     # proxy for all phases
# delay = 0.0
# rate_limit = 0
# parallel_jobs = 4
# safe_mode = false
# cookie = ""

[scan]
dos_mode = false
sqlmap_level = 1
sqlmap_risk = 1
# sample_mode = "normal"

[api]
# shodan_key = ""
# whoisxml_key = ""
# projectdiscovery_key = ""
# github_tokens = ["ghp_xxx", "ghp_yyy"]

[notify]
# slack_webhook = "https://hooks.slack.com/services/xxx"
# discord_webhook = "https://discord.com/api/webhooks/xxx"
# telegram_bot_token = ""
# telegram_chat_id = ""

[proxy]
# url = "socks5://127.0.0.1:9050"
# vuln_url = "socks5://127.0.0.1:9050"

[ai]
# provider = "ollama"
# model = "llama3"
# api_key = ""

[dashboard]
# enabled = false
# host = "127.0.0.1"
# port = 8765

[bot]
# platform = "discord"
# token = ""
# channel_id = ""
# mention_on_critical = true

[plugins]
# directory = "~/.config/vulnforge/plugins"
```

The interactive wizard (`vulnforge -i`) saves its chosen setup as a profile in `~/.config/vulnforge/profiles/`.

## Output Structure

Scans write to `./out/<domain>/` (override with `-o`):

```
out/example.com/
├── summary.json / summary.txt        # Always
├── report.html / report.md           # Always
├── results.faraday.json              # Always (Faraday JSONL)
├── dashboard.html                    # Always (self-contained)
├── results.sarif                     # Only with --format sarif
├── attack_surface.html / .json       # --attack-graph (or subdomains found)
├── exploit_chains.json               # Unless --no-exploit-chains
├── risk_score.json                   # Unless --no-risk
├── confidence_scores.json            # Unless --no-confidence
├── compliance_pci_dss.md/.json       # --compliance
├── compliance_hipaa.md/.json         # --compliance
├── compliance_soc2.md/.json          # --compliance
├── threat_intel_report.json          # --threat-intel
├── classified_vulns.json             # --ml-classify
├── target_profile.json               # Unless --no-profile
├── tool_health.json / dedup_state.json
├── state.json                        # Resume state (after every phase)
├── audit.jsonl                       # Structured audit trail
├── evidence.txt, evidence_payloads/, evidence/poc/
├── poc/                              # Auto-generated PoCs (unless --no-poc)
├── screenshots/                      # Gowitness/Playwright screenshots
├── oast/callbacks.txt, logs/interactsh.log
├── logs/                             # Per-tool stdout/stderr logs
├── ai_cache/                         # AI triage results (when enabled)
└── *.txt                             # Per-artifact finding files (~200)
```

## Safety

- **Per-tool process limits**: `RLIMIT_NPROC` 2048, `RLIMIT_FSIZE` 512 MB, core dumps disabled. RAM is governed by the adaptive monitor instead of `RLIMIT_AS`, since Go binaries reserve >2 GB of virtual address space.
- **Adaptive monitor**: concurrency scales up when CPU < 50% and >2 GB RAM free, scales down at CPU > 80% or <1 GB free, and emergency-kills child processes below 1 GB free, resuming at 2 GB.
- **Circuit breaker**: pauses a phase after 3 consecutive real subprocess failures.
- **Phase timeout**: 7200s per phase (1800s in `--safe`); default per-tool timeout 300s.
- **Safe mode** (`--safe`): serial execution, halved sample sizes, `RLIMIT_NPROC` 512, `RLIMIT_FSIZE` 128 MB, preflight RAM check.
- **Rate limiting**: `--rate-limit`, `--rate-limit-per-domain`, `--delay`.
- **Proxy**: `--proxy` (all phases) and `--vuln-proxy` (vuln phases only); tool timeouts multiplied by 1.5 when proxied. DNS tools bypass the proxy.
- **Secrets**: credentials redacted from `repr`, cookies files permission-fixed, secrets not exported to subprocess environments.
- **Input sanitization**: hostname validation, output path confinement to `./out`, batch file filtering, `state.json` whitelist filtering.
- **Audit logging**: structured JSONL audit trail of scan start and per-phase events.

## Architecture

```
vulnforge/
├── cli/                  # banner.py, parser.py (179 flags, 8 groups),
│                         # wizard.py (interactive setup), helpers.py (main dispatch)
├── config.py             # PipelineConfig, VALID_PHASES (213), presets
├── conf.py               # TOML config file loading
├── pipeline.py           # DAG executor, state persistence, report orchestration
├── process.py            # Subprocess management, RLIMIT, circuit breaker, rate limiting
├── resource_monitor.py   # Adaptive CPU/RAM concurrency scaling
├── scheduler.py          # Async job scheduling
├── throttle.py           # Token-bucket rate limiting
├── utils.py              # Logging, HTTP/DNS helpers, file I/O, caches
├── tools.py              # External tool detection
├── phases/               # 213 phase implementations
│   ├── recon/            # subdomain.py, dns.py, scan.py, harvest.py, jsintel.py,
│   │                     # params.py, osint.py, scope.py
│   ├── injection.py, injection_misc.py   # XSS, SQLi, SSTI, NoSQLi, XXE, CMDi, SSRF
│   ├── auth.py, auth_bypass.py, sso.py, account.py   # JWT, OAuth, IDOR, CSRF, SAML, 2FA
│   ├── client_side.py, advanced_inject.py, redos.py   # DOM XSS, clickjack, CORS, CRLF
│   ├── smuggling.py      # HTTP/2 request smuggling, race conditions
│   ├── graphql_chain.py, llm_ai.py       # GraphQL, LLM/AI security
│   ├── cloud.py, origin_cloud.py, network.py, web_infra.py
│   ├── cms.py, cms_deep.py, modern_web.py, modern_proto.py
│   ├── encoding.py, extended.py, third_party.py, supplychain.py
│   ├── email_misc.py, secrets_git.py, cookie_security.py, bizlogic.py
│   ├── electron.py, webrtc.py, pwa_security.py, protocol.py
│   └── vuln_scan.py, fuzzing.py   # nuclei, testssl, waf detection
├── finding.py            # Structured Finding dataclass
├── artifacts.py          # Artifact registry, severity classification
├── dedup.py              # Cross-phase fuzzy deduplication (prefix-indexed)
├── certainty.py          # Confidence scoring
├── severity.py           # Risk scoring (A-F)
├── remediation.py        # CWE-to-fix mappings
├── exploit_chain.py      # Cross-phase exploit chain analysis
├── attack_surface.py     # Attack surface graph generation
├── reporting.py          # HTML, Markdown, JSON, SARIF, Faraday reports
├── proof.py              # Auto-PoC generation
├── target_profile.py     # Target profiling + auto-tuning
├── tool_health.py        # Tool health monitoring
├── ai.py, ai_triage.py, ai_exploit.py   # LLM providers + AI triage/suggestions
├── api.py, openapi.py    # REST API server + spec (stdlib; library API)
├── dashboard_server.py, tui.py   # SSE web dashboard, terminal UI
├── bot.py, notify.py     # Discord/Slack bot, Slack/Discord/Telegram notifications
├── distributed.py        # SSH-based distributed scanning
├── plugin.py               # Plugin system
├── interactsh.py         # OOB interaction tracking
├── events.py             # In-process event bus (pub/sub)
├── audit.py              # Structured JSONL audit logging
├── credentials.py        # Encrypted credential store (library)
├── compliance.py         # PCI DSS / HIPAA / SOC 2 reporting (library)
├── threat_intel.py       # MITRE ATT&CK mapping + threat feeds (library)
├── ml_phase_selector.py, ml_vuln.py   # Rule-based phase selection + classification (library)
├── diff.py               # Scan comparison
├── review.py             # Interactive finding review
├── fleet.py              # Batch scan runner
├── exceptions.py         # Typed exception hierarchy
└── __init__.py           # Package exports, main()
```

Modules marked *library* are invoked programmatically; the rest are exposed via the CLI. Compliance, threat intel, ML classification, ML phase selection, credentials, and the REST API are now wired to flags (`--compliance`, `--threat-intel`, `--ml-classify`, `--ml-select`, `--cred-*`, `--api-port`).

## Development

```bash
python3 -m pip install -e ".[dev]"
pytest tests/ -v                    # 435+ tests across 24 files
ruff check vulnforge/ && ruff format --check vulnforge/
mypy vulnforge/
make ci                             # full CI suite
```

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | Module structure, pipeline flow, data flow |
| [REST API](docs/api.md) | API endpoints, security notes, programmatic usage |
| [Plugins](docs/plugins.md) | Custom phase development guide |
| [Events](docs/events.md) | Event bus reference for real-time streaming |
| [Contributing](docs/contributing.md) | Development setup, code style, PR process |

## License

MIT
