# ReconChain v3.1.0

Enterprise-grade security reconnaissance and vulnerability assessment pipeline orchestrator. Chains **164 security phases** across **27 DAG stages**, orchestrating **45+ external tools** into a single resumable, adaptive pipeline.

```bash
reconchain -d example.com                          # Full scan
reconchain -i                                      # Interactive wizard
reconchain -d example.com --fast                   # Quick recon (5 phases)
reconchain -d example.com --safe                   # VM/container safe mode
reconchain -d example.com,test.org                 # Multi-domain scan
reconchain --batch targets.txt                     # Batch scan from file
reconchain -d example.com --api-port 8080          # REST API
reconchain -d example.com --dashboard              # Live web dashboard
```

## Install

```bash
pip install tqdm && python3 -m pip install -e '.[dev]'
chmod +x install.sh && ./install.sh
```

Or with Docker:

```bash
docker build -t reconchain .
docker compose run reconchain -d example.com
```

## Features

- **164 phases, 27 DAG stages** — resumable, parallel execution with explicit dependency ordering
- **45+ integrated tools** — subfinder, nuclei, httpx, naabu, ffuf, sqlmap, dalfox, katana, gau, and more
- **Adaptive resource monitor** — auto-scales concurrency based on real-time CPU/RAM; circuit breaker prevents cascading failures
- **Multi-format reporting** — HTML, Markdown, JSON, SARIF (CI/CD), Faraday (JSONL)
- **AI-powered triage** — OpenAI, Anthropic, or Ollama integration for vulnerability classification and exploit suggestions
- **ML-assisted scanning** — phase prioritization, vulnerability classification with 24 signatures, exploit chain analysis
- **Compliance reports** — PCI DSS v4.0 (8 controls), HIPAA (6 controls), SOC 2 Type II (6 controls)
- **Threat intelligence** — MITRE ATT&CK mapping (20 techniques across 7 tactics), custom threat feed matching
- **Attack surface visualization** — directed graph analysis of multi-step attack chains
- **Collaborative scanning** — multi-scanner team workspaces with consensus-based confirmation
- **Plugin marketplace** — community-contributed phase plugins
- **Continuous monitoring** — watchdog scripts, scheduled re-scans, Discord/Slack/Telegram notifications
- **REST API** — stdlib-based HTTP server with health, findings, artifacts, and scan control endpoints
- **Terminal UI & web dashboard** — live SSE streaming dashboard
- **Distributed scanning** — SSH-based multi-host orchestration
- **Secure by default** — RLIMIT caps, rate limiting, credential encryption (Fernet/AES-128), input sanitization, audit logging

## Quick Start

| Command | Description |
|---------|-------------|
| `reconchain -d example.com` | Full reconnaissance and vulnerability scan |
| `reconchain -d example.com --fast` | Quick recon (scope, resolve, scan, harvest, params) |
| `reconchain -d example.com --safe` | Conservative settings for VMs/containers |
| `reconchain -d example.com --no-dos` | Skip DoS-style phases |
| `reconchain -d example.com --resume` | Resume from saved state |
| `reconchain -d example.com --only 01-RECON,02-RESOLVE` | Selective phases |
| `reconchain -d example.com --skip 23-RACE,93-PWDSPRAY` | Skip specific phases |
| `reconchain -i` | Interactive setup wizard |
| `reconchain --batch targets.txt` | Batch scan multiple domains |

### Advanced

```bash
reconchain -d example.com --proxy socks5://127.0.0.1:9050     # Tor proxy
reconchain -d example.com --compliance pci_dss,hipaa           # Compliance report
reconchain -d example.com --threat-intel                       # MITRE ATT&CK
reconchain -d example.com --credential-store                   # Encrypted creds
reconchain -d example.com --collaborative --workspace team     # Team scanning
reconchain -d example.com --format sarif                       # CI/CD output
python3 monitor.py -d example.com                              # Watchdog
```

## Phases (164)

```
00-SCOPE              01-RECON             02-RESOLVE          03-PERMUTE
04-SCAN               04b-TAKEOVER         05-HARVEST          05b-APISPEC
06-JSINTEL            07-PARAMS            08-FUZZ             09-VULNSCAN
10-TLSCMS             11-INJECT            11a-DOMXSS          11b-SQLMAP
12-SSTI               13-OOB               14-ORIGIN           15-SECRETS
16a-AUTHZ             16b-MASSASSIGN       17-IDOR             17b-SSRFMETA
18-CLOUD              19-GIT               20-GRAPHQL          21-WAF
21b-WAFBYPASS         22-NOSQLI            23-RACE             24-JWT
25-XXE                26-CMDINJECT         27-SSPP             28-CACHED
29-DEPCHECK           30-LFI               31-OPENREDIR        32-CLICKJACK
33-CRLF               34-RATELIMIT         35-CORSADV          36-JWTADV
37-FILEUPLOAD         38-SMUGGLE           38b-H2SMUGGLE       39-OAUTH
40-PWRESET            41-WEBSOCKET         42-LDAP             43-DESERIAL
44-CHAIN              45-EVIDENCE          46-BUCKET           47-CDN
48-CONTENT            49-FRAMEWORKS        50-BUCKET-PERMS     51-HPP
52-SERVERLESS         53-CSP               54-WS-FUZZ          55-CSV-INJECT
56-EXPOSED-DB         57-DEFAULT-CREDS     58-HOST-INJECT      59-EMAIL-SEC
60-SMTP-ENUM          61-OAUTH-ADV         62-LOG-INJECT       63-DOC-ATTACK
64-IDEMPOTENCY        65-SESSION           66-SSRF-FULL        67-PATHNORM
68-DEPCVE             69-DNSZT             70-PORTFULL         71-EMHARVEST
72-ACCOUNTENUM        73-CSPBYPASS         74-GHTOOLS          75-MOBILEAPI
76-WORKFLOW           77-CACHEKEY          78-FILEUPLOADADV    79-SECRETDIFF
80-STOREXSS           81-IDORFUZZ          82-OAUTHDEEP        83-RACEBURST
84-WHOIS              85-ASN               86-DORK             87-SHODAN
88-EMPLOYEE           89-PASSIVEDNS        90-CSRF             91-SESSIONFIX
92-SAML               93-PWDSPRAY          94-COOKIEAUDIT      95-POSTTEST
96-METHODOVERRIDE     97-FORCEDBROWSE      98-CASEBYPASS       99-APIPAGE
99a-TABNAB            99b-APIKEYLEAK       99c-REDIRABUSE      99d-LOGTRIGGER
99e-XSSSTORED         99f-HOSTABUSE        99g-AUTHBYPASSADV   100-SSI
101-JSONINJECT        102-NULLBYTE         103-DOUBLEENCOD     104-UNICODE
105-POSTMSGXSS        106-JSONP            107-SRI             108-MIXEDCONTENT
109-HSTSPRELOAD       110-THIRDPARTYJS     111-BROWSERSTORAGE  112-RFI
113-WEBDAV            114-SNMP             115-BANNER          116-PHPINFO
117-SRVSTATUS         118-ERRORLEAK        119-WILDCARDDNS     120-DNSREBIND
121-IISASPNET         122-TOMCAT           123-NODEJS          124-LARAVEL
125-DJANGO            126-SYMFONY          127-CICD            128-DOCKER
129-K8S               130-TERRAFORM        131-ENVDEEP         132-GQLABUSE
133-APIVERSION        134-LBDETECT         135-VHOST           136-RATELIMITBYPASS
```

## Integrated Tools (45+)

**Go:** subfinder, alterx, dnsx, naabu, httpx, nuclei, gau, gospider, katana, subjs, ffuf, dalfox, interactsh-client, kxss, gitleaks, httprobe, trufflehog, unfurl, qsreplace, Gxss, cdncheck, puredns, gowitness, cloudfox, crlfuzz

**Rust:** findomain (CT logs + 14 APIs, DNS, port scan, monitoring)

**Python:** dnsgen, waymore, xnLinkFinder, SecretFinder, wafw00f, inql, cloud_enum, clairvoyance, graphinder, arjun, jsubfinder, corsy, jwt_tool, ssmrfy, commix, wpscan, sqlmap

**System:** nmap, massdns, testssl.sh, feroxbuster

## Configuration

Place `reconchain.cfg` in the project root or `~/.config/reconchain/`:

```ini
[general]
# proxy = socks5://127.0.0.1:9050
# delay = 0.0
# rate_limit = 0
# parallel_jobs = 4

[scan]
dos_mode = false
sqlmap_level = 1
sqlmap_risk = 1

[api]
# shodan_key = ""
# whoisxml_key = ""
# projectdiscovery_key = ""
# github_tokens = ["ghp_xxx"]

[notify]
# slack_webhook = ""
# discord_webhook = ""

[ai]
# provider = ollama
# model = llama3
# api_key = ""
```

## Output Structure

```
out/example.com/
├── summary.json / summary.txt
├── report.html / report.md
├── results.sarif / results.faraday.json
├── attack_surface.html / attack_surface.json
├── exploit_chains.json
├── classified_vulns.json
├── threat_intel_report.json
├── compliance_pci_dss.json
├── risk_score.json / confidence_scores.json
├── state.json                    # Resume state
├── evidence/                     # Auto-generated PoCs
├── screenshots/                  # Gowitness screenshots
├── oast/                         # OOB interaction callbacks
├── logs/                         # Raw tool output
└── *.txt                         # Per-artifact finding files
```

## Safety

- **Per-tool resource caps**: RLIMIT_AS (8 GB), RLIMIT_NPROC (2048), RLIMIT_FSIZE (512 MB)
- **Global process counter**: auto-scales with CPU, caps at 12 concurrent subprocesses
- **Adaptive monitor**: auto-tunes concurrency; emergency kill at 500 MB RAM, resume at 1.5 GB
- **Circuit breaker**: pauses after 3 consecutive subprocess failures
- **Phase timeout**: 7200s per phase
- **Safe mode** (`--safe`): start=1, max=4, max_procs=2, CPU threshold=60%, RAM threshold=2 GB
- **Rate limiting**: per-tool via `--rate-limit`, global via `--delay`
- **Credential encryption**: Fernet (AES-128-CBC + HMAC-SHA256) with machine-derived keys
- **Input sanitization**: domain validation, output path confinement, batch file filtering
- **Audit logging**: structured JSONL audit trail

## Architecture

```
reconchain/
├── cli/                    # banner.py, parser.py (170+ flags), wizard.py (997 lines), helpers.py
├── phases/                 # 164 phase implementations
│   └── recon/              # 8 recon sub-modules
├── config.py               # PipelineConfig (130+ fields), phase definitions
├── pipeline.py             # DAG executor (1137 lines)
├── process.py              # Subprocess management, circuit breaker
├── api.py                  # REST API (stdlib http.server)
├── reporting.py            # HTML, Markdown, JSON, SARIF, Faraday reports
├── exploit_chain.py        # Attack path graph analysis
├── threat_intel.py         # MITRE ATT&CK mapping (20 techniques, 7 tactics)
├── compliance.py           # PCI DSS / HIPAA / SOC 2 reporting
├── ai.py / ai_triage.py    # LLM providers + vulnerability triage
├── ml_phase_selector.py    # Rule-based phase prioritization
├── ml_vuln.py              # 24-signature vulnerability classification
├── collaborative.py        # Team workspace with multi-scanner dedup
├── marketplace.py          # Plugin marketplace client
├── plugin.py               # Plugin/extension system
├── resource_monitor.py     # Adaptive CPU/RAM monitor
├── bot.py                  # Discord/Slack companion bot
├── dashboard_server.py     # SSE live web dashboard
├── tui.py                  # Terminal UI dashboard
├── distributed.py          # SSH-based distributed scanning
├── dedup.py                # Cross-phase fuzzy deduplication
├── credentials.py          # Encrypted credential storage (Fernet)
├── audit.py                # Structured JSONL audit logging
├── events.py               # In-process event bus (pub/sub)
├── notify.py               # Slack/Discord/Telegram notifications
├── interactsh.py           # OOB interaction tracking
├── poc.py                  # Auto-PoC generation
├── target_profile.py       # Target profiling + auto-tuning
├── artifacts.py            # 164-phase artifact registry
├── severity.py             # Risk scoring (A-F)
├── confidence.py           # Confidence scoring
├── remediation.py          # CWE-to-fix mappings (25 types)
├── exceptions.py           # 28-class exception hierarchy
└── utils.py                # Logging, DNS, HTTP, file I/O
```

## Compliance Reporting

```bash
reconchain -d example.com --compliance pci_dss      # PCI DSS v4.0 (8 controls)
reconchain -d example.com --compliance hipaa,soc2   # HIPAA + SOC 2
```

## Threat Intelligence

```bash
reconchain -d example.com --threat-intel
reconchain -d example.com --threat-intel --threat-intel-feeds feeds.json
```

MITRE ATT&CK coverage: 20 techniques across Initial Access, Execution, Defense Evasion, Credential Access, Lateral Movement, Exfiltration, and Impact.

## REST API

```bash
reconchain -d example.com --api-port 8080

GET  /api/v1/health              # Health check
GET  /api/v1/summary             # Scan summary
GET  /api/v1/findings            # List findings (filterable)
GET  /api/v1/coverage            # Phase coverage metrics
GET  /api/v1/artifacts           # Artifact registry
GET  /api/v1/openapi.json        # OpenAPI 3.0 spec
```

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | Module structure, pipeline flow, data flow |
| [REST API](docs/api.md) | API endpoints, security, programmatic usage |
| [Plugins](docs/plugins.md) | Custom phase development guide |
| [Events](docs/events.md) | Event bus reference for real-time streaming |
| [Contributing](docs/contributing.md) | Development setup, code style, PR process |

## Development

```bash
pip install -e '.[dev]'
pytest tests/          # Run tests
ruff check reconchain/ # Lint
mypy reconchain/       # Type check
```

## License

MIT
