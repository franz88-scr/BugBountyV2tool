# Architecture

## Overview

VulnForge is a Python-based bug bounty reconnaissance pipeline orchestrator that chains **213 security phases** across **45 DAG stages**. Given a target domain, it orchestrates **40+ external security tools** into a single resumable pipeline with adaptive resource management.

## Module Structure

```
vulnforge/
├── __init__.py              # Package exports + main() dispatch
├── cli/                     # CLI package
│   ├── __init__.py          # Re-exports: build_parser, main, InteractiveWizard
│   ├── banner.py            # ASCII banner display
│   ├── helpers.py           # main() entry point, mode dispatch
│   ├── parser.py            # ArgumentParser with 8 groups, 179 flags
│   └── wizard.py            # Interactive setup wizard (1619 lines)
│
├── config.py                # PipelineConfig (130+ fields), VALID_PHASES (213), presets
├── conf.py                  # TOML vulnforge.cfg loading (CLI wins), wizard profiles
├── pipeline.py              # DAG executor, state persistence, report orchestration
├── process.py               # Subprocess management, RLIMIT, circuit breaker, rate limiting
├── resource_monitor.py      # Adaptive CPU/RAM concurrency scaling
├── scheduler.py             # Async job scheduling
├── throttle.py              # Token-bucket rate limiting
├── utils.py                 # Logging, HTTP/DNS helpers, file I/O, caches
├── tools.py                 # External tool detection (cached binary lookup)
│
├── phases/                  # 213 security phase implementations
│   ├── __init__.py          # PIPELINE list, PHASE_DEPS DAG, STAGES (45) ordering
│   ├── recon/               # Subdomain, DNS, live probing, harvesting, JS, params, OSINT
│   │   ├── scope.py         # Domain scope validation
│   │   ├── subdomain.py     # Subdomain enumeration (subfinder, findomain, alterx, dnsgen)
│   │   ├── dns.py           # DNS resolution + DNS cache (puredns, massdns, dnsx)
│   │   ├── scan.py          # Port scanning + live host detection (naabu, nmap, httpx)
│   │   ├── harvest.py       # URL/endpoint harvesting (gau, waymore, katana)
│   │   ├── jsintel.py       # JavaScript analysis (SecretFinder, xnLinkFinder)
│   │   ├── params.py        # Parameter discovery (arjun)
│   │   └── osint.py         # WHOIS and passive OSINT
│   ├── injection.py         # XSS (dalfox, kxss, Gxss), SQLi (sqlmap), SSTI
│   ├── injection_misc.py    # NoSQLi, XXE, CMDi (commix), SSRF, LDAP, deserialization
│   ├── auth.py              # JWT, OAuth, IDOR, password reset
│   ├── auth_bypass.py       # CSRF, SAML, forced browse, method override
│   ├── account.py           # Account enumeration, 2FA, ATO
│   ├── client_side.py       # Cache poison, CORS (corsy), clickjack, CRLF (crlfuzz)
│   ├── advanced_inject.py   # DOM XSS via Playwright, blind XSS via OAST
│   ├── encoding.py          # SSI, null byte, double encoding, unicode bypasses
│   ├── fuzzing.py           # Endpoint fuzzing (ffuf), WAF detect/bypass (wafw00f)
│   ├── smuggling.py         # HTTP/2 request smuggling, race conditions
│   ├── vuln_scan.py         # Nuclei, testssl.sh, wpscan, trivy
│   ├── network.py           # RFI, WebDAV, SNMP, banner grab
│   ├── third_party.py       # SRI, HSTS, mixed content, third-party JS
│   ├── origin_cloud.py      # Origin IP, cloud buckets (cloud_enum, cloudfox)
│   ├── secrets_git.py       # Secrets (trufflehog, gitleaks, unfurl), git exposure
│   ├── web_infra.py         # CDN, CSP, file upload
│   ├── graphql_chain.py     # GraphQL (inql, clairvoyance, graphinder) + evidence phases
│   ├── email_misc.py        # Email security, SMTP enumeration, workflow
│   ├── llm_ai.py            # LLM/AI application security phases
│   ├── cloud.py             # Cloud metadata, exposed databases, bucket perms
│   ├── cms.py, cms_deep.py  # CMS fingerprinting + deep checks (Magento, SharePoint, etc.)
│   ├── modern_web.py, modern_proto.py   # Modern protocols (gRPC, H2/H3, WebTransport)
│   ├── bizlogic.py          # Business logic, payments, coupons, multi-tenancy
│   ├── sso.py               # SSO/SAML advanced
│   ├── electron.py, webrtc.py, pwa_security.py   # App/desktop/browser security
│   ├── cookie_security.py, redos.py, protocol.py # Cookie audit, ReDoS, misc protocol
│   ├── encoding.py, extended.py, supplychain.py  # Bypasses, TLSX, dependency exposure
│   └── infra.py             # Backward-compat re-export shim
│
├── exceptions.py            # VulnForgeError hierarchy (28 classes)
├── audit.py                 # Structured JSONL audit logging
├── dedup.py                 # Cross-phase deduplication (prefix-indexed)
│
├── finding.py               # Structured Finding dataclass
├── remediation.py           # CWE-to-fix mappings (25 vuln types)
├── severity.py              # Risk scoring (A-F grades)
├── artifacts.py             # Artifact registry (~200 per-phase files)
├── certainty.py             # Finding confidence scoring
├── exploit_chain.py         # Cross-phase exploit chain analysis
├── attack_surface.py        # Attack surface graph generation
│
├── reporting.py             # HTML, Markdown, JSON, SARIF, Faraday reports
├── proof.py                 # Auto-PoC generation
├── target_profile.py        # Target profiling + auto-tuning
├── tool_health.py           # Tool health monitoring
│
├── ai.py                    # LLM provider abstraction (openai/anthropic/ollama/dry-run)
├── ai_triage.py             # AI-powered vulnerability triage
├── ai_exploit.py            # AI-powered exploit suggestions
│
├── api.py, openapi.py       # REST API server + OpenAPI spec (stdlib; library API)
├── dashboard_server.py      # Live web dashboard (SSE)
├── tui.py                   # Terminal UI dashboard
├── bot.py, notify.py        # Discord/Slack companion bot, webhook notifications
├── distributed.py           # SSH-based distributed scanning
├── plugin.py               # Plugin system
├── interactsh.py            # OOB interaction tracking
├── events.py                # In-process event bus (pub/sub)
├── credentials.py           # Encrypted credential store (library)
├── compliance.py            # PCI DSS / HIPAA / SOC 2 reporting (library)
├── threat_intel.py          # MITRE ATT&CK mapping + threat feeds (library)
├── ml_phase_selector.py, ml_vuln.py   # Phase selection + vuln classification (library)
├── diff.py                  # Scan comparison
├── review.py                # Interactive finding review
├── fleet.py                 # Batch scan runner
├── filter.py                # Finding filtering helpers
├── adapters.py              # Cross-phase result adapters
├── spoof.py                 # Request fingerprint spoofing
├── browser.py               # Browser automation helpers (Playwright)
└── py.typed                 # PEP 561 marker
```

Modules marked *library* exist with full implementations but are not yet wired into the CLI/pipeline; they are invoked programmatically.

## Pipeline Execution Flow

```
 CLI args
    │
    ▼
┌─────────────────┐
│  parse args      │
│  build_parser()  │
└────────┬────────┘
         │
    ▼─────────────────────┐
    │ InteractiveWizard    │  (if --interactive)
    │  → preset selection  │
    │  → phase selection   │
    │  → profile save/load │
    └──────────┬──────────┘
               │
    ▼─────────────────────┐
    │ Config file         │  ./vulnforge.cfg or
    │ (TOML, CLI wins)    │  ~/.config/vulnforge/vulnforge.cfg
    └──────────┬──────────┘
               │
    ▼─────────────────────┐
    │  Tool Detection      │  Tools.have() checks PATH
    │  (cached results)    │  for each required binary
    └──────────┬──────────┘
               │
    ▼─────────────────────┐
    │  DAG Construction    │  Topological sort of PHASE_DEPS
    │  → stage ordering    │  Independent phases grouped
    └──────────┬──────────┘
               │
    ▼─────────────────────┐
    │  Target Profiling    │  (if --no-profile not set)
    │  → size_category     │  small/medium/large/huge
    │  → tech detection    │  Adjusts sampling multipliers
    │  → phase filtering   │  Skips irrelevant phases
    └──────────┬──────────┘
               │
    ▼─────────────────────┐
    │  For each stage:     │
    │  ┌────────────────┐  │
    │  │ asyncio.gather  │  │  Run independent phases in parallel
    │  │ (per-phase)     │  │
    │  │  ├─ RLIMIT      │  │  Per-process resource limits
    │  │  ├─ subprocess  │  │  Tool execution as child process
    │  │  ├─ circuit     │  │  Pause after 3 consecutive failures
    │  │  │   breaker    │  │
    │  │  └─ adaptive    │  │  Scale concurrency by CPU/RAM
    │  │      monitor    │  │
    │  └────────────────┘  │
    │  → state.json        │  Persist after each phase
    │  → event bus emit    │  Notify subscribers
    └──────────┬──────────┘
               │
    ▼─────────────────────┐
    │  Report Generation   │
    │  ├─ summary.json     │
    │  ├─ report.html/md   │
    │  ├─ results.sarif    │  (if --format sarif)
    │  ├─ results.faraday  │
    │  ├─ dashboard.html   │
    │  └─ risk/confidence  │
    └──────────┬──────────┘
               │
    ▼─────────────────────┐
    │  Post-processing     │
    │  ├─ exploit chains   │
    │  ├─ confidence score │
    │  ├─ remediation      │
    │  ├─ AI triage        │  (if --ai-provider set)
    │  └─ audit log        │
    └─────────────────────┘
```

## Data Flow

```
Target domain
    │
    ▼
[00-SCOPE] ──→ scope validation
    │
[01-RECON] ──→ subdomain enumeration
    │
[02-RESOLVE] ─→ DNS resolution ──→ resolved.txt
    │
[03-PERMUTE] ─→ permutation-based subs
    │
[04-SCAN] ───→ port scan + httpx probing ──→ urls_all.txt, tech.txt
    │
[05-HARVEST] ─→ URL/endpoint harvesting
    │
[06-JSINTEL] ─→ JavaScript analysis
    │
[07-PARAMS] ──→ parameter discovery
    │
[08-FUZZ] ────→ directory fuzzing (ffuf)
    │
    ├─→ [09-VULNSCAN] ──→ nuclei scanning
    ├─→ [10-TLSCMS] ───→ TLS/certificate analysis
    ├─→ [11-INJECT] ───→ XSS, SQLi, SSTI
    ├─→ [13-OOB] ──────→ out-of-band testing
    ├─→ [14-ORIGIN] ───→ origin IP discovery
    ├─→ [15-SECRETS] ──→ secret/credential detection
    │
    ... (stages 5-44)
    │
[POST-SCAN]
    ├─→ DedupEngine (cross-phase deduplication)
    ├─→ exploit chain analysis
    ├─→ confidence scoring
    ├─→ risk scoring (A-F grade)
    └─→ report generation (HTML, MD, JSON, SARIF, Faraday)
```

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Zero mandatory dependencies** | Only Python stdlib required. Optional deps (tqdm, openai, anthropic, aiohttp) for enhanced features. |
| **DAG-based execution** | Phases declare dependencies; independent phases run in parallel for maximum throughput. |
| **Resumable** | State persisted to `state.json` after every phase. `--resume` picks up where left off. |
| **Subprocess isolation** | Each tool runs as a subprocess with `RLIMIT_*` resource limits. Circuit breaker pauses after 3 failures. |
| **Event bus** | Components communicate via pub/sub (`EventBus`). No polling or file watching needed. |
| **Artifact registry** | Single source of truth for all ~200 output files. Prevents drift between phases and reports. |
| **Prefix-indexed dedup** | `DedupEngine` uses first-3-char prefix index for O(1) candidate narrowing on 50k+ findings. |
| **Adaptive concurrency** | `AdaptiveThreadSemaphore` scales job count and subprocess limits based on real-time CPU/RAM. |
| **Structured findings** | `Finding` dataclass with CWE, CVSS, severity, remediation, confidence score. |
| **Plugin system** | Custom phases injected into DAG at runtime. Plugins inherit all pipeline features (circuit breaker, adaptive, audit). |

## Security Architecture

```
┌─────────────────────────────────────────────────┐
│                Input Validation                   │
│  ├─ Domain validation (hostname regex)           │
│  ├─ Output path confinement (stays in ./out/)    │
│  ├─ Batch file domain filtering                  │
│  └─ State.json whitelist filtering               │
├─────────────────────────────────────────────────┤
│              Secret Management                    │
│  ├─ PipelineConfig.__repr__ redacts auth fields  │
│  ├─ Auth bearer/api_key/basic/client_cert        │
│  ├─ Cookie sanitization in logging               │
│  └─ No secrets in subprocess env (env= param)    │
├─────────────────────────────────────────────────┤
│              Audit Logging                        │
│  ├─ JSONL structured audit trail                 │
│  ├─ scan_start / phase_complete events           │
│  ├─ Timestamps + phase metadata                  │
│  └─ Configurable enable/disable                  │
├─────────────────────────────────────────────────┤
│              Process Isolation                    │
│  ├─ RLIMIT_NPROC (2048), RLIMIT_FSIZE (512 MB)  │
│  ├─ Core dumps disabled                          │
│  ├─ Circuit breaker (3 failures → pause)         │
│  ├─ Emergency kill below 1 GB free RAM           │
│  └─ Child process cleanup on shutdown            │
└─────────────────────────────────────────────────┘
```

## Test Coverage

- **388+ tests** across 19 test files
- Security tests: repr redaction, input validation, state filtering, audit logging, proxy safety, dedup performance, subprocess safety
- Integration tests: phase integration, mocked subprocess output parsing, data flow, HTTP/DNS cache
- Unit tests: exception hierarchy, CLI package, recon phases, config validation, pipeline DAG, threat intel

## Version History Highlights

**v3.1**
- Modular CLI: `cli/` package (banner, parser, wizard, helpers)
- Modular recon: `phases/recon/` package (8 focused modules)
- 28-class exception hierarchy rooted at `VulnForgeError`
- PipelineConfig validation of 130+ fields at construction
- Structured `Finding` dataclass with CWE/CVSS/severity/remediation/confidence
- SARIF + Faraday reporting, REST API module, rate limiter, auth methods
- Docker: SHA256-verified binaries, non-root user, hardened run notes
- Secret management (`__repr__` redaction), input sanitization, JSONL audit log
- Performance: prefix-indexed dedup, HTTP/DNS response caches

**v3.0**
- Phase catalog expanded to 213 phases across 45 DAG stages
- AI triage, exploit chains, attack surface graphs, target profiling
- Adaptive resource monitor, circuit breaker, safe mode
