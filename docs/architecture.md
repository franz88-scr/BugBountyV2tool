# Architecture

## Overview

ReconChain is a Python-based bug bounty reconnaissance pipeline orchestrator that chains 164 security phases across 27 DAG stages. Given a target domain, it orchestrates 43+ external security tools into a single resumable pipeline.

## Module Structure

```
reconchain/
├── __init__.py              # Package re-exports + docstring
├── cli/                     # CLI package (decomposed from cli.py)
│   ├── __init__.py          # Re-exports: build_parser, main, InteractiveWizard
│   ├── banner.py            # ASCII banner display
│   ├── helpers.py           # main() entry point, _run_single(), dispatch logic
│   ├── parser.py            # ArgumentParser with 9 argument groups
│   └── wizard.py            # Interactive setup wizard (911 lines)
│
├── config.py                # PipelineConfig (130+ fields), phase defs, presets
├── pipeline.py              # DAG executor, state management (1148 lines)
├── process.py               # Subprocess management, circuit breaker, rate limiting
├── utils.py                 # Logging, HTTP helpers, file I/O, caches (1252 lines)
├── tools.py                 # External tool detection (cached binary lookup)
│
├── phases/                  # 164 security phase implementations
│   ├── __init__.py          # PIPELINE list, PHASE_DEPS DAG, STAGES ordering
│   ├── recon/               # Subdomain enumeration, DNS, URL harvesting
│   │   ├── __init__.py      # Re-exports all recon phases
│   │   ├── scope.py         # Domain scope validation
│   │   ├── subdomain.py     # Subdomain enumeration (subfinder, findomain)
│   │   ├── dns.py           # DNS resolution + DNS cache
│   │   ├── scan.py          # Live host detection (httpx)
│   │   ├── harvest.py       # URL/endpoint harvesting
│   │   ├── jsintel.py       # JavaScript analysis
│   │   ├── params.py        # Parameter discovery
│   │   └── osint.py         # OSINT gathering
│   ├── injection.py         # XSS, SQLi, SSTI
│   ├── injection_misc.py    # NoSQLi, XXE, CMDi, SSRF
│   ├── auth.py              # JWT, OAuth, IDOR, session
│   ├── auth_bypass.py       # CSRF, SAML, forced browse
│   ├── client_side.py       # Cache poison, CORS, clickjack, CRLF
│   ├── encoding.py          # SSI, null byte, unicode bypasses
│   ├── fuzzing.py           # ffuf, WAF detect/bypass
│   ├── smuggling.py         # HTTP/2 smuggling, race conditions
│   ├── vuln_scan.py         # Nuclei, TLS, OOB
│   ├── network.py           # RFI, WebDAV, SNMP
│   ├── third_party.py       # SRI, HSTS, mixed content
│   ├── origin_cloud.py      # Origin IP, cloud buckets
│   ├── secrets_git.py       # Secrets, git exposure
│   ├── web_infra.py         # CDN, CSP, file upload
│   ├── email_misc.py        # Email sec, SMTP, workflow
│   └── infra.py             # Backward-compat re-export shim
│
├── exceptions.py            # 28-class exception hierarchy
├── audit.py                 # Structured JSONL audit logging
├── dedup.py                 # Cross-phase deduplication (prefix-indexed)
│
├── finding.py               # Structured Finding dataclass
├── remediation.py           # CWE-to-fix mappings (25 vuln types)
├── severity.py              # Risk scoring (A-F grades)
├── artifacts.py             # Artifact registry, severity classification
├── confidence.py            # Finding confidence scoring
├── exploit_chain.py         # Cross-phase exploit chain analysis
│
├── api.py                   # REST API server (stdlib http.server)
├── ratelimiter.py           # Token-bucket rate limiter
├── ratelimit.py             # Per-tool rate limiting
├── reporting.py             # HTML, Markdown, JSON, SARIF, Faraday reports
│
├── ai.py                    # LLM provider abstraction
├── ai_triage.py             # AI-powered vulnerability triage
├── ai_exploit.py            # AI-powered exploit suggestions
│
├── attack_surface.py        # Attack surface graph generation
├── bot.py                   # Discord/Slack companion bot
├── dashboard_server.py      # Live web dashboard (SSE)
├── tui.py                   # Terminal UI dashboard
│
├── events.py                # In-process event bus (pub/sub)
├── plugin.py                # Plugin/extension system
├── distributed.py           # SSH-based distributed scanning
├── interactsh.py            # OOB interaction tracking
├── learning.py              # False-positive learning
├── monitor.py               # Scheduled re-scan
├── notify.py                # Slack/Discord/Telegram notifications
├── poc.py                   # Auto-PoC generation
├── review.py                # Interactive finding review
├── target_profile.py        # Target profiling + auto-tuning
├── tool_health.py           # Tool health monitoring
├── useragent.py             # User-agent rotation
└── verify.py                # Output verification/filtering
```

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
    │  ├─ report.html      │
    │  ├─ report.md        │
    │  ├─ results.sarif    │  (if --format sarif)
    │  ├─ dashboard.html   │  (if --dashboard)
    │  └─ risk_score.json  │
    └──────────┬──────────┘
               │
    ▼─────────────────────┐
    │  Post-processing     │
    │  ├─ exploit chains   │
    │  ├─ confidence score │
    │  ├─ remediation      │
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
[02-RESOLVE] ─→ DNS resolution ──→ live_hosts.txt
    │
[03-PERMUTE] ─→ permutation-based subs
    │
[04-SCAN] ───→ httpx probing ──→ urls_all.txt, tech.txt
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
    ... (stages 12-27)
    │
[POST-SCAN]
    ├─→ DedupEngine (cross-phase deduplication)
    ├─→ exploit chain analysis
    ├─→ confidence scoring
    ├─→ risk scoring (A-F grade)
    └─→ report generation (HTML, MD, JSON, SARIF)
```

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Zero mandatory dependencies** | Only Python stdlib required. Optional deps (tqdm, openai, anthropic, aiohttp) for enhanced features. |
| **DAG-based execution** | Phases declare dependencies; independent phases run in parallel for maximum throughput. |
| **Resumable** | State persisted to `state.json` after every phase. `--resume` picks up where left off. |
| **Subprocess isolation** | Each tool runs as a subprocess with `RLIMIT_*` resource limits. Circuit breaker pauses after 3 failures. |
| **Event bus** | Components communicate via pub/sub (`EventBus`). No polling or file watching needed. |
| **Artifact registry** | Single source of truth for all 150+ output files. Prevents drift between phases and reports. |
| **Prefix-indexed dedup** | `DedupEngine` uses first-3-char prefix index for O(1) candidate narrowing on 50k+ findings. |
| **Adaptive concurrency** | `AdaptiveThreadSemaphore` scales job count and subprocess limits based on real-time CPU/RAM. |
| **Structured findings** | `Finding` dataclass with CWE, CVSS, severity, remediation, confidence score. |
| **Plugin system** | Custom phases injected into DAG at runtime. Plugins inherit all pipeline features (circuit breaker, adaptive, audit). |

## Security Architecture

```
┌─────────────────────────────────────────────────┐
│                Input Validation                   │
│  ├─ Domain validation (_is_valid_hostname)        │
│  ├─ Output path confinement (stays in ./out/)     │
│  ├─ Batch file domain filtering                   │
│  └─ State.json whitelist filtering                │
├─────────────────────────────────────────────────┤
│              Secret Management                    │
│  ├─ PipelineConfig.__repr__ redacts auth fields   │
│  ├─ Auth bearer/api_key/basic/client_cert         │
│  ├─ Cookie sanitization in logging                │
│  └─ No secrets in subprocess env (env= param)     │
├─────────────────────────────────────────────────┤
│              Audit Logging                        │
│  ├─ JSONL structured audit trail                  │
│  ├─ scan_start / phase_complete events            │
│  ├─ Timestamps + phase metadata                   │
│  └─ Configurable enable/disable                   │
├─────────────────────────────────────────────────┤
│              Process Isolation                    │
│  ├─ RLIMIT_NPROC, RLIMIT_AS, RLIMIT_NOFILE       │
│  ├─ Per-process resource limits                   │
│  ├─ Circuit breaker (3 failures → pause)          │
│  └─ Child process cleanup on shutdown             │
└─────────────────────────────────────────────────┘
```

## Test Coverage

- **183 tests** across 8 test files
- Security tests: repr redaction, input validation, state filtering, audit logging, proxy safety, dedup performance, subprocess safety
- Integration tests: phase integration, mocked subprocess output parsing, data flow, HTTP/DNS cache
- Unit tests: exception hierarchy, CLI package, recon phases, config validation, pipeline DAG

## New in v3.1

- **Modular CLI**: `cli.py` decomposed into `cli/` package (banner, parser, wizard, helpers)
- **Modular Recon**: `recon.py` decomposed into `phases/recon/` package (8 focused modules)
- **28-class Exception Hierarchy**: Typed exceptions for every failure mode
- **PipelineConfig Validation**: `__post_init__` validates all 130+ fields at construction
- **Binary Hash Verification**: Dockerfile SHA256 ARGs for reproducible builds
- **Docker Security**: Non-root user, hardened run notes
- **Secret Management**: `__repr__` redaction for auth fields
- **Input Sanitization**: Domain validation, output path confinement
- **Audit Logging**: Structured JSONL audit trail
- **Performance**: Prefix-indexed dedup, HTTP response cache, DNS cache, memory optimizations
- **Developer Experience**: Argument groups in `--help`, epilog with examples, 9 docstring improvements
