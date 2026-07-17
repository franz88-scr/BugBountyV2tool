# Architecture

## Overview

ReconChain is a Python-based bug bounty reconnaissance pipeline orchestrator that chains 164 security phases across 26+ DAG stages. Given a target domain, it orchestrates 45+ external security tools into a single resumable pipeline.

## Module Structure

```
reconchain/
├── __init__.py              # Package re-exports
├── cli.py                   # CLI parser + InteractiveWizard
├── config.py                # PipelineConfig, phase definitions, presets
├── pipeline.py              # DAG executor, state management
├── process.py               # Subprocess management, circuit breaker
├── utils.py                 # Logging, HTTP helpers, file I/O
├── tools.py                 # External tool detection
│
├── phases/                  # 164 security phase implementations
│   ├── __init__.py          # PIPELINE list, PHASE_DEPS DAG, STAGES
│   ├── helpers.py           # Shared constants and utilities
│   ├── recon.py             # Subdomain enumeration, DNS, URL harvesting
│   ├── injection.py         # XSS, SQLi, SSTI
│   ├── auth.py              # JWT, OAuth, IDOR, session
│   ├── auth_bypass.py       # CSRF, SAML, forced browse
│   ├── client_side.py       # Cache poison, CORS, clickjack, CRLF
│   ├── encoding.py          # SSI, null byte, unicode bypasses
│   ├── fuzzing.py           # ffuf, WAF detect/bypass
│   ├── smuggling.py         # HTTP/2 smuggling, race conditions
│   ├── vuln_scan.py         # Nuclei, TLS, OOB
│   ├── network.py           # RFI, WebDAV, SNMP
│   ├── third_party.py       # SRI, HSTS, mixed content
│   ├── extended.py          # Email finder, metagoofil, crt.sh
│   ├── cms.py               # IIS, Tomcat, Laravel, Django
│   ├── cloud.py             # CI/CD, Docker, K8s, vhost
│   ├── origin_cloud.py      # Origin IP, cloud buckets [NEW]
│   ├── secrets_git.py       # Secrets, git exposure [NEW]
│   ├── graphql_chain.py     # GraphQL, chain correlation [NEW]
│   ├── injection_misc.py    # NoSQLi, XXE, CMDi, SSRF [NEW]
│   ├── web_infra.py         # CDN, CSP, file upload [NEW]
│   ├── email_misc.py        # Email sec, SMTP, workflow [NEW]
│   └── infra.py             # Backward-compat re-export shim
│
├── finding.py               # Structured Finding dataclass [NEW]
├── remediation.py           # CWE-to-fix mappings [NEW]
├── api.py                   # REST API server [NEW]
├── ratelimiter.py           # Token-bucket rate limiter [NEW]
├── reporting.py             # HTML, Markdown, JSON, SARIF reports
├── severity.py              # Risk scoring (A-F grades)
├── artifacts.py             # Artifact registry, severity classification
├── confidence.py            # Finding confidence scoring
├── exploit_chain.py         # Cross-phase exploit chain analysis
├── ai.py                    # LLM provider abstraction
├── ai_triage.py             # AI-powered vulnerability triage
├── ai_exploit.py            # AI-powered exploit suggestions
├── attack_surface.py        # Attack surface graph generation
├── bot.py                   # Discord/Slack companion bot
├── dashboard_server.py      # Live web dashboard (SSE)
├── tui.py                   # Terminal UI dashboard
├── dedup.py                 # Cross-phase deduplication
├── distributed.py           # SSH-based distributed scanning
├── events.py                # In-process event bus
├── interactsh.py            # OOB interaction tracking
├── learning.py              # False-positive learning
├── monitor.py               # Scheduled re-scan
├── notify.py                # Slack/Discord/Telegram notifications
├── plugin.py                # Plugin/extension system
├── poc.py                   # Auto-PoC generation
├── ratelimit.py             # Per-tool rate limiting
├── review.py                # Interactive finding review
├── target_profile.py        # Target profiling
├── tool_health.py           # Tool health monitoring
├── useragent.py             # User-agent rotation
└── verify.py                # Output verification/filtering
```

## Pipeline Execution Flow

```
1. CLI parses args → PipelineConfig
2. InteractiveWizard (if --interactive)
3. Tool detection (Tools.has())
4. DAG construction from PHASE_DEPS
5. Topological sort → stage ordering
6. For each stage:
   a. Run independent phases concurrently (asyncio.gather)
   b. Per-phase resource limits (RLIMIT)
   c. Global process counter (AdaptiveThreadSemaphore)
   d. Circuit breaker pauses after 3 consecutive failures
   e. Adaptive monitor scales concurrency based on CPU/RAM
   f. State persisted to state.json after each phase
7. Report generation (HTML, Markdown, JSON, SARIF, Faraday)
8. Risk scoring, confidence scoring, exploit chain analysis
```

## Key Design Decisions

- **Zero mandatory dependencies**: Uses only Python stdlib by default
- **DAG-based execution**: Phases declare dependencies; independent phases run in parallel
- **Resumable**: State persisted after every phase; `--resume` picks up where left off
- **Subprocess isolation**: Each tool runs as a subprocess with resource limits
- **Event bus**: Components communicate via pub/sub (EventBus)
- **Artifact registry**: Single source of truth for all output files

## New in v3.1

- **Structured Findings**: `Finding` dataclass with CWE, CVSS, severity, remediation
- **REST API**: `--api-port` starts HTTP API for querying findings
- **Rate Limiter**: Global + per-domain token-bucket rate limiting
- **Auth Methods**: `--auth-bearer`, `--auth-api-key`, `--auth-basic`, `--auth-client-cert`
- **Remediation Guidance**: 25+ CWE-to-fix mappings for all vuln types
- **Modular Phases**: `infra.py` split into 6 focused modules
- **Docker Multi-stage**: ~40% smaller images, proper health checks
- **Expanded Tests**: 184 tests (from 46)
