```markdown
<div align="center">

# 🔥 VulnForge

**Resumable bug-bounty pipeline orchestrator.**  
213 phases · 45 DAG stages · 40+ tools · zero core Python dependencies

[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED.svg?logo=docker&logoColor=white)](Dockerfile)
[![Tests](https://img.shields.io/badge/tests-435%2B%20passing-brightgreen.svg)](#development)
[![Version](https://img.shields.io/badge/version-3.1.0-blue.svg)](CHANGELOG.md)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-success.svg)](CONTRIBUTING.md)
[![Security: responsible use](https://img.shields.io/badge/responsible%20use-required-orange.svg)](#responsible-use)

Run a full recon-to-report pipeline in a single command.  
Resume where you left off. Don't melt your box.

</div>

---

> **Naming note:** This repository is historically named `BugBountyV2tool`.  
> The package and CLI are called **`vulnforge`** (the old `reconchain` command is kept as an alias).

---

## Why VulnForge?

Every bug bounty hunter runs roughly the same tools in roughly the same order.  
Yet most recon sessions still end as a mess of half-finished scripts, dead terminals, and lost progress after a Ctrl-C.

**VulnForge is the orchestrator you keep writing for yourself and never quite finish.**

- 🔁 **Resumable** — State is written to `state.json` after every phase. Kill the process, the VM, or the laptop. Resume with `--resume`.
- 🧠 **DAG-ordered** — 213 phases across 45 stages with explicit dependencies. Independent phases run in parallel.
- 🛡️ **Resource-safe by default** — Process limits, adaptive CPU/RAM monitor, circuit breaker, emergency kill. Designed to run on a 4 GB VPS.
- 📦 **Stdlib-first** — Core path has **zero mandatory third-party Python dependencies**. Tools are auto-detected on `PATH` and missing ones are skipped.
- 📊 **Reports that humans read** — HTML dashboard, Markdown, JSON, SARIF, Faraday. Optional AI triage (off by default).

---

## Quick Start

```bash
git clone https://github.com/franz88-scr/BugBountyV2tool.git
cd BugBountyV2tool
./install.sh                       # installs 40+ external recon tools
python3 -m pip install -e .
vulnforge -d example.com           # full pipeline
```

That’s it. The scan runs, state is persisted after every phase, and you get HTML + Markdown + SARIF + Faraday + a self-contained `dashboard.html` when it finishes.

### Common variants

```bash
vulnforge -d example.com --fast              # 5 essential recon phases only
vulnforge -d example.com --profile quick     # skips ~37 low-signal / redundant phases
vulnforge -d example.com --safe              # conservative mode for VMs / containers
vulnforge -d example.com --resume            # continue exactly where you stopped
vulnforge -i                                 # interactive wizard (presets + phase selection)
```

---

## Features

| Category         | What you get |
|------------------|--------------|
| **Pipeline**     | 213 phases · 45 DAG stages · parallel execution · state after every phase · `--resume` · `--force` |
| **Tools**        | subfinder, nuclei, httpx, naabu, ffuf, sqlmap, dalfox, katana, gau, waymore, trufflehog, gitleaks, testssl, nmap, massdns, dnsx, alterx, xnLinkFinder, SecretFinder, wafw00f, inql, arjun, corsy, commix, wpscan, interactsh, gowitness, cloudfox, and many more — all auto-detected |
| **Reports**      | HTML · Markdown · JSON · SARIF · Faraday JSONL · self-contained `dashboard.html` |
| **Compliance**   | PCI-DSS v4.0 · HIPAA · SOC 2 (`--compliance`) |
| **Threat intel** | MITRE ATT&CK mapping · threat-feed IOCs (`--threat-intel`) |
| **Triage**       | Rule-based classification with confidence scores · optional AI triage (OpenAI / Anthropic / Ollama) |
| **Extras**       | Attack-surface graph · exploit-chain analysis · scan diffing · encrypted credential store · REST API · live web dashboard · Discord/Slack/Telegram notifications · OOB via interactsh · custom plugins |

---

## How the pipeline works

VulnForge is **not a scanner itself** — it is an **orchestrator**.

It chains 40+ external tools into a single resumable pipeline with explicit dependencies, parallel execution, resource limits, and structured reporting. The core path is stdlib-only: no mandatory third-party Python libraries.

### Startup flow

```
CLI (vulnforge -d example.com)
    │
    ▼
Config load (CLI flags > vulnforge.cfg > defaults)
    │
    ▼
Optional interactive wizard (-i)
    │
    ▼
run_pipeline()
    ├── Preflight RAM check
    ├── Create output directory
    ├── Load state.json (if --resume)
    ├── Detect tools on PATH
    ├── Apply --fast / --profile / --only / --skip / --dos
    ├── Start adaptive resource monitor
    │
    └── Execute stages (45 total)
            │
            └── Post-scan: dedup → exploit chains → scoring → reports
```

### Building blocks

| Concept | Meaning |
|---------|---------|
| **Phase** | One async unit of work (e.g. `01-RECON`, `09-VULNSCAN`, `11b-SQLMAP`). There are **213** phases. |
| **Stage** | A group of independent phases that can run in parallel. There are **45** stages. The next stage starts only after the current one finishes. |
| **Dependency (DAG)** | Each phase declares what it needs. The orchestrator builds the order and parallel groups from `PHASE_DEPS`. |
| **Artifact** | Output files exchanged between phases (`resolved.txt`, `urls_all.txt`, …). Tracked in a central registry. |
| **State** | `state.json` written after every phase — the basis for `--resume`. |

### Data flow (simplified)

```
example.com
    │
    ▼
00-SCOPE          → validate target scope
    │
01-RECON          → subdomain enumeration (subfinder, findomain, alterx, …)
    │
02-RESOLVE        → DNS resolution → resolved / live hosts
    │
03-PERMUTE        → subdomain permutations
04-SCAN           → ports + httpx → urls_all.txt, tech.txt
21-WAF            → WAF detection
    │
05-HARVEST        → URL collection (gau, katana, waymore, …)
06-JSINTEL        → JavaScript analysis & secrets
07-PARAMS         → parameter discovery (arjun)
08-FUZZ           → endpoint fuzzing (ffuf)
    │
    ├── 09-VULNSCAN   (nuclei)
    ├── 10-TLSCMS
    ├── 11-INJECT / 11a-DOMXSS / 11b-SQLMAP
    ├── 14-ORIGIN / 15-SECRETS / 18-CLOUD / …
    └── further parallel clusters across remaining stages
    │
POST-SCAN
    ├── DedupEngine
    ├── Exploit-chain analysis
    ├── Confidence & risk scoring
    ├── Optional AI triage
    └── Reports (HTML, MD, JSON, SARIF, Faraday, dashboard.html)
```

### What a single phase does

1. Check `only` / `skip` — skip if not selected
2. Check existing output — skip if already present (unless `--force`)
3. Read required input artifacts from previous phases
4. Run external tools as subprocesses (with RLIMIT, timeout, rate limit, optional proxy)
5. Write results to artifact files
6. Return metadata (paths + counts) and persist state

Missing tools are skipped gracefully — the pipeline continues with whatever is available on `PATH`.

### State & resume

After **every** phase, VulnForge updates `state.json` with:

- domain
- existing artifacts
- missing tools
- tool failures

On `--resume`:

1. Load `state.json`
2. Verify domain matches
3. Rebase artifact paths to the current output directory
4. Skip phases whose outputs already exist (unless `--force`)

You can kill the process mid-scan and continue later without redoing finished work.

### Resource control

| Mechanism | Role |
|-----------|------|
| Adaptive semaphore | Scales concurrency up/down based on CPU and free RAM |
| `--safe` | Forces low concurrency and stricter limits for VMs |
| Circuit breaker | Pauses a phase after consecutive real subprocess failures |
| Preflight check | Aborts early if the system has too little RAM |
| Emergency kill | Terminates child processes when free RAM becomes critical |
| Rate limiting | Global and per-domain (`--rate-limit`, `--rate-limit-per-domain`, `--delay`) |
| DoS phases | Off by default (`DOS_PHASES`); require `--dos` |

### How flags change the pipeline

| Flag / profile | Effect |
|----------------|--------|
| `--fast` | Runs only `FAST_PHASES`: 00-SCOPE, 01-RECON, 02-RESOLVE, 04-SCAN, 05-HARVEST |
| `--profile quick` | Adds ~37 low-signal phases to `skip` |
| `--profile full` | Full pipeline (default) |
| `--safe` | Reduced concurrency and sample sizes |
| `--only A,B` | Run only these phases (overrides conflicting skips) |
| `--skip A,B` | Explicitly exclude phases |
| (no `--dos`) | All DoS-style phases are automatically skipped |
| `--resume` | Continue from `state.json` |
| `--force` | Re-run phases even if outputs already exist |

Full module layout and design decisions:  
→ [`docs/architecture.md`](docs/architecture.md)

---

## Installation

### Prerequisites

- Python **3.9+**
- Linux or macOS (Windows via WSL2 recommended)
- `git` (and optionally `make`)

### Option 1 – Local

```bash
git clone https://github.com/franz88-scr/BugBountyV2tool.git
cd BugBountyV2tool
python3 -m pip install -e ".[dev]"
./install.sh
```

`install.sh` installs the external tools. Useful flags:

```bash
./install.sh --check      # only report what is missing
./install.sh --go-only    # only Go-based tools
./install.sh --py-only    # only Python-based tools
```

VulnForge detects what is available on `PATH` and skips the rest.

### Option 2 – Docker (recommended for production)

```bash
docker build -t vulnforge .
docker compose run --rm vulnforge -d example.com
```

The image is hardened:

- non-root user
- dropped capabilities (`cap_drop: ALL`, only `NET_RAW` added)
- read-only filesystem + tmpfs for `/tmp`
- 8 GB memory limit / 2 CPU limit
- SHA256 verification support for downloaded binaries

### Optional extras

```bash
pip install -e ".[progress]"   # tqdm progress bars
pip install -e ".[ai]"         # OpenAI + Anthropic SDKs
pip install -e ".[bot]"        # Discord / Slack companion bot
pip install -e ".[all]"        # everything above
```

Core package has **no required runtime dependencies** (`dependencies = []` in `pyproject.toml`).

---

## Usage Examples

### Basic

```bash
vulnforge -d example.com
vulnforge -d example.com --fast
vulnforge -d example.com --resume
vulnforge -d example.com --force          # re-run even if outputs exist
```

### Profiles & modes

```bash
vulnforge -d example.com --profile quick  # skip low-signal phases
vulnforge -d example.com --profile full   # everything (default behaviour)
vulnforge -d example.com --safe           # reduced concurrency & sample sizes
vulnforge -i                              # interactive wizard
vulnforge --dry-run -d example.com
```

### Advanced

```bash
# Multi-target batch
vulnforge --batch targets.txt

# SOCKS5 through Tor
vulnforge -d example.com --proxy socks5://127.0.0.1:9050

# IDOR cross-session diffing
vulnforge -d example.com --cookie-a 'session=u1' --cookie-b 'session=u2'

# Attack-surface graph
vulnforge -d example.com --attack-graph

# Diff two previous scans
vulnforge --compare ./out/scan-a ./out/scan-b

# Load custom phases
vulnforge -d example.com --plugins-dir ./my-phases

# Run only selected phases
vulnforge -d example.com --only 01-RECON,02-RESOLVE,04-SCAN
```

---

## Configuration & Profiles

Configuration is loaded in this order (later wins):

1. CLI flags
2. `./vulnforge.cfg`
3. `~/.config/vulnforge/vulnforge.cfg`

### CLI profiles (`--profile`)

| Value   | Effect |
|---------|--------|
| `quick` | Skips ~37 redundant / low-signal phases (see `QUICK_SKIP_PHASES`) |
| `full`  | Full pipeline (default) |

### Interactive wizard presets (`vulnforge -i`)

| Preset     | Description |
|------------|-------------|
| `quick`    | Scope → Subs → DNS → Ports/HTTP → URLs (~5 min) |
| `standard` | Balanced assessment with common vuln phases (~15 min) |
| `full`     | All 213 phases |
| `stealth`  | Polite recon with rate limiting |
| `pentest`  | Standard + injection + auth bypass + client-side |
| `osint`    | Passive / OSINT-focused phases |

---

## After the scan

A typical output directory contains:

| Artifact              | Description |
|-----------------------|-------------|
| `dashboard.html`      | Self-contained interactive report |
| `report.md` / `.html` | Human-readable summary |
| `summary.json`        | Machine-readable results |
| `results.sarif`       | SARIF for CI / GitHub code scanning |
| Faraday JSONL         | Import into Faraday |
| `state.json`          | Resume state |
| `audit.jsonl`         | Structured audit log of every phase |

Optional post-processing (AI triage, exploit-chain analysis, compliance reports) runs only when explicitly enabled.

---

## Safety

VulnForge performs **active scanning**. It is designed to be left running unattended on modest hardware:

- Per-tool process limits (`RLIMIT_NPROC`, `RLIMIT_FSIZE`, core dumps disabled)
- Adaptive CPU/RAM monitor with emergency kill when free RAM is critically low
- Circuit breaker (pauses a phase after consecutive real subprocess failures)
- Per-phase timeouts (shorter in `--safe` mode)
- Rate limiting (`--rate-limit`, `--rate-limit-per-domain`, `--delay`)
- Proxy support (`--proxy` for all phases, `--vuln-proxy` for vuln phases only)
- Secret redaction and input sanitization
- Structured audit log (`audit.jsonl`)
- **DoS-style phases are off by default** and require `--dos`  
  (race bursts, request smuggling, GraphQL depth attacks, H2 rapid reset, credential spray, …)

---

## Responsible Use

> **VulnForge performs active scanning against live targets.**  
> Only use it against systems you own or are explicitly authorized to test.

By running VulnForge you agree that:

- You have **written authorization** for every target you scan.
- You will not exceed the authorized scope.
- You will treat all findings and any collected credentials as confidential.
- You will disclose findings only through the program’s responsible-disclosure process.

The operator — not the tool — is responsible for complying with all applicable laws and the rules of engagement of any bug-bounty program.

Distributed under the **MIT license** with no warranty. Misuse is solely the responsibility of the user.  
See [`LICENSE`](LICENSE).

---

## Development

```bash
python3 -m pip install -e ".[dev]"

pytest tests/ -v                  # full test suite
ruff check vulnforge/ && ruff format --check vulnforge/
mypy vulnforge/
make ci                           # lint + typecheck + test
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for setup, code style, and the PR process.

---

## Documentation

| Document | Content |
|----------|---------|
| [`docs/architecture.md`](docs/architecture.md) | Module structure, pipeline flow, design decisions |
| [`docs/api.md`](docs/api.md) | REST API and programmatic usage |
| [`docs/plugins.md`](docs/plugins.md) | Writing custom phases |
| [`docs/events.md`](docs/events.md) | Event bus reference |
| [`docs/phase-classification.md`](docs/phase-classification.md) | What each phase actually does |
| [`CHANGELOG.md`](CHANGELOG.md) | Version history |

---

## FAQ

**What happens if some tools are missing?**  
They are skipped. VulnForge continues with the tools that are available on `PATH`.

**Can I stop a scan and continue later?**  
Yes. Use `--resume`. State is written after every phase.

**How do I reduce resource usage?**  
Use `--safe`, `--fast`, or `--profile quick`. You can also lower concurrency with `-j` / adaptive settings.

**Why is the repository named differently from the tool?**  
Historical reasons. The package and CLI have been `vulnforge` since the 3.x series. The old `reconchain` entry point still works as an alias.

**Is this only for authorized testing?**  
Yes. Active scanning without authorization is illegal in most jurisdictions. See [Responsible Use](#responsible-use).

---

## Contributing

PRs are welcome, especially:

- New phase implementations
- Heuristics that **reduce** false positives
- Real-world findings discovered with VulnForge (write-ups encouraged)
- Bug reports against specific phases
- Documentation improvements

Open an issue first for larger changes.  
See [`CONTRIBUTING.md`](CONTRIBUTING.md).

---

## License

MIT — see [`LICENSE`](LICENSE).

---

<div align="center">

**Built by hunters who got tired of restarting `nmap` at 3 a.m.**

⭐ Star it if it saved you a bash script.  
🐛 Open an issue if it broke one.

</div>
```