<div align="center">

# 🔥 VulnForge

### A stdlib-first Python orchestrator that chains 40+ bug-bounty tools into one resumable, safe, observable pipeline.

**Run a full recon-to-report pipeline in a single command. Resume where you left off. Don't melt your box.**

[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED.svg?logo=docker&logoColor=white)](Dockerfile)
[![Tests](https://img.shields.io/badge/tests-435%2B%20passing-brightgreen.svg)](#development)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-success.svg)](CONTRIBUTING.md)
[![Security: responsible use](https://img.shields.io/badge/responsible%20use-required-orange.svg)](#responsible-use)

**vulnforge** is what happens when you stop writing bash glue between `subfinder`, `nuclei`, `httpx`, `naabu`, `ffuf`, `sqlmap`, `dalfox`, and `katana` — and start running them as one DAG with proper state, resource caps, circuit breakers, and report generation.

</div>

---

## ⚡ 30-second start

```bash
git clone https://github.com/franz88-scr/BugBountyV2tool.git
cd BugBountyV2tool
./install.sh                       # installs 40+ recon tools
vulnforge -d example.com           # full pipeline
```

That's it. Scan runs, state is persisted after every phase, and you get HTML + Markdown + SARIF + Faraday + a self-contained dashboard when it's done.

Want something faster?

```bash
vulnforge -d example.com --fast              # 5-phase quick recon
vulnforge -d example.com --profile quick     # full pipeline minus low-signal noise
vulnforge -d example.com --safe              # conservative mode for VMs/containers
vulnforge -d example.com --resume            # pick up exactly where you stopped
```

---

## 🤔 Why VulnForge?

Every bug bounty hunter runs the same 12 tools in roughly the same order. So why is every recon session still a mess of half-finished scripts, dead terminals, and `nmap` scans you lost to a Ctrl-C?

**VulnForge is the orchestrator you keep writing for yourself and never quite finish.**

- 🔁 **Resumable** — kill the VM, kill the laptop, hit a rate limit? Resume from `state.json` after every single phase.
- 🧠 **DAG-ordered** — 213 phases across 45 stages, with explicit dependencies. No more "I ran nuclei before httpx resolved hosts."
- 🛡️ **Resource-safe by default** — `RLIMIT_NPROC`, `RLIMIT_FSIZE`, adaptive CPU/RAM monitor, circuit breaker, emergency kill. Run it on a 4 GB VPS without crying.
- 📦 **40+ tools, zero Python deps for the core** — stdlib-first. Detects what's on `PATH`, skips what's not. No dependency rot.
- 📊 **Reports that humans read** — HTML dashboard, Markdown, JSON, SARIF for CI, Faraday for your team's platform.
- 🤖 **AI triage if you want it** — OpenAI, Anthropic, or local Ollama, off by default, post-scan only.
- 🧩 **Pluggable** — drop a custom phase in `./plugins/` and it joins the DAG.
- 🌐 **Distributed** — SSH-driven multi-host orchestration for those large engagements.

---

## ✨ Features

| Category | What you get |
|---|---|
| **Pipeline** | 213 phases · 45 DAG stages · parallel execution · state after every phase · `--resume` |
| **Tools** | subfinder, nuclei, httpx, naabu, ffuf, sqlmap, dalfox, katana, gau, waymore, trufflehog, gitleaks, testssl, nmap, massdns, dnsx, alterx, xnLinkFinder, SecretFinder, wafw00f, inql, arjun, corsy, commix, wpscan, interactsh, gowitness, cloudfox, and 15+ more — all auto-detected |
| **Reports** | HTML · Markdown · JSON · SARIF · Faraday JSONL · self-contained `dashboard.html` |
| **Compliance** | PCI-DSS v4.0 · HIPAA · SOC 2 (one flag: `--compliance`) |
| **Threat intel** | MITRE ATT&CK mapping · threat-feed IOCs (`--threat-intel`) |
| **Triage** | Rule-based classification with confidence scores · AI triage (opt-in) |
| **Extras** | Attack-surface graph · exploit-chain analysis · scan diffing · encrypted credential store · REST API · web dashboard · Discord/Slack/Telegram notifications · OOB via interactsh |

---

## 🏗️ Architecture

```
vulnforge/
├── pipeline.py             # DAG executor, state, orchestration
├── process.py              # Subprocess + RLIMIT + circuit breaker + rate limit
├── resource_monitor.py     # Adaptive CPU/RAM scaling
├── phases/                 # 213 phase implementations
├── reporting.py            # HTML / MD / JSON / SARIF / Faraday
├── exploit_chain.py        # Cross-phase attack-path detection
├── attack_surface.py       # Host/asset graph generator
├── ai.py                   # OpenAI / Anthropic / Ollama
├── compliance.py           # PCI / HIPAA / SOC 2
├── plugin.py               # Custom-phase loader
└── ... 40+ modules, 435+ tests
```

**Design choice: stdlib-first.** No `requests`, no `httpx`, no `aiohttp` for the core path. Less to break, easier to audit, runs anywhere.

---

## 📦 Install

### Option 1: local

```bash
git clone https://github.com/franz88-scr/BugBountyV2tool.git
cd BugBountyV2tool
python3 -m pip install -e ".[dev]"
./install.sh
```

### Option 2: Docker (recommended for production)

```bash
docker build -t vulnforge .
docker compose run --rm vulnforge -d example.com
```

The image is hardened: non-root user, dropped capabilities, SHA256-verified binaries, 8 GB memory cap, read-only filesystem.

### Optional extras

```bash
pip install -e ".[progress]"   # tqdm progress bars
pip install -e ".[ai]"         # OpenAI + Anthropic SDKs
pip install -e ".[bot]"        # Discord/Slack companion bot
pip install -e ".[all]"        # everything
```

---

## 🧪 Examples

```bash
# Multi-target batch
vulnforge --batch targets.txt

# SOCKS5 through Tor
vulnforge -d example.com --proxy socks5://127.0.0.1:9050

# IDOR diffing with two sessions
vulnforge -d example.com --cookie-a 'session=u1' --cookie-b 'session=u2'

# Attack-surface graph
vulnforge -d example.com --attack-graph

# Diff two scans
vulnforge --compare ./out/scan-a ./out/scan-b

# Run a plugin-loaded custom phase
vulnforge -d example.com --plugins-dir ./my-phases

# Dry-run to preview what would execute
vulnforge --dry-run -d example.com
```

---

## 🛡️ Safety

VulnForge performs **active scanning**. It is built to be safe enough to leave running unattended on a production-ish box:

- **Per-tool process limits** — `RLIMIT_NPROC` 2048, `RLIMIT_FSIZE` 512 MB, core dumps disabled
- **Adaptive monitor** — scales concurrency up when CPU < 50% and > 2 GB RAM free, scales down aggressively, emergency-kills children below 1 GB free
- **Circuit breaker** — pauses a phase after 3 consecutive real subprocess failures
- **Per-phase timeout** — 7200s (1800s in `--safe`)
- **Rate limiting** — `--rate-limit`, `--rate-limit-per-domain`, `--delay`
- **Proxy** — `--proxy` (all phases) and `--vuln-proxy` (vuln phases only)
- **Secret redaction** — credentials stripped from `repr` and not exported to subprocess env
- **Input sanitization** — hostname validation, output path confinement, batch file filtering, state whitelist
- **Audit log** — every scan start and per-phase event in `audit.jsonl`
- **DoS-style phases are off by default** — race bursts, request smuggling, GraphQL depth attacks, H2 rapid reset, credential spray all gated behind `--dos`

---

## ⚖️ Responsible Use

> **VulnForge performs active scanning against live targets. Only use it against systems you own or are explicitly authorized to test.**

By running VulnForge you agree that:

- You have **written authorization** for every target you scan.
- You will not exceed the authorized scope (avoid `--dos` on production systems unless explicitly permitted, and respect rate limits).
- You will handle all findings and any credentials collected by the tool **confidentially**, and disclose them only through the program's responsible-disclosure process.

The operator — not the tool — is responsible for complying with all applicable laws and the rules of engagement of any bug-bounty program.

Distributed under the **MIT license** with no warranty. See [`LICENSE`](LICENSE) for the full text. Misuse is solely the responsibility of the user.

---

## 🧑‍💻 Development

```bash
python3 -m pip install -e ".[dev]"

pytest tests/ -v                  # 435+ tests across 24 files
ruff check vulnforge/ && ruff format --check vulnforge/
mypy vulnforge/
make ci                           # full CI suite
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the dev setup, code style, and PR process.

---

## 📚 Docs

| Document | What it covers |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Module structure, pipeline flow, data flow |
| [`docs/api.md`](docs/api.md) | REST API endpoints + programmatic usage |
| [`docs/plugins.md`](docs/plugins.md) | Writing custom phases |
| [`docs/events.md`](docs/events.md) | Event bus reference for real-time streaming |
| [`docs/phase-classification.md`](docs/phase-classification.md) | Per-phase breakdown of what each phase actually does |
| [`docs/contributing.md`](docs/contributing.md) | Dev setup, code style, PR process |

---

## 🤝 Contributing

PRs welcome — especially:

- New phase implementations
- Better heuristics that **reduce** false positives
- Real-world findings via VulnForge (write-ups encouraged)
- Bug reports on specific phases
- Translations of the docs

Open an issue first if your change is significant. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

---

## 📜 License

MIT — see [`LICENSE`](LICENSE).

---

<div align="center">

**Built by hunters who got tired of restarting `nmap` at 3am.**

⭐ Star it if it saved you a bash script. 🐛 Open an issue if it broke one.

</div>
