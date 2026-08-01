# Plan: BugBountyV2tool — Neue Phasen & Vertiefung

## Overview
Add new vulnerability classes (Option A) and deepen existing phases (Option B) to increase vulnerability detection coverage.

## Success Criteria
- New phases: Prototype Pollution, CSS Injection, Dangling Markup Injection
- Deepened phases: SSTI, XXE, LFI, NoSQLi, CMDINJECT, JWT, Cache Poisoning, GraphQL, Rate Limit, File Upload, Stored XSS, SQLMap
- All new phases registered in pipeline, config, artifacts, findings, remediation
- Lint/typecheck/tests pass

## Tech Stack
- Python 3.9+ (stdlib, existing patterns)
- Playwright for browser-based probes (already used in DOM XSS / Stored XSS)
- asyncio for concurrent probes

## File Structure Changes

### New Files
- `vulnforge/phases/web_client.py` — Option A: Prototype Pollution (149-PP), CSS Injection (150-CSSINJECT), Dangling Markup (150a-DANGLING)

### Modified Files
- `vulnforge/phases/injection.py` — B1: SSTI (phase 12) + B12: SQLMap (phase 11b)
- `vulnforge/phases/injection_misc.py` — B2: XXE (phase 25), B4: NoSQLi (phase 22), B5: CMDINJECT (phase 26)
- `vulnforge/phases/client_side.py` — B3: LFI (phase 30), B7: Cache Poisoning (phase 28), B9: Rate Limit (phase 34), B10: File Upload (phase 37), B11: Stored XSS (phase 80)
- `vulnforge/phases/fuzzing.py` — B9: Rate Limit Bypass (phase 136)
- `vulnforge/phases/graphql_chain.py` — B8: GraphQL (phase 20/132)
- `vulnforge/phases/auth.py` — B6: JWT (phase 24/36)
- `vulnforge/phases/__init__.py` — Register new phases in PIPELINE, PHASE_DEPS, STAGES, _PHASE_WEIGHTS
- `vulnforge/config.py` — Add phase IDs to VALID_PHASES, PHASE_CATEGORIES, etc.
- `vulnforge/finding.py` — Add proto_pollution, css_inject, dangling_markup
- `vulnforge/remediation.py` — Add remediations for new vuln types
- `vulnforge/artifacts.py` — Add artifact defs for new phases

## Task Breakdown

### Task 1: Plan file (DONE)
Create this plan file with all tasks documented.

### Task 2: Option A — New phase file `web_client.py`
- phase_149_PP: Prototype Pollution detection (client-side via Playwright + server-side via JSON payloads)
- phase_150_CSSINJECT: CSS Injection via `{ }` style block injection + OAST exfiltration probes
- phase_150a_DANGLING: Dangling Markup Injection via `<img src=` and similar patterns

INPUT: urls_all.txt, host_targets.txt -> OUTPUT: pp.txt, css_inject.txt, dangling_markup.txt
VERIFY: Phase function executes without error

### Task 3: Option B — Deepening modifications
INPUT: Existing phase files -> OUTPUT: Modified phase files with deepened payloads
VERIFY: Each phase function still runs correctly

| ID | Phase | What to add |
|----|-------|-------------|
| B1 | 12-SSTI | +10 Engines: Jinja2, Twig, Freemarker, Velocity, Mako, Jade/Pug, Handlebars, Mustache, Dot, Nunjucks + framework fingerprinting via `{{config}}`, `{{self}}` |
| B2 | 25-XXE | +SVG XXE, +DOCX/XML upload XXE, +XInclude, +blind XXE with OAST, +parameter entity OOB |
| B3 | 30-LFI | +PHP wrappers (php://filter), +RFI tests (http://external), +Log Poisoning via User-Agent |
| B4 | 22-NOSQLI | +Firebase REST API probes, +CouchDB-specific payloads |
| B5 | 26-CMDINJECT | +Time-based (sleep 5), +OOB-based (nslookup {oast}), +Filter-bypass sequences |
| B6 | 24/36-JWT | +JWK injection (header), +kid path traversal, +algorithm confusion for more libs |
| B7 | 28-CACHED | +Unkeyed cookie poisoning, +Vary header poisoning |
| B8 | 20/132-GRAPHQL | +Batching attack (parallel queries), +Aliasing-based DoS |
| B9 | 34/136-RATELIMIT | +X-Forwarded-For rotation bypass, +IP rotation with proxy list |
| B10 | 37-FILEUPLOAD | +Polyglot GIF+PHP/JPEG+JS, +Race condition upload |
| B11 | 80-STOREXSS | +Multipage crawl via forms, +OOB confirmation of stored payload |
| B12 | 11b-SQLMAP | +Second pass with level=5, risk=3 |

### Task 4: Registration
All new phases registered in:
- `config.py`: VALID_PHASES, QUICK_SKIP_PHASES, DOS_PHASES (if relevant), PHASE_CATEGORIES
- `phases/__init__.py`: PIPELINE list, PHASE_DEPS, _PHASE_WEIGHTS, STAGES, import re-exports
- `finding.py`: _VULN_TYPE_CWE, _VULN_TYPE_CVSS, _VULN_TYPE_SEVERITY
- `remediation.py`: REMEDIATIONS entries
- `artifacts.py`: ARTIFACTS entries

### Task 5: Verification
Run `ruff check vulnforge/`, `mypy vulnforge/`, `pytest tests/ -v`

## Verification
- ruff check passes (no errors)
- mypy passes (no type errors)
- pytest tests pass (all existing)
- New phase functions are importable from vulnforge.phases
- New phase IDs are in VALID_PHASES
- Pipeline can enumerate all phases including new ones
