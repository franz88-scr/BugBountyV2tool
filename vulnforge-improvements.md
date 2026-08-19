# VulnForge Improvement Plan

## Overview

VulnForge works — `out/` contains real scan artifacts, the DAG/resource-safety layer is solid, CI is strong. The problems are all in the *shape* of the code, not the concept:

- 213 phases are 213 hand-rolled copies of the same ~200-line template (`skip-check → cached-output check → read hosts → gather → write findings`).
- `helpers.py` is a star-import god-module; `mypy` quietly excludes the biggest chunk of code (`phases/`).
- The `sample_*` config surface is maintained in **three** hand-synced places, so defaults already drift (`sample_urls_params` is 15 in `config.py:735`, 50 in `pipeline.py` and the wizard).
- Dead code, stale claimed numbers, noise-in-findings, and dev artifacts in the repo root.

Goal: remove the copy-paste and drift so the *next* phase takes ~30 lines, adding a knob touches one file, and typechecking covers everything. Not a rewrite — a set of mechanical, verifiable refactors plus one structural change (the phase harness).

**Design decisions (see §Decisions for the one open question):**

1. **Harness over decorator.** A heavyweight `@phase(...)` decorator would force 213 divergent functions into one shape. Instead extract the mechanical parts into four small helpers (`phase_begin`, `phase_targets`, `phase_finish`, `@http_probe`) that phases *opt into*. Migrate a pilot batch to prove the pattern; migrate the rest opportunistically — never as a big-bang.
2. **`PipelineConfig` becomes the single source of truth.** Safe-mode halving and `sample_mode` handling move into `__post_init__`. The wizard and `pipeline.py` stop hand-listing fields; they iterate `dataclasses.fields()`.
3. **Numbers derive from code.** Phase/stage counts are computed, not typed into READMEs and docstrings.

## Success Criteria

- A new phase needs only the probe logic; template boilerplate lives in the harness.
- Adding a `sample_*` knob touches exactly one file (the dataclass), and a test fails if wizard/pipeline drift.
- `mypy vulnforge/` passes with `phases/` included (no excludes).
- `ruff check`, `ruff format --check`, and the targeted test files all pass.
- README claims (213 phases / stage count) match code-derived values, enforced by a test.
- Findings files contain only real findings; "no findings" is represented as empty or `#`-commented, not a fake finding.
- No dead top-level dev artifacts remain in the repo root.
- Behavioral parity: an existing real scan dir (e.g. `out/brandenburg.cloud`) re-runs the migrated phases with identical findings output.

## Tech Stack

- Python 3.9+/3.10 (see §Decisions), stdlib only in core — **no new dependencies**.
- Existing tooling only: `ruff`, `mypy`, `pytest`. No new frameworks.
- Rationale: the whole project is stdlib-first; the harness must not introduce runtime deps or import cycles with `process.py`/`utils.py`.

## File Structure

```
vulnforge/
├── phases/
│   ├── harness.py          # NEW: phase_begin / phase_targets / phase_finish / @http_probe
│   ├── cookie_security.py  # migrated to harness (pilot)
│   ├── network.py          # migrated to harness (pilot)
│   ├── third_party.py      # migrated to harness (pilot)
│   ├── webrtc.py           # migrated to harness (pilot)
│   └── ...                 # 36 remaining files: import cleanup only (Workstream C)
├── config.py               # PipelineConfig.__post_init__ applies mode + safe-mode halving
├── pipeline.py             # 115-line constructor collapses to a field loop (B3); dead clause removed (D1)
├── cli/wizard.py           # _set_sample_defaults derived from dataclass fields (B2)
tests/
├── test_config_consistency.py  # NEW: field/default agreement (B4), phase-count parity (E3)
├── test_phase_harness.py       # NEW: harness behavior + golden output for pilot (A2)
├── test_noise_findings.py      # NEW: no fake findings written (F)
scripts/                    # moved dev artifacts (G1)
README.md                   # numbers corrected to code-derived (E2)
```

## Task Breakdown

Workstreams are independent unless noted. Agents: `code` = coding agent, `docs` = docs edit.

### Workstream A — Phase harness (highest value)

**A1 — Create `vulnforge/phases/harness.py`** · agent: `code` · priority: P1 · deps: none
- INPUT: the repeated template observed across `cookie_security.py`, `fuzzing.py`, etc.
- OUTPUT: four helpers:
  - `phase_begin(name, outdir, skip, force) -> Optional[Path]` — skip + cached-output check + start log. Returns `None` when the phase should not run.
  - `phase_targets(outdir, kind)` — resolve `host_targets.txt`/`hosts.txt`/`urls_all.txt` with scheme prepend + "no targets" log.
  - `phase_finish(name, findings, out, phase_id) -> Dict[str, Any]` — wraps existing `utils.write_findings` (empty ⇒ no file, no fake finding).
  - `@http_probe(...)` — thin decorator for the uniform GET-request+regex majority; unwraps to the same helpers so it's optional.
- VERIFY: `pytest tests/test_phase_harness.py -v`; `ruff check vulnforge/phases/harness.py`.

**A2 — Migrate pilot batch** · agent: `code` · priority: P1 · deps: A1
- INPUT: `cookie_security.py`, `network.py`, `third_party.py`, `webrtc.py` (pure-HTTP phases, no tool shells).
- OUTPUT: the four files use the harness; per-phase body shrinks toward probe-only logic. No behavior change.
- VERIFY: golden-output test — feed a fixture outdir (copied from `out/brandenburg.cloud`) to the old and new implementations and assert identical `*_findings` files. `mypy` + `ruff` on the four files.

**A3 — Document the pattern** · agent: `docs` · priority: P2 · deps: A2
- INPUT: harness.py docstrings + migration experience.
- OUTPUT: CONTRIBUTING.md section "Writing a phase — use the harness"; add "new phases use `phases/harness.py`, never the old template" to AGENTS.md §11.
- VERIFY: docs link-check; a reader (subagent) follows the section and produces a valid skeleton.

**A4 — Opportunistic migration (ongoing)** · agent: `code` · priority: P3 · deps: A3
- INPUT: remaining phase files as they're touched for other reasons.
- OUTPUT: no file is rewritten for this workstream alone; every touched file is harness-converted.
- VERIFY: N/A (process rule, tracked in AGENTS.md).

### Workstream B — Config single source of truth

**B1 — `PipelineConfig.__post_init__` applies `sample_mode` + safe-mode halving** · agent: `code` · priority: P0 · deps: none
- INPUT: current `_ss()` logic in `pipeline.py:439-446`.
- OUTPUT: `__post_init__` walks `dataclasses.fields()`, and for every `sample_*` int field applies: `minimal → 1`, `all → sys.maxsize`, `safe_mode → max(1, v//2)`. The `_ss` helper is deleted.
- VERIFY: unit test that `PipelineConfig(safe_mode=True)` halves all `sample_*` values; `minimal`/`all` behave.

**B2 — Derive wizard defaults from the dataclass** · agent: `code` · priority: P0 · deps: B1
- INPUT: `_set_sample_defaults` in `wizard.py:1462+` (~109 assignments) and the `_resolve_count` block.
- OUTPUT: both replaced by iterating `dataclasses.fields(PipelineConfig)` filtered on the `sample_` prefix.
- VERIFY: wizard dry-run produces identical namespace values to today.

**B3 — Collapse the pipeline constructor** · agent: `code` · priority: P0 · deps: B1
- INPUT: `pipeline.py:448-562` (~115 hand-listed kwargs).
- OUTPUT: a field loop: for each `sample_*` field, `setattr(cfg, name, getattr(args, name, default))`; non-sample fields only override when set. The giant `PipelineConfig(...)` literal is deleted.
- VERIFY: dry-run scan (`vulnforge --dry-run -d example.com`) shows identical effective config; `pipeline.py` line count drops.

**B4 — Consistency test** · agent: `code` · priority: P0 · deps: B2, B3
- INPUT: the observed drift (`sample_urls_params` 15 vs 50).
- OUTPUT: `tests/test_config_consistency.py` asserting (a) wizard defaults == dataclass defaults for every `sample_*` field, (b) every `sample_*` dataclass field has a settable `args` path.
- VERIFY: test fails before B2/B3, passes after.

### Workstream C — Real typecheck coverage

**C1 — Kill the god-module import** · agent: `code` · priority: P1 · deps: none
- INPUT: 44 files doing `from vulnforge.phases.helpers import (...)`, `helpers.py` re-exporting stdlib/typing/utils/process names.
- OUTPUT: each file imports from its real source (`typing`, `vulnforge.utils`, `vulnforge.process`, `vulnforge.config`). Mechanical, no logic change. `helpers.py` keeps only its own definitions (`_rate_limit_args`, `_SCOPE_*`, `_normalize_url`, etc.) and stops re-exporting the rest.
- VERIFY: `ruff check vulnforge/` clean; `pytest tests/test_recon_phases.py tests/test_wired_features.py -v` (phase-heavy files) still pass; `git diff` shows import-block-only changes.

**C2 — Enable mypy on phases** · agent: `code` · priority: P1 · deps: C1
- INPUT: `[tool.mypy] exclude = ["tests/", "phases/"]`.
- OUTPUT: remove `phases/` from exclude; run `mypy vulnforge/`; fix errors (annotations already exist via `typing`, so most are real type bugs worth fixing).
- VERIFY: `mypy vulnforge/` exits 0. Cap the effort: if >50 fixes, log them as follow-up issues rather than weakening strictness.

**C3 — Align declared Python version** · agent: `code` · priority: P2 · deps: C2
- INPUT: `requires-python = ">=3.9"` vs `[tool.mypy] python_version = "3.10"` vs CI testing only 3.10–3.12.
- OUTPUT: per §Decisions, either bump to `>=3.10` (recommended) or force mypy to 3.9. CI gains a 3.9 job if support is kept.
- VERIFY: `make ci` green.

### Workstream D — Dead code

**D1 — Remove duplicate exception clause** · agent: `code` · priority: P0 · deps: none
- INPUT: `pipeline.py:818-822` — two identical `except asyncio.CancelledError` clauses.
- OUTPUT: one clause remains; comment removed.
- VERIFY: `pytest tests/test_pipeline_dag.py tests/test_reconchain.py -v`; `mypy`/`ruff` clean.

**D2 — Fix the dead condition in `phase_195_MIMESNIFF`** · agent: `code` · priority: P0 · deps: none
- INPUT: `cookie_security.py:175` — `"text/html" in content_type and "json" in content_type` is never both.
- OUTPUT: rewrite to the actual intent — flag when `Content-Type` says `text/html` but the body is not HTML, or the type and body disagree (confirm with a quick fixture response).
- VERIFY: new unit test with a synthetic `Content-Type`/body pair exercising the branch; old branch never executed.

### Workstream E — Numbers reconcile with code

**E1 — Computed counts** · agent: `code` · priority: P0 · deps: none
- INPUT: hardcoded counts ("213 phases / 45 stages", "All 185 phases").
- OUTPUT: `count_phases()`/`count_stages()` helpers (or a test) deriving from `PIPELINE` and `STAGES`. Verified: `PIPELINE` and `VALID_PHASES` already agree at 213; `STAGES` has 36 entries vs README's 45 — the README/stage-count side is what's wrong.
- VERIFY: `python -c` printout matches reality; no stale literal remains.

**E2 — Fix stale strings** · agent: `docs` · priority: P1 · deps: E1
- INPUT: `_RECON_LEVELS["full"]` desc ("All 185 phases") in `phases/__init__.py:1356`, README "45 DAG stages".
- OUTPUT: both corrected to code-derived values (213 phases; actual stage-list count).
- VERIFY: `grep -rn "185 phases\|45 stages" vulnforge README.md` returns nothing.

**E3 — Parity test** · agent: `code` · priority: P1 · deps: E1
- OUTPUT: test asserting `VALID_PHASES == {names in PIPELINE}` (already true today) and that README's phase/stage numbers match `count_phases()`/`count_stages()`.
- VERIFY: test passes; fails if future phases are added without updating the count source.

### Workstream F — Stop writing fake findings

**F1 — Empty-findings convention** · agent: `code` · priority: P1 · deps: A1
- INPUT: the `findings.append("[...] No X detected (expected)")` pattern and the `mime-upload-endpoint` Allow-header "finding".
- OUTPUT: harness `phase_finish` uses `utils.write_findings` (empty ⇒ no file). Where an empty-file marker is genuinely needed, write a `#`-comment line — `count_nonblank` and `_snapshot_findings` already skip `#` lines, so counts stay honest.
- VERIFY: count of findings in a fixture scan equals number of real findings; `test_noise_findings.py` asserts no line containing "(expected)" survives into a findings file.

**F2 — Audit downstream consumers** · agent: `code` · priority: P2 · deps: F1
- INPUT: `vulnforge.artifacts.ARTIFACTS`, reporting counts, ML/compliance/threat-intel readers.
- OUTPUT: confirm none of them count `#`-prefixed lines as findings; adjust any that do.
- VERIFY: grep for `read_lines(`/`count_nonblank` on artifacts; regression tests in `test_ml_modules.py`, `test_compliance.py`, `test_threat_intel.py`.

### Workstream G — Repo hygiene

**G1 — Move/remove dead top-level artifacts** · agent: `code` · priority: P2 · deps: none
- INPUT: `overseer.py`, `monitor.py`, `fix_bugs.py`, `recon_monitor.py`, `beacon.sh`, `watchdog.sh`, `check_status.sh`, `status_reporter.sh`, `vulnforge.cfg`. Already verified unreferenced by `vulnforge.py`, `__init__.py`, parser, Makefile, CI.
- OUTPUT: grep `install.sh`, `docker-compose.yml`, `Dockerfile`, `docs/` for references first; anything dead moves to `scripts/` (or `git rm` if truly obsolete). Keep `reconchain.py` (console-script entry) and `vulnforge.py`.
- VERIFY: `git grep -l "overseer\|recon_monitor\|beacon\|watchdog\|status_reporter"` returns nothing outside `scripts/`; `make ci` green.

**G2 — Commit discipline (process)** · agent: `docs` · priority: P3 · deps: none
- OUTPUT: AGENTS.md note — one logical change per commit; the 8-huge-commit history is not rewritable, but going forward diffs stay reviewable.
- VERIFY: N/A (process rule).

### Workstream H — False-positive reduction (biggest risk, ongoing)

**H1 — Audit the noisiest phases on real data** · agent: `code` · priority: P2 · deps: none
- INPUT: real output in `out/brandenburg.cloud` and `out/erp-betsy.com` + `_PHASE_WEIGHTS`.
- OUTPUT: score phases by findings-volume; pick top 10; for each, mark every unconfirmed signal `[candidate]` and add a confirmation heuristic (second request, status/shape check) where cheap.
- VERIFY: for the reviewed 10 phases, findings on the real scans drop by >=30% or are re-labeled `[candidate]`; triage/report shows candidates separately.

**H2 — Certainty wiring** · agent: `code` · priority: P3 · deps: H1
- INPUT: existing `certainty.py`, `severity.py`, `ml_vuln.py` classification.
- OUTPUT: every unconfirmed finding carries low certainty by default; reports distinguish confirmed vs candidate.
- VERIFY: a synthetic low-signal scan produces zero "confirmed" findings.

## Verification

Final checklist (run before declaring the plan complete):

- [ ] `ruff check vulnforge/ && ruff format --check vulnforge/` — clean.
- [ ] `mypy vulnforge/` — exits 0 with `phases/` **included**, `python_version` aligned.
- [ ] `pytest tests/test_phase_harness.py tests/test_config_consistency.py tests/test_noise_findings.py tests/test_recon_phases.py tests/test_wired_features.py tests/test_pipeline_dag.py tests/test_ml_modules.py tests/test_compliance.py tests/test_threat_intel.py -v` — pass (targeted only; full suite optional per AGENTS.md §11).
- [ ] Golden-output test: migrated pilot phases produce byte-identical findings vs pre-migration on `out/brandenburg.cloud`.
- [ ] `vulnforge --dry-run -d example.com` — effective config identical to before B.
- [ ] `grep -rn "185 phases\|45 stages\|(expected)" vulnforge README.md` — no hits.
- [ ] `git grep -l "overseer\|recon_monitor\|beacon\|watchdog\|status_reporter"` — nothing outside `scripts/`.
- [ ] Phase-count parity test passes: `VALID_PHASES == PIPELINE` names, README == computed counts.

## Decisions

**Open — Python floor.** Recommend `requires-python >= 3.10`: CI already only runs 3.10–3.12, mypy is pinned to 3.10, and nothing below 3.10 is ever exercised. Tradeoff: drops 3.9 users (who are currently promised support they may not actually get). Alternative: keep 3.9 and force mypy to 3.9 + add a 3.9 CI job. Confirm before Workstream C.
