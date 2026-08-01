# Changelog

All notable changes to this project are documented here. Versions follow the `pyproject.toml` `version` field.

## [Unreleased]

### Fixed
- `_diff_findings` created the diff directory only as a parent; now creates the directory itself (`vulnforge/pipeline.py`).
- Phase ID prefix collision: `175-WS-DEEP` renamed to `175a-WS-DEEP` so every phase has a unique numeric prefix.
- Dependency-check CVE table: removed fabricated CVE-2023 entries and corrected wrong fixed-version mappings (`vulnforge/phases/injection_misc.py`).
- `dashboard.port` from the config was ignored when `enabled = true` (the `8765` default was applied first and could not be overridden); the configured port now wins (`vulnforge/conf.py`).
- A config without a `[general]` section leaked section dicts (e.g. the whole `[proxy]` block) into general settings; the top-level fallback now only accepts scalar keys, and section lookups guard against non-dict values (`vulnforge/conf.py`).

### Added
- Ethics / responsible-use disclaimer in `README.md`.
- `tests/test_process_core.py` (31 tests) covering process-core helpers, scheduler, snapshot/diff, and preflight checks.
- Phase classification generator `scripts/classify_phases.py` and generated `docs/phase-classification.md`.
- README naming note documenting the `vulnforge` / `reconchain` / `BugBountyV2tool` history.

### Removed
- Dead `reconchain.cfg` (the config loader reads `vulnforge.cfg`).

## [3.1.0] - 2026-07-31

- Package renamed to `vulnforge`; pipeline expanded to 213 phases across 45 DAG stages; `reconchain` kept as a CLI alias.

## [2.0.0] - 2026-07-18

- Major feature update: AI triage, ML classification/phase selection, dashboard, plugins, compliance reports, threat intelligence.

## [3.1.0-rc] - 2026-07-17

- Structured findings, remediation guidance, REST API, rate limiter, authentication methods, modular phase layout.

## [3.0.0] - 2026-07-15

- Resource monitor, improved pipeline, rate limiting, CLI and phase updates.
