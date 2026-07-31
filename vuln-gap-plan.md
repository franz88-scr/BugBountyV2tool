# Plan: BugBountyV2tool — Close the Vulnerability-Detection Gaps

## Overview

Graph analysis (graphify-out/graph.json) shows a mature pipeline: 196 registered phases across 31 modules, all previously-planned phases 170–196 already implemented, and a well-connected architecture (`log`/`ensure`/`Tools` as cross-cutting hubs). The real remaining upside is **not** breadth sprawl — it is three concrete gaps the graph surfaced:

1. **Missing vuln types**: `finding.py`'s registry lacks 7 vulnerability classes that existing phases already emit as plain-text hints (`[xss-dom-clobber]`, etc.) or that real targets exhibit with no phase at all: `dom_clobber`, `second_order`, `oauth_csrf`, `xssi`, `weak_tls`, `open_proxy`, `smtp_relay`. Findings in these classes can never be reported with severity/CWE/CVSS.
2. **Thin phases with zero test coverage**: phases 170–196 (170-CLIENTPP through 196-PUSHAPI) have **no test file references** in `tests/` (grep returned nothing), and modules like `redos.py` (137 lines), `webrtc.py` (150), `pwa_security.py` (188), `account.py` (203) are minimal.
3. **Five genuinely absent attack classes** worth new phases: second-order (stored→triggered) injection, weak TLS/crypto, open proxy / SMTP relay, OAuth CSRF + account-linking, and XSSI (JSON hijacking).

## Success Criteria

- All 7 missing vuln types registered in `finding.py` (CWE/CVSS/severity), `remediation.py`, `artifacts.py`.
- 5 new phases (197-SECONDORDER, 198-WEAKTLS, 199-OPENPROXY, 200-OAUTHCSRF, 201-XSSI) wired into `config.py`, `phases/__init__.py` (PIPELINE, PHASE_DEPS, STAGES, _PHASE_WEIGHTS).
- Existing phases 192-REDOS, 193-WEBRTC, 196-PUSHAPI deepened and exercised by new tests.
- `pytest tests/ -v` passes; `ruff check vulnforge/ && ruff format --check vulnforge/` passes; `mypy vulnforge/` passes.
- `python vulnforge.py --list-phases` shows 197–201.

## Tech Stack

- Python 3.9+ stdlib (existing pattern — no new dependencies).
- Reuse existing helpers: `vulnforge/utils.py` (`_async_urlopen`, `log`, `ensure`), `vulnforge/phases/helpers.py` (`_rate_limit_args`, `_dedupe_by_normalized_url`), `vulnforge/tools.py` (`Tools`).
- Tests: pytest, following `tests/test_recon_phases.py` patterns.

## File Structure Changes

### New files
- `vulnforge/phases/gap_vulns.py` — phases 197–201 (all five new classes in one module, matching the multi-phase module pattern).

### Modified files
- `vulnforge/finding.py` — add 7 vuln types to `_VULN_TYPE_CWE`, `_VULN_TYPE_CVSS`, `_VULN_TYPE_SEVERITY`.
- `vulnforge/remediation.py` — add `REMEDIATIONS` entries for the 7 types.
- `vulnforge/artifacts.py` — add `ArtifactDef` entries for new phase outputs.
- `vulnforge/config.py` — add phase IDs to `VALID_PHASES` (auto-derived from `PHASE_CATEGORIES`), add `PHASE_CATEGORIES` entries.
- `vulnforge/phases/__init__.py` — import new module, register phases in `PIPELINE`, `PHASE_DEPS`, `_PHASE_WEIGHTS`, `STAGES`.
- `vulnforge/phases/redos.py` — deepen 192-REDOS.
- `vulnforge/phases/webrtc.py` — deepen 193-WEBRTC.
- `vulnforge/phases/pwa_security.py` — deepen 196-PUSHAPI.

### New test files
- `tests/test_gap_vulns.py` — coverage for phases 197–201 and registration integrity.
- `tests/test_deep_phases.py` — coverage for deepened 192/193/196.

## Task Breakdown

### Task 1: Register the 7 missing vuln types
Add to `finding.py`, `remediation.py`, `artifacts.py`:
- `dom_clobber` → CWE-79, CVSS 6.1, medium (already emitted as `[xss-dom-clobber]` in `injection.py`, `client_side.py`, `auth_bypass.py`)
- `second_order` → CWE-74, CVSS 8.6, high
- `oauth_csrf` → CWE-352, CVSS 6.5, medium
- `xssi` → CWE-932, CVSS 4.3, low
- `weak_tls` → CWE-327, CVSS 7.4, high
- `open_proxy` → CWE-441, CVSS 5.3, medium
- `smtp_relay` → CWE-441, CVSS 5.3, medium

INPUT: `finding.py`, `remediation.py`, `artifacts.py` → OUTPUT: 7 fully-registered types → VERIFY: `pytest tests/test_finding.py tests/test_remediation.py -v` and `python -c "from vulnforge.finding import Finding; print(Finding('x','197-SECONDORDER','second_order','high',1.0,'t','e'))"`.

### Task 2: New module `vulnforge/phases/gap_vulns.py` (5 phases)
- **phase_197_SECONDORDER**: read stored payload outputs from 11-INJECT/80-STOREXSS/99e-XSSSTORED; re-submit them to every `urls_all.txt` endpoint; detect the payload echoing back (stored→triggered). OUTPUT: `second_order.txt`. DEPS: 11-INJECT, 80-STOREXSS.
- **phase_198_WEAKTLS**: TLS 1.0/1.1/SSLv3 negotiation, weak cipher suites (RC4, 3DES, EXPORT), no SNI, cert chain/expiry issues, TLS 1.3 downgrade. Stdlib-only via `ssl.create_default_context` + `_create_unverified_context` probes on 04-SCAN ports. OUTPUT: `weak_tls.txt`. DEPS: 04-SCAN.
- **phase_199_OPENPROXY**: CONNECT-method proxy detection, open HTTP forward proxy, open SMTP relay (HELO/RCPT/QUIT) — safe probes only, no mail delivery. OUTPUT: `open_proxy.txt`, `smtp_relay.txt`. DEPS: 04-SCAN.
- **phase_200_OAUTHCSRF**: missing/weak `state` param on OAuth login flows (detected via 05-HARVEST URL patterns), `response_type=token` leak, account-linking endpoint without CSRF token. OUTPUT: `oauth_csrf.txt`. DEPS: 05-HARVEST, 39-OAUTH.
- **phase_201_XSSI**: endpoints returning arrays/objects under script tags without `X-Content-Type-Options: nosniff` or proper `application/json` content type; check authenticated JSON responses readable cross-origin. OUTPUT: `xssi.txt`. DEPS: 04-SCAN.

INPUT: `urls_all.txt`, `host_targets.txt`, `resolved.txt` → OUTPUT: 6 output files → VERIFY: run each against a local test HTTP server; assert findings written.

### Task 3: Register the 5 phases in pipeline
- `config.py`: `PHASE_CATEGORIES` (add "gap" category with 197–201 + weights); `VALID_PHASES` auto-derives.
- `phases/__init__.py`: `PIPELINE` entries, `PHASE_DEPS`, `_PHASE_WEIGHTS`, new STAGES entry (Stage 36), re-export import.
- `artifacts.py`: artifact defs per output file.

INPUT: Task 2 module → OUTPUT: registered phases → VERIFY: `python vulnforge.py --list-phases | grep -E "19[7-9]|20[01]-"` shows all 5; `pytest tests/test_pipeline_dag.py -v` passes.

### Task 4: Deepen 192-REDOS
Expand payload corpus (email/base64/date regex bombs), add polyglot input encoding (URL/JSON), add response-time-delta confirmation with 3-run baseline. Keep stdlib-only.

INPUT: `redos.py` → OUTPUT: deeper phase → VERIFY: test with a slow-regex test endpoint; assert time-delta > 5s flagged.

### Task 5: Deepen 193-WEBRTC + 196-PUSHAPI
- 193-WEBRTC: add STUN server enumeration (`stun:` URLs from 06-JSINTEL), TURN credential config leakage check, ICE candidate internal-IP flagging with 10./172.16-31./192.168. regex.
- 196-PUSHAPI: add VAPID public key exposure check, unauthenticated push-subscription endpoint check, missing user-gesture subscription check.

INPUT: `webrtc.py`, `pwa_security.py` → OUTPUT: deepened phases → VERIFY: unit tests against fixture payloads.

### Task 6: Tests
- `tests/test_gap_vulns.py`: parametrized tests for each new phase using a local `http.server`-based fixture; assert output files + finding types.
- `tests/test_deep_phases.py`: REDOS timing, WebRTC IP regex, PushAPI VAPID extraction.
- Assert every phase in 170–201 has at least one referenced test (guards the graph's "no coverage for 170–196" finding).

INPUT: Tasks 1–5 → OUTPUT: passing test suite → VERIFY: `pytest tests/ -v`.

## Verification

1. `ruff check vulnforge/ && ruff format --check vulnforge/`
2. `mypy vulnforge/`
3. `pytest tests/ -v` (all pass)
4. `python vulnforge.py --list-phases 2>&1 | grep -E "19[7-9]|20[01]-"`
5. Manual smoke: run `python vulnforge.py -t example.com --phase 198-WEAKTLS` against a local TLS test server.
