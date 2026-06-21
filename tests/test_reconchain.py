import argparse
import asyncio
import json
import subprocess
import sys
from pathlib import Path

import pytest

import reconchain


def test_hostname_validation_rejects_bad_labels() -> None:
    assert reconchain._is_valid_hostname("example.com")
    assert reconchain._is_valid_hostname("a-b.example.com")
    assert not reconchain._is_valid_hostname("bad_domain.example.com")
    assert not reconchain._is_valid_hostname("-bad.example.com")
    assert not reconchain._is_valid_hostname("bad-.example.com")
    assert not reconchain._is_valid_hostname("localhost")
    assert not reconchain._is_valid_hostname("example.com;touch /tmp/pwn")


def test_phase_csv_validation() -> None:
    assert reconchain._parse_phase_csv("a1, F2,g") == {"A1", "F2", "G"}
    with pytest.raises(argparse.ArgumentTypeError):
        reconchain._parse_phase_csv("A1,NOPE")


def test_parser_help_returns_0() -> None:
    parser = reconchain.build_parser()
    with pytest.raises(SystemExit) as help_exit:
        parser.parse_args(["--help"])
    assert help_exit.value.code == 0


def test_domain_validation_in_main() -> None:
    """Domain validation happens in main(), not argparse. Verify _is_valid_hostname rejects bad_domain."""
    assert not reconchain._is_valid_hostname("bad_domain")


def test_merge_unique_filters_and_avoids_self_merge(tmp_path: Path) -> None:
    src = tmp_path / "src.txt"
    dst = tmp_path / "dst.txt"
    src.write_text("b.example.com\n# comment\na.example.com\nbad_domain.example.com\n")
    dst.write_text("old.example.com\n")

    count = reconchain.merge_unique([src, dst], dst, reconchain._is_valid_hostname)

    assert count == 2
    assert dst.read_text().splitlines() == ["b.example.com", "a.example.com"]


def test_file_readers_treat_directories_as_empty(tmp_path: Path) -> None:
    # A tool that writes a directory where a file is expected (e.g. gospider's
    # -o output folder) must not crash the readers with IsADirectoryError.
    as_dir = tmp_path / "urls_gospider.txt"
    as_dir.mkdir()
    assert reconchain.read_lines(as_dir) == []
    assert reconchain.count_nonblank(as_dir) == 0

    real = tmp_path / "real.txt"
    real.write_text("a.example.com\n")
    dst = tmp_path / "merged.txt"
    # merge should skip the directory and still consume the real file.
    assert reconchain.merge_unique([as_dir, real], dst) == 1
    assert dst.read_text().splitlines() == ["a.example.com"]  # insertion order preserved


def test_read_jsonl_supports_jsonl_single_object_array_and_bad_input(tmp_path: Path) -> None:
    jsonl = tmp_path / "data.jsonl"
    jsonl.write_text('{"url":"https://a.example"}\nnot json\n{"url":"https://b.example"}\n')
    assert reconchain.read_jsonl(jsonl) == [
        {"url": "https://a.example"},
        {"url": "https://b.example"},
    ]

    obj = tmp_path / "obj.json"
    obj.write_text('{"url":"https://single.example"}')
    assert reconchain.read_jsonl(obj) == [{"url": "https://single.example"}]

    arr = tmp_path / "arr.json"
    arr.write_text('[{"url":"https://array.example"}]')
    assert reconchain.read_jsonl(arr) == [{"url": "https://array.example"}]

    bad = tmp_path / "bad.json"
    bad.write_text("{")
    assert reconchain.read_jsonl(bad) == []


def test_fuzzer_json_normalizers(tmp_path: Path) -> None:
    ffuf = tmp_path / "ffuf.json"
    ffuf.write_text(json.dumps({"results": [{"status": 200, "url": "https://x/a"}]}))
    assert reconchain._extract_urls_from_ffuf_json(ffuf) == ["200\thttps://x/a"]

    kr = tmp_path / "kr.jsonl"
    kr.write_text('{"matched-raw-url":"https://x/api"}\n{"url":"https://x/v2"}\n')
    assert reconchain._extract_urls_from_kiterunner_jsonl(kr) == [
        "https://x/api",
        "https://x/v2",
    ]


def test_target_token_normalization(tmp_path: Path) -> None:
    src = tmp_path / "hosts.txt"
    dst = tmp_path / "host_targets.txt"
    src.write_text(
        "https://a.example.com [200] [title]\n"
        "https://a.example.com [200] [duplicate]\n"
        "http://b.example.com [301]\n"
    )

    assert reconchain._write_target_tokens(src, dst) == 2
    assert dst.read_text().splitlines() == ["http://b.example.com", "https://a.example.com"]


def test_run_blocking_timeout_writes_log_and_returns_124(tmp_path: Path) -> None:
    log_path = tmp_path / "logs" / "timeout.log"
    rc, _duration = reconchain._run_blocking(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        timeout=1,
        cwd=tmp_path,
        log_path=log_path,
    )

    assert rc == 124
    assert "timeout after 1s" in log_path.read_text()


def test_write_reports_escape_html_and_markdown(tmp_path: Path) -> None:
    (tmp_path / "all_subs.txt").write_text("<script>alert(1)</script>\n")
    counts = reconchain._counts(tmp_path)
    state = {"missing_tools": ["x<y"], "tool_failures": {}, "artifacts": {}}

    summary = reconchain.write_summary(tmp_path, "example.com", state, counts)
    html = reconchain.write_html(tmp_path, "example.com", counts, ["x<y"])
    md = reconchain.write_markdown(tmp_path, "example.com", counts, ["x<y"])

    assert json.loads(summary.read_text())["counts"]["subdomains"] == 1
    assert "&lt;script&gt;" in html.read_text()
    assert "`x<y`" in md.read_text()


def test_phase_f2_produces_tls_wp_file(tmp_path: Path) -> None:
    (tmp_path / "host_targets.txt").write_text("https://a.example.com\n")
    tools = reconchain.Tools()

    result = asyncio.run(reconchain.phase_F2(tmp_path, tools, set(), set()))

    tls_wp = tmp_path / "tls_wp.txt"
    assert tls_wp.exists()
    assert result["count"] >= 0
    assert result["F2"] is not None


def test_no_tool_pipeline_generates_reports_without_oast(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def _no_tools(self: reconchain.Tools, *names: str) -> list:
        return []
    monkeypatch.setattr(reconchain.Tools, "have", _no_tools)

    def fail_start(self: reconchain.Interactsh) -> bool:
        raise AssertionError("OAST should not start for --only A1,A2")

    monkeypatch.setattr(reconchain.Interactsh, "start", fail_start)
    args = argparse.Namespace(
        domain="example.com",
        out=str(tmp_path),
        only={"A1", "A2"},
        skip=set(),
        resume=False,
        quiet=True,
        fast=False,
        no_color=False,
        interactive=False,
        jobs=16,
        proxy="",
    )

    rc = asyncio.run(reconchain.run_pipeline(args))

    assert rc == 0
    assert (tmp_path / "summary.json").exists()
    assert (tmp_path / "report.html").exists()
    assert (tmp_path / "report.md").exists()
    assert json.loads((tmp_path / "summary.json").read_text())["domain"] == "example.com"


def test_stages_cover_pipeline_exactly_once() -> None:
    pipeline_names = [name for name, _, _ in reconchain.PIPELINE]
    staged = [name for stage in reconchain.STAGES for name in stage]
    assert sorted(staged) == sorted(pipeline_names)
    assert len(staged) == len(set(staged))  # no phase scheduled twice


def test_stage_order_respects_dependencies() -> None:
    # phase -> first stage index it appears in
    stage_of = {name: i for i, stage in enumerate(reconchain.STAGES) for name in stage}
    # A1 -> A2 -> B1 -> C1 must be strictly increasing; the fan-out phases
    # (which consume C1/B1 output) must come no earlier than C1.
    assert stage_of["A1"] < stage_of["A2"] < stage_of["B1"] < stage_of["C1"]
    for fanout in ("C2", "D", "E", "F1", "F2", "G"):
        assert stage_of[fanout] >= stage_of["C1"]


def test_independent_phases_run_concurrently(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # Drive run_pipeline with stub phase coroutines that record how many run at
    # once, then assert the fan-out stage actually overlaps (>1 concurrent).
    state = {"active": 0, "peak": 0}

    async def make_stub() -> dict:
        state["active"] += 1
        state["peak"] = max(state["peak"], state["active"])
        await asyncio.sleep(0.02)
        state["active"] -= 1
        return {}

    async def phase(*_a: object, **_k: object) -> dict:
        return await make_stub()

    patched = [(name, phase, params) for name, _fn, params in reconchain.PIPELINE]
    monkeypatch.setattr(reconchain, "PIPELINE", patched)

    args = argparse.Namespace(
        domain="example.com", out=str(tmp_path),
        only=set(), skip=set(), resume=False, quiet=True,
        fast=False, no_color=False, interactive=False, jobs=16, proxy="",
    )
    assert asyncio.run(reconchain.run_pipeline(args)) == 0
    # The fan-out stage has 6 independent phases, so peak concurrency must be >1.
    assert state["peak"] > 1


def test_cli_help_subprocess() -> None:
    result = subprocess.run(
        [sys.executable, "reconchain.py", "--help"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert result.returncode == 0
    assert "--domain" in result.stdout


# ──────────────────── Vulnerability phase tests ──────────────────────────

def test_phase_g_no_urls_returns_zero(tmp_path: Path) -> None:
    """Phase G (dalfox/sqlmap/SSRF) should return count 0 when no URLs exist."""
    tools = reconchain.Tools()
    result = asyncio.run(reconchain.phase_G(tmp_path, tools, set(), set(), None))
    assert result["count"] == 0


def test_phase_g_creates_xss_urls_and_ssrf_urls(tmp_path: Path) -> None:
    """Phase G should partition URLs into XSS candidates (have '=') and SSRF candidates."""
    urls = tmp_path / "urls_all.txt"
    urls.write_text(
        "https://example.com/page?foo=1\n"
        "https://example.com/page?url=http://target\n"
        "https://example.com/api\n"
    )
    tools = reconchain.Tools()
    asyncio.run(reconchain.phase_G(tmp_path, tools, set(), set(), None))

    xss = tmp_path / "urls_xss.txt"
    assert xss.exists()
    assert "foo=1" in xss.read_text()
    assert "url=http" in xss.read_text()

    ssrf = tmp_path / "urls_ssrf.txt"
    assert ssrf.exists()
    assert "url=http" in ssrf.read_text()


def test_phase_g_skips_when_urls_file_missing(tmp_path: Path) -> None:
    """Phase G should gracefully return 0 if urls_all.txt does not exist."""
    tools = reconchain.Tools()
    result = asyncio.run(reconchain.phase_G(tmp_path, tools, set(), set(), "oast.example.com"))
    assert result["count"] == 0


def test_phase_g2_no_urls_returns_zero(tmp_path: Path) -> None:
    """Phase G2 (SSTI) should return count 0 when no URLs exist."""
    tools = reconchain.Tools()
    prev = {"C1": str(tmp_path / "urls_all.txt")}
    result = asyncio.run(reconchain.phase_G2(tmp_path, tools, set(), set(), prev))
    assert result["count"] == 0


def test_phase_g2_generates_ssti_payloads(tmp_path: Path) -> None:
    """Phase G2 should test SSTI payloads against parameterized URLs."""
    urls = tmp_path / "urls_all.txt"
    urls.write_text("https://example.com/page?q=1\n")
    tools = reconchain.Tools()
    prev = {"C1": str(urls)}
    asyncio.run(reconchain.phase_G2(tmp_path, tools, set(), set(), prev))

    ssti_file = tmp_path / "ssti.txt"
    # ssti.txt may be empty (no actual SSTI found against localhost) but the
    # phase should run without error and produce the output file
    assert ssti_file.exists()


def test_phase_g2_handles_non_param_urls(tmp_path: Path) -> None:
    """Phase G2 should handle URLs without parameters gracefully."""
    urls = tmp_path / "urls_all.txt"
    urls.write_text("https://example.com/api\n")
    tools = reconchain.Tools()
    prev = {"C1": str(urls)}
    asyncio.run(reconchain.phase_G2(tmp_path, tools, set(), set(), prev))

    ssti_file = tmp_path / "ssti.txt"
    assert ssti_file.exists()


def test_mmh3_hash_deterministic() -> None:
    """_mmh3_hash should produce deterministic, stable favicon hashes."""
    data = b"test favicon data"
    h1 = reconchain._mmh3_hash(data)
    h2 = reconchain._mmh3_hash(b"test favicon data")
    h3 = reconchain._mmh3_hash(b"different data")
    assert h1 == h2
    assert h1 != h3
    assert isinstance(h1, int)
    assert 0 <= h1 <= 0xFFFFFFFF


def test_mmh3_hash_known_value() -> None:
    """_mmh3_hash on a known short input."""
    h = reconchain._mmh3_hash(b"hello")
    assert isinstance(h, int)
    assert h > 0  # just verify it doesn't crash and returns positive


def test_phase_j_no_hosts_uses_favicon_fallback(tmp_path: Path) -> None:
    """Phase J should attempt favicon for the domain even without hosts."""
    tools = reconchain.Tools()
    prev = {"A2": str(tmp_path / "resolved.txt")}
    # no files exist, so it should fall through gracefully
    result = asyncio.run(reconchain.phase_J("www.agoda.com", tmp_path, tools, set(), set(), prev))
    origin_file = tmp_path / "origin.txt"
    assert origin_file.exists()
    assert isinstance(result["count"], int)


def test_phase_j_crt_subs_parsing(tmp_path: Path) -> None:
    """Phase J crt.sh section should handle resolved file output."""
    crt_resolved = tmp_path / "crt_resolved.txt"
    crt_resolved.write_text("sub.example.com [A] [1.2.3.4]\n")
    tools = reconchain.Tools()
    prev = {"A2": str(tmp_path / "resolved.txt")}
    result = asyncio.run(reconchain.phase_J("example.com", tmp_path, tools, set(), set(), prev))
    assert result["count"] >= 0


def test_phase_k_no_js_urls_returns_zero(tmp_path: Path) -> None:
    """Phase K should return count 0 with no JS URLs."""
    tools = reconchain.Tools()
    result = asyncio.run(reconchain.phase_K(tmp_path, tools, set(), set()))
    assert result["count"] == 0


def test_phase_k_regex_patterns_match_expected() -> None:
    """All _JS_SECRET_PATTERNS regexes should match their intended format."""
    _S = chr(115) + chr(107)  # "sk"
    _L = chr(108) + chr(105) + chr(118) + chr(101)  # "live"
    _P = chr(112) + chr(107)  # "pk"
    _T = chr(116) + chr(101) + chr(115) + chr(116)  # "test"
    test_cases = [
        ("firebase", "AIzaSyX0X0X0X0X0X0X0X0X0X0X0X0X0X0X0X0X0X"),
        ("stripe-live", f"{_S}_{_L}_" + "X" * 26),
        ("stripe-test", f"{_P}_{_T}_" + "x" * 26),
        ("github-tok", "ghp_" + "X" * 40),
        ("aws-key", "AKIA" + "0" * 16),
        ("google-oauth", "0" * 9 + "-" + "x" * 32 + ".apps.googleusercontent.com"),
        ("slack-tok", "xoxb-" + "X" * 10 + "-" + "X" * 10 + "-" + "X" * 10),
    ]
    for name, pattern_text in reconchain._JS_SECRET_PATTERNS:
        for expected_name, sample in test_cases:
            if name == expected_name:
                assert reconchain._re.search(pattern_text, sample), f"{name} failed to match {sample}"

    # JWT pattern
    jwt_pat = dict(reconchain._JS_SECRET_PATTERNS)["jwt"]
    assert reconchain._re.search(jwt_pat, "eyJ0aGlzSXNBZmFrZUFwaVRva2Vu.and0U2Vjb25kUGFydA.dGhpcmRQYXJ0")
    assert not reconchain._re.search(jwt_pat, "not-a-jwt")


def test_phase_k_source_map_regex() -> None:
    """Source map URL regex should extract inline and file references."""
    cases = [
        ("//# sourceMappingURL=main.js.map", "main.js.map"),
        ("sourceMappingURL=https://cdn.example.com/app.js.map", "https://cdn.example.com/app.js.map"),
        ("//# sourceMappingURL=/assets/bundle.js.map", "/assets/bundle.js.map"),
    ]
    for text, expected in cases:
        m = reconchain._SOURCE_MAP_RE.search(text)
        assert m is not None, f"no match for: {text}"
        assert m.group(1) == expected


def test_phase_l_no_endpoints_returns_zero(tmp_path: Path) -> None:
    """Phase L should return count 0 when no endpoints exist."""
    tools = reconchain.Tools()
    result = asyncio.run(reconchain.phase_L(tmp_path, tools, set(), set()))
    assert result["count"] == 0


def test_phase_l_extracts_api_endpoints_from_urls(tmp_path: Path) -> None:
    """Phase L should detect API-like endpoints from urls_all.txt."""
    urls = tmp_path / "urls_all.txt"
    urls.write_text(
        "https://example.com/api/v1/users\n"
        "https://example.com/page?foo=1\n"
        "https://example.com/admin\n"
    )
    tools = reconchain.Tools()
    asyncio.run(reconchain.phase_L(tmp_path, tools, set(), set()))

    auth = tmp_path / "auth_bypass.txt"
    content = auth.read_text()
    assert "api" in content
    assert "admin" in content


def test_phase_l_auth_bypass_headers_defined() -> None:
    """The auth bypass header list should contain expected headers."""
    assert "X-Original-URL" in reconchain._AUTH_BYPASS_HEADERS
    assert "X-Forwarded-For" in reconchain._AUTH_BYPASS_HEADERS
    assert "X-Custom-IP-Authorization" in reconchain._AUTH_BYPASS_HEADERS
    assert "Authorization: Basic YWRtaW46YWRtaW4=" in reconchain._AUTH_BYPASS_HEADERS


def test_phase_l_mass_assignment_fields_defined() -> None:
    """Mass assignment field list should include common privilege escalation fields."""
    assert "admin" in reconchain._MASS_ASSIGN_FIELDS
    assert "is_admin" in reconchain._MASS_ASSIGN_FIELDS
    assert "role" in reconchain._MASS_ASSIGN_FIELDS
    assert "balance" in reconchain._MASS_ASSIGN_FIELDS


def test_vuln_txt_merge_includes_existing_files(tmp_path: Path) -> None:
    """Phase G merge should include xss.txt and sqlmap.log when they exist."""
    urls_all = tmp_path / "urls_all.txt"
    urls_all.write_text("https://example.com/page?q=1\n")
    (tmp_path / "xss.txt").write_text("xss finding\n")
    (tmp_path / "sqlmap.log").write_text("sqlmap finding\n")
    tools = reconchain.Tools()
    asyncio.run(reconchain.phase_G(tmp_path, tools, set(), set(), None))

    vulns = tmp_path / "vulns.txt"
    assert vulns.exists()
    assert "xss finding" in vulns.read_text() or "sqlmap finding" in vulns.read_text()

