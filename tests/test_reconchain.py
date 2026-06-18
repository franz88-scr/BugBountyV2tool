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


def test_parser_help_and_rejects_invalid_domain() -> None:
    parser = reconchain.build_parser()
    with pytest.raises(SystemExit) as help_exit:
        parser.parse_args(["--help"])
    assert help_exit.value.code == 0

    with pytest.raises(SystemExit) as bad_domain:
        parser.parse_args(["-d", "bad_domain"])
    assert bad_domain.value.code == 2


def test_merge_unique_filters_and_avoids_self_merge(tmp_path: Path) -> None:
    src = tmp_path / "src.txt"
    dst = tmp_path / "dst.txt"
    src.write_text("b.example.com\n# comment\na.example.com\nbad_domain.example.com\n")
    dst.write_text("old.example.com\n")

    count = reconchain.merge_unique([src, dst], dst, reconchain._is_valid_hostname)

    assert count == 2
    assert dst.read_text().splitlines() == ["a.example.com", "b.example.com"]


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


def test_phase_f2_returns_real_count_without_tools(tmp_path: Path) -> None:
    (tmp_path / "host_targets.txt").write_text("https://a.example.com\n")
    (tmp_path / "testssl_a.txt").write_text("tls finding\n")
    tools = reconchain.Tools()

    result = asyncio.run(reconchain.phase_F2(tmp_path, tools, set(), set()))

    assert result["count"] == 1
    assert (tmp_path / "tls_wp.txt").read_text() == "tls finding\n"


def test_no_tool_pipeline_generates_reports_without_oast(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
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
    )

    rc = asyncio.run(reconchain.run_pipeline(args))

    assert rc == 0
    assert (tmp_path / "summary.json").exists()
    assert (tmp_path / "report.html").exists()
    assert (tmp_path / "report.md").exists()
    assert json.loads((tmp_path / "summary.json").read_text())["domain"] == "example.com"


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

