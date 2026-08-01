"""Regression tests for the wired-in library features (CLI flags + helpers)."""

from pathlib import Path

import pytest

from vulnforge.cli.parser import build_parser

try:
    import cryptography  # noqa: F401

    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

needs_crypto = pytest.mark.skipif(not HAVE_CRYPTO, reason="cryptography not installed")


@pytest.fixture
def parser():
    return build_parser()


class TestWiredFlags:
    def test_compliance_flags(self, parser) -> None:
        args = parser.parse_args(["--compliance", "--threat-intel"])
        assert args.compliance is True
        assert args.threat_intel is True

    def test_threat_feed_flag(self, parser) -> None:
        args = parser.parse_args(["--threat-feed", "feeds.json"])
        assert args.threat_feed == "feeds.json"

    def test_ml_classify_flags(self, parser) -> None:
        args = parser.parse_args(["--ml-classify", "--ml-min-confidence", "0.7"])
        assert args.ml_classify is True
        assert args.ml_min_confidence == 0.7

    def test_api_host_flag(self, parser) -> None:
        args = parser.parse_args(["--api-host", "127.0.0.2"])
        assert args.api_host == "127.0.0.2"

    def test_ml_select_flag(self, parser) -> None:
        args = parser.parse_args(["--ml-select", "12"])
        assert args.ml_select == 12
        assert parser.parse_args([]).ml_select == 0

    def test_credential_flags(self, parser) -> None:
        args = parser.parse_args(["--cred-set", "api_key", "sk-1"])
        assert args.cred_set == ["api_key", "sk-1"]
        args = parser.parse_args(["--cred-get", "api_key"])
        assert args.cred_get == "api_key"
        args = parser.parse_args(["--cred-rm", "api_key"])
        assert args.cred_rm == "api_key"
        assert parser.parse_args(["--cred-list"]).cred_list is True


class TestCredentialMetaCommands:
    @needs_crypto
    def test_set_get_list_rm_roundtrip(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from vulnforge.cli import helpers

        def fake_log(level: str, msg: str) -> None:
            pass

        monkeypatch.setattr(helpers, "log", fake_log)
        monkeypatch.setattr(
            "sys.argv",
            ["vulnforge", "--cred-dir", str(tmp_path), "--cred-set", "token", "value1"],
        )
        assert helpers.main() == 0

        monkeypatch.setattr("sys.argv", ["vulnforge", "--cred-dir", str(tmp_path), "--cred-list"])
        assert helpers.main() == 0

    def test_get_missing_credential_returns_1(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from vulnforge.cli import helpers

        def fake_log(level: str, msg: str) -> None:
            pass

        monkeypatch.setattr(helpers, "log", fake_log)
        monkeypatch.setattr(
            "sys.argv", ["vulnforge", "--cred-dir", str(tmp_path), "--cred-get", "missing"]
        )
        assert helpers.main() == 1

    def test_cred_set_without_crypto_returns_1(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        if HAVE_CRYPTO:
            pytest.skip("cryptography installed; error path not exercised")
        from vulnforge.cli import helpers

        monkeypatch.setattr(
            "sys.argv", ["vulnforge", "--cred-dir", str(tmp_path), "--cred-set", "k", "v"]
        )
        assert helpers.main() == 1


class TestOpenApi:
    def test_get_spec(self) -> None:
        from vulnforge.openapi import get_spec, validate_spec

        spec = get_spec()
        assert spec["openapi"].startswith("3.")
        result = validate_spec(spec)
        assert result["valid"] is True

    def test_generate_spec_file(self, tmp_path: Path) -> None:
        from vulnforge.openapi import generate_spec_file

        path = generate_spec_file(tmp_path)
        assert path.exists()
        assert path.read_text().startswith("{")


class TestTui:
    def test_lifecycle(self) -> None:
        from vulnforge.tui import get_tui

        tui = get_tui()
        tui.update(phases_total=10, phases_completed=2)
        tui.add_finding("some finding", "high")
        tui.start()
        tui.stop()
        assert tui._data["findings"] == 1
        assert tui._data["phases_total"] == 10


class TestApiSafety:
    def test_refuses_all_interfaces_bind(self, tmp_path: Path) -> None:
        from vulnforge.api import start_api_server

        with pytest.raises(ValueError):
            start_api_server(tmp_path, host="0.0.0.0", port=0)
