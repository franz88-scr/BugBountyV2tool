"""Tests for the CLI sub-package (reconchain.cli)."""
import argparse
from io import StringIO
from unittest.mock import patch

import pytest

from reconchain.cli import build_parser, InteractiveWizard, main
from reconchain.cli.banner import _banner
from reconchain.cli.parser import build_parser as build_parser_direct


class TestBanner:
    def test_banner_returns_none(self):
        """_banner() prints to stdout and returns None."""
        result = _banner()
        assert result is None

    def test_banner_prints_to_stdout(self, capsys):
        _banner()
        captured = capsys.readouterr()
        assert "3.1.0" in captured.out
        assert "ReconChain" in captured.out

    def test_direct_import_same_as_package(self):
        assert build_parser is build_parser_direct


class TestParser:
    def test_build_parser_returns_argparse(self):
        parser = build_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_parser_has_domain_argument(self):
        parser = build_parser()
        args = parser.parse_args(["-d", "example.com"])
        assert args.domain == "example.com"

    def test_parser_has_only_argument(self):
        parser = build_parser()
        args = parser.parse_args(["--only", "01-RECON,04-SCAN", "-d", "example.com"])
        assert "01-RECON" in args.only
        assert "04-SCAN" in args.only

    def test_parser_has_skip_argument(self):
        parser = build_parser()
        args = parser.parse_args(["--skip", "01-RECON", "-d", "example.com"])
        assert "01-RECON" in args.skip

    def test_parser_has_out_argument(self):
        parser = build_parser()
        args = parser.parse_args(["-o", "/tmp/test_out", "-d", "example.com"])
        assert args.out == "/tmp/test_out"

    def test_parser_has_proxy_argument(self):
        parser = build_parser()
        args = parser.parse_args(["--proxy", "socks5://127.0.0.1:9050", "-d", "example.com"])
        assert args.proxy == "socks5://127.0.0.1:9050"

    def test_parser_has_force_argument(self):
        parser = build_parser()
        args = parser.parse_args(["--force", "-d", "example.com"])
        assert args.force is True

    def test_parser_has_resume_argument(self):
        parser = build_parser()
        args = parser.parse_args(["--resume", "-d", "example.com"])
        assert args.resume is True

    def test_parser_has_sample_argument(self):
        parser = build_parser()
        args = parser.parse_args(["--sample-urls-fuzz", "50", "-d", "example.com"])
        assert args.sample_urls_fuzz == 50

    def test_parser_has_api_port_argument(self):
        parser = build_parser()
        args = parser.parse_args(["--api-port", "8888", "-d", "example.com"])
        assert args.api_port == 8888

    def test_parser_has_interactive_argument(self):
        parser = build_parser()
        args = parser.parse_args(["-i"])
        assert args.interactive is True

    def test_parser_multiple_actions(self):
        parser = build_parser()
        args = parser.parse_args([
            "--only", "01-RECON,04-SCAN",
            "--skip", "04-SCAN",
            "--force",
            "-o", "/tmp/scan",
            "-d", "example.com",
        ])
        assert "01-RECON" in args.only
        assert "04-SCAN" in args.skip
        assert args.force is True
        assert args.out == "/tmp/scan"


class TestParserDefaults:
    def test_default_force_false(self):
        parser = build_parser()
        args = parser.parse_args(["-d", "example.com"])
        assert args.force is False

    def test_default_resume_false(self):
        parser = build_parser()
        args = parser.parse_args(["-d", "example.com"])
        assert args.resume is False

    def test_default_interactive_false(self):
        parser = build_parser()
        args = parser.parse_args(["-d", "example.com"])
        assert args.interactive is False

    def test_default_out_is_empty_string(self):
        parser = build_parser()
        args = parser.parse_args(["-d", "example.com"])
        assert args.out == ""


class TestInteractiveWizard:
    def test_wizard_instantiation(self):
        w = InteractiveWizard()
        assert w is not None

    def test_wizard_has_clean_input(self):
        from reconchain.cli.wizard import _clean_input
        assert callable(_clean_input)

    def test_wizard_has_prompt(self):
        from reconchain.cli.wizard import _prompt
        assert callable(_prompt)

    def test_wizard_has_prompt_yes_no(self):
        from reconchain.cli.wizard import _prompt_yes_no
        assert callable(_prompt_yes_no)


class TestHelpers:
    def test_main_is_callable(self):
        assert callable(main)
