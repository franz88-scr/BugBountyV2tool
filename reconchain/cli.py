"""CLI entry points: build_parser, main, InteractiveWizard.

This module is a backward-compatible wrapper. All functionality has been
decomposed into reconchain.cli.banner, reconchain.cli.parser,
reconchain.cli.wizard, and reconchain.cli.helpers.
"""
from __future__ import annotations

from reconchain.cli.banner import _banner
from reconchain.cli.helpers import _pid_alive, _run_single, main
from reconchain.cli.parser import build_parser
from reconchain.cli.wizard import InteractiveWizard

__all__ = [
    "_banner",
    "_pid_alive",
    "_run_single",
    "build_parser",
    "InteractiveWizard",
    "main",
]
