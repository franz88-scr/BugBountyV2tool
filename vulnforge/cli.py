"""CLI entry points: build_parser, main, InteractiveWizard.

This module is a backward-compatible wrapper. All functionality has been
decomposed into vulnforge.cli.banner, vulnforge.cli.parser,
vulnforge.cli.wizard, and vulnforge.cli.helpers.
"""

from __future__ import annotations

from vulnforge.cli.banner import _banner
from vulnforge.cli.helpers import _pid_alive, _run_single, main
from vulnforge.cli.parser import build_parser
from vulnforge.cli.wizard import InteractiveWizard

__all__ = [
    "_banner",
    "_pid_alive",
    "_run_single",
    "build_parser",
    "InteractiveWizard",
    "main",
]
