#!/usr/bin/env python3
"""
vulnforge.py — vulnerability forge orchestrator.

All phase logic, reporting, and pipeline orchestration live in
vulnforge/ submodules (vulnforge/phases/, reporting.py, pipeline.py, etc.).

Usage:
  python3 vulnforge.py -d example.com -o ./out
  python3 vulnforge.py --interactive
  python3 vulnforge.py -d example.com --fast --proxy socks5://127.0.0.1:9050
"""
from __future__ import annotations
import sys

from vulnforge import main

if __name__ == "__main__":
    sys.exit(main())
