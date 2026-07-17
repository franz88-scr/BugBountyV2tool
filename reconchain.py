#!/usr/bin/env python3
"""
reconchain.py — recon orchestrator.

This is now a thin shim that delegates to the reconchain/ package.
All phase logic, reporting, and pipeline orchestration live in
reconchain/ submodules (reconchain/phases/, reporting.py, pipeline.py, etc.).

Usage:
  python3 reconchain.py -d example.com -o ./out
  python3 reconchain.py --interactive
  python3 reconchain.py -d example.com --fast --proxy socks5://127.0.0.1:9050
"""
from __future__ import annotations
import sys

from reconchain import main

if __name__ == "__main__":
    sys.exit(main())
