#!/usr/bin/env python3
"""
reconchain.py — backward-compat shim for vulnforge.

Delegates to the vulnforge/ package. The `reconchain` CLI command
and `reconchain.py` entry point still work via this shim.

Usage:
  python3 reconchain.py -d example.com -o ./out
  python3 reconchain.py --interactive
  python3 reconchain.py -d example.com --fast --proxy socks5://127.0.0.1:9050
"""
from __future__ import annotations
import sys

from vulnforge import main

if __name__ == "__main__":
    sys.exit(main())
