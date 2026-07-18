"""Banner display for ReconChain CLI."""
from __future__ import annotations

from reconchain.config import __version__
from reconchain.utils import C


def _banner() -> None:
    """Display the ReconChain ASCII banner."""
    _box = "═" * 56
    banner = f"""
{C["c"]}    ██████╗ ██████╗ ████████╗
{C["c"]}    ██╔══██╗██╔══██╗╚══██╔══╝
{C["c"]}    ██████╔╝██████╔╝   ██║
{C["c"]}    ██╔══██╗██╔══██╗   ██║
{C["c"]}    ██████╔╝██████╔╝   ██║
{C["c"]}    ╚═════╝ ╚═════╝    ╚═╝
{C["r"]}
{C["g"]}   ╔{_box}╗
{C["g"]}   ║  {C["c"]}ReconChain v{__version__}{C["g"]}  —  {C["y"]}Bug Bounty Recon & Vuln Pipeline{C["g"]}  ║
{C["g"]}   ║  {C["d"]}43+ tools  |  164 phases  |  27 DAG stages  |  Resumable{C["g"]}  ║
{C["g"]}   ║  {C["y"]}Adaptive Resource Monitor  |  Tor/SOCKS5 Optimized{C["g"]}   ║
{C["g"]}   ╚{_box}╝{C["r"]}
"""
    print(banner, flush=True)
