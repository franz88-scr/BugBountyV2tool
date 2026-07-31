"""Banner display for VulnForge CLI."""

from __future__ import annotations

from vulnforge.config import __version__
from vulnforge.utils import C


def _banner() -> None:
    """Display the VulnForge ASCII banner."""
    _top = "═" * 62
    _bot = "═" * 62
    banner = f"""
{C["c"]}  __    _______
{C["c"]}  \\ \\  / /| ___|
{C["y"]}   \\ \\/ / | _|
{C["y"]}    \\__/  |_|
{C["r"]}
{C["g"]}   ╔{_top}╗
{C["g"]}   ║{C["r"]}  {C["m"]}◆{C["r"]} {C["c"]}VulnForge v{__version__}{C["r"]}  {C["g"]}│  {C["y"]}Advanced Bug Bounty Pipeline{C["r"]}  {C["g"]}│  {C["d"]}Automated • Adaptive • Resilient{C["r"]}{C["g"]}  ║
{C["g"]}   ║{C["r"]}  {C["m"]}◆{C["r"]} {C["d"]}45+ tools  •  185 phases  •  27 DAG stages  •  Tor optimized{C["r"]}{C["g"]}     ║
{C["g"]}   ║{C["r"]}  {C["m"]}◆{C["r"]} {C["y"]}Adaptive Resource Monitor  |  Real-time TUI  |  Resumeable{C["r"]}{C["g"]}  ║
{C["g"]}   ╚{_bot}╝{C["r"]}
"""
    print(banner, flush=True)
