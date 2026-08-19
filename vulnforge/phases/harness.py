"""Phase harness: shared plumbing for phase implementations.

Every phase repeats the same mechanical shell: skip-check, cached-output
check, target-file resolution, findings writeback, result dict. These
helpers own that shell so a phase body contains only its probe logic.

Typical usage::

    async def phase_999_EXAMPLE(outdir, t, only, skip, prev, force=False):
        run = phase_begin("999-EXAMPLE", outdir, skip, force, "example.txt")
        if run is None:
            return {}
        targets = phase_targets(outdir, "hosts")
        if not targets:
            return run.no_targets("no HTTP targets")
        for host in targets:
            ...
            run.findings.append(f"[example] {host} ...")
        return run.done()
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from vulnforge.phases.helpers import PhaseSet
from vulnforge.utils import count_nonblank, ensure, log, read_lines


@dataclass
class PhaseRun:
    """Accumulates findings for one phase and writes them on ``done``.

    ``done`` never writes a file when there are no findings (matches
    ``utils.write_findings``), so counts stay honest and empty phases do not
    emit a fake "[no X detected (expected)]" line into the findings output.
    """

    name: str
    outdir: Path
    out: Path
    findings: List[str] = field(default_factory=list)
    _cached: bool = False

    def no_targets(self, reason: str) -> Dict[str, Any]:
        """Abort a phase because there is nothing to probe."""
        log("warn", f"{self.name}: {reason}")
        return {self.name: str(self.out), "count": 0}

    def done(self) -> Dict[str, Any]:
        """Persist findings (or reuse a cached result) and return the result dict."""
        if self._cached:
            return {self.name: str(self.out), "count": count_nonblank(self.out)}
        if not self.findings:
            if self.out.exists():
                self.out.unlink()
            return {self.name: str(self.out), "count": 0}
        ensure(self.out).write_text("\n".join(self.findings) + "\n")
        log("ok", f"{self.name}: {len(self.findings)} findings -> {self.out}")
        return {self.name: str(self.out), "count": len(self.findings)}


def phase_begin(
    name: str,
    outdir: Path,
    skip: PhaseSet,
    force: bool = False,
    outfile: str = "",
) -> Optional[PhaseRun]:
    """Gate a phase on skip/cache and return a :class:`PhaseRun`.

    Returns ``None`` when the phase is skipped; the caller returns ``{}``.
    When a cached result exists, the returned ``PhaseRun.done()`` reproduces
    the cached count without re-running the probe.
    """
    if skip & {name}:
        return None
    out = outdir / outfile
    if outfile and out.exists() and not force:
        log("ok", f"Phase {name}: cached ({count_nonblank(out)} findings)")
        return PhaseRun(name=name, outdir=outdir, out=out, _cached=True)
    log("info", f"Phase {name}: running")
    return PhaseRun(name=name, outdir=outdir, out=out)


def phase_targets(outdir: Path, kind: str = "hosts", https: bool = True) -> List[str]:
    """Resolve the phase's target list from standard artifact files.

    ``kind="hosts"`` reads ``host_targets.txt`` (falling back to ``hosts.txt``)
    and prepends ``https://`` unless already present. ``kind="urls"`` reads
    ``urls_all.txt``. Returns an empty list when the file is missing.
    """
    if kind == "urls":
        urls_file = outdir / "urls_all.txt"
        return read_lines(urls_file) if urls_file.exists() else []
    hosts_file = outdir / "host_targets.txt"
    if not hosts_file.exists():
        hosts_file = outdir / "hosts.txt"
    lines = read_lines(hosts_file)
    if not https:
        return lines
    return [f"https://{h}" if not h.startswith("http") else h for h in lines]
