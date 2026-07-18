"""Phase 00: scope validation."""
from reconchain.phases.helpers import *


async def phase_00_SCOPE(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet,
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"00-SCOPE"}:
        return {}
    out = outdir / "scope_validated.txt"
    if out.exists() and not force:
        return {"00-SCOPE": str(out), "count": count_nonblank(out)}
    log("info", "Phase 00-SCOPE: scope validation")

    global _SCOPE_FILE, _SCOPE_PATTERNS
    scope_sources = [
        outdir / "scope.txt",
        outdir / "allowlist.txt",
        outdir / ".." / "scope.txt",
        Path.cwd() / "scope.txt",
        Path.cwd() / "allowlist.txt",
    ]
    scope_patterns: List[str] = []
    scope_file: Optional[Path] = None
    for sp in scope_sources:
        if sp.exists():
            scope_file = sp.resolve()
            scope_patterns = [ln.strip().lower() for ln in read_lines(sp) if ln.strip() and not ln.startswith("#")]
            if scope_patterns:
                log("ok", f"00-SCOPE: loaded {len(scope_patterns)} scope patterns from {scope_file}")
                break

    findings: List[str] = []
    if scope_patterns:
        _SCOPE_PATTERNS = scope_patterns
        _SCOPE_FILE = scope_file
        findings.append(f"scope_file={scope_file}")
        findings.append(f"scope_patterns={len(scope_patterns)}")
        for p in scope_patterns[:20]:
            findings.append(f"  pattern={p}")
        for asset_file in ("all_subs.txt", "resolved.txt", "hosts.txt", "host_targets.txt"):
            af = outdir / asset_file
            if af.exists():
                keep: List[str] = []
                dropped: List[str] = []
                for ln in read_lines(af):
                    h = ln.strip().lower().rstrip(".")
                    h = h.split("://")[-1].split("/")[0]
                    in_scope = any(
                        fnmatch.fnmatch(h, pattern) or h.endswith("." + pattern.lstrip("*."))
                        for pattern in scope_patterns
                    )
                    (keep if in_scope else dropped).append(ln)
                if dropped:
                    findings.append(f"  {asset_file}: {len(dropped)} out-of-scope assets dropped")
                    for d in dropped[:10]:
                        findings.append(f"    dropped={d.strip()}")
                    af.write_text("\n".join(keep) + ("\n" if keep else ""))
                findings.append(f"  {asset_file}: {len(keep)} in-scope assets retained")
        findings.append("[scope] validation complete")
    else:
        findings.append("[scope] No scope file found — running unrestricted")
        _SCOPE_FILE = None
        _SCOPE_PATTERNS = []

    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"00-SCOPE: {len(findings)} scope findings → {out}")
    return {"00-SCOPE": str(out), "count": len(findings)}
