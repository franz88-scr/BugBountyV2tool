# Plugin Development Guide

ReconChain supports custom scan phases via a plugin system. Plugins are Python files containing classes that subclass `PhasePlugin` and are injected into the pipeline DAG as first-class phases.

## Quick Start

1. Create a plugin file:

```python
# my_scanner.py
from pathlib import Path
from typing import Any, Dict
from reconchain.plugin import PhasePlugin

class MyScanner(PhasePlugin):
    name = "MY-SCANNER"          # unique phase ID
    stage = 12                    # DAG stage (0-15); higher = runs later
    deps = {"05-HARVEST"}         # phase IDs that must complete first
    weight = 5                    # resource weight (1-10, higher = heavier)
    description = "Custom scanner for widget endpoints"

    async def run(self, outdir: Path, t, only, skip, prev, force=False, **kwargs):
        # Access previous phase results
        urls = prev.get("05-HARVEST", {}).get("urls", [])

        # Run your scan logic
        findings = []
        for url in urls:
            # ... your scanning code ...
            findings.append({"url": url, "vuln": "xss"})

        # Write findings to an artifact file
        outpath = outdir / "my_scanner.txt"
        with open(outpath, "w") as f:
            for finding in findings:
                f.write(f"{finding['url']} {finding['vuln']}\n")

        # Return artifact mapping (key = artifact filename)
        return {"MY-SCANNER": str(outpath), "count": len(findings)}
```

2. Place the file in one of:
   - `~/.config/reconchain/plugins/` (default)
   - A custom directory via `--plugins-dir ./my_plugins`

3. Run:
```bash
reconchain -d example.com --plugins-dir ./my_plugins
```

4. List discovered plugins:
```bash
reconchain --list-plugins --plugins-dir ./my_plugins
```

## PhasePlugin API

### Class Attributes

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `name` | `str` | `""` | Unique phase ID (e.g. `"MY-SCANNER"`). **Must be set.** |
| `stage` | `int` | `15` | DAG stage number. Phases in earlier stages run first. |
| `deps` | `Set[str]` | `set()` | Phase IDs this plugin depends on. |
| `weight` | `int` | `5` | Resource weight (1-10). Affects adaptive concurrency. |
| `description` | `str` | `""` | Human-readable description shown in `--list-plugins`. |

### `run()` Method

```python
async def run(
    self,
    outdir: Path,           # output directory for this scan
    t: Tools,               # tool availability checker (t.have("nuclei"))
    only: PhaseSet,         # --only filter (empty = run all)
    skip: PhaseSet,         # --skip filter
    prev: Dict[str, Any],   # results from previous phases
    force: bool = False,    # --force flag
    **kwargs: Any,          # additional context
) -> Dict[str, Any]:
```

**Return value**: A dict mapping artifact filenames to file paths. The pipeline uses this to track what your plugin produced.

### Accessing Previous Results

The `prev` dict maps phase IDs to their return values:

```python
async def run(self, outdir, t, only, skip, prev, force=False, **kwargs):
    # Get live hosts from phase 02
    live_hosts = prev.get("02-RESOLVE", {}).get("hosts", [])

    # Get URLs harvested in phase 05
    urls = prev.get("05-HARVEST", {}).get("urls", [])

    # Check if a phase ran
    if "04-SCAN" not in prev:
        log("warn", "Scan phase did not run, skipping")
        return {}
```

### Tool Detection

Use the `Tools` object to check if external tools are available:

```python
async def run(self, outdir, t, only, skip, prev, force=False, **kwargs):
    if not t.have("nuclei"):
        log("warn", "nuclei not installed, skipping custom scan")
        return {}

    if not t.have("httpx"):
        log("warn", "httpx not installed, skipping")
        return {}
```

## Plugin Discovery

Plugins are discovered from:

1. `~/.config/reconchain/plugins/` (checked first)
2. `--plugins-dir <path>` (additional directories)

Discovery rules:
- Only `.py` files are scanned (files starting with `_` are skipped)
- Each file is imported; classes subclassing `PhasePlugin` with a non-empty `name` are registered
- Duplicate `name` values are rejected with a warning
- Plugins that conflict with built-in phase names are skipped

## DAG Integration

When a plugin is registered, it is injected into the pipeline's DAG structures:

```
Plugin "MY-SCANNER" (stage=12, deps={"05-HARVEST"})
  ↓
VALID_PHASES.add("MY-SCANNER")
PIPELINE.append(("MY-SCANNER", run_method, params))
PHASE_DEPS["MY-SCANNER"] = {"05-HARVEST"}
STAGES[12].append("MY-SCANNER")
_PHASE_WEIGHTS["MY-SCANNER"] = 5
```

This means:
- The plugin runs in stage 12 (after all stage 11 phases complete)
- It only runs if `05-HARVEST` completed successfully
- It participates in adaptive concurrency (weight=5)
- It appears in `--only` and `--skip` filters

## Example: nuclei Template Scanner

```python
"""Custom nuclei template scanner plugin."""
import json
from pathlib import Path
from typing import Any, Dict
from reconchain.plugin import PhasePlugin
from reconchain.utils import log

class NucleiCustom(PhasePlugin):
    name = "CUSTOM-NUCLEI"
    stage = 9
    deps = {"02-RESOLVE", "05-HARVEST"}
    weight = 6
    description = "Run custom nuclei templates against live hosts"

    async def run(self, outdir: Path, t, only, skip, prev, force=False, **kwargs):
        if not t.have("nuclei"):
            log("warn", "nuclei not installed, skipping custom scan")
            return {}

        hosts_file = outdir / "live_hosts.txt"
        if not hosts_file.exists():
            log("warn", "no live hosts file found")
            return {}

        templates_dir = outdir / "custom-templates"
        if not templates_dir.exists():
            log("warn", "no custom templates directory")
            return {}

        # Run nuclei with custom templates
        cmd = [
            "nuclei", "-l", str(hosts_file),
            "-t", str(templates_dir),
            "-o", str(outdir / "custom_nuclei.txt"),
            "-json", "-silent",
        ]
        # ... execute via t or subprocess ...

        return {"CUSTOM-NUCLEI": str(outdir / "custom_nuclei.txt")}
```
