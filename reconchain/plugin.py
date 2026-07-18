"""
reconchain.plugin — plugin/extension system for custom scan phases.

Plugins are Python files containing classes that subclass PhasePlugin.
They are discovered from:
  1. ~/.config/reconchain/plugins/
  2. --plugins-dir <path>

Each plugin becomes a first-class phase in the pipeline DAG.

Usage:
    # In a plugin file (e.g. my_scanner.py):
    from reconchain.plugin import PhasePlugin

    class MyScanner(PhasePlugin):
        name = "MY-SCANNER"
        stage = 12
        deps = {"05-HARVEST"}
        weight = 5
        description = "Custom scanner for widget endpoints"

        async def run(self, outdir, t, only, skip, prev, force=False):
            ...
            return {"MY-SCANNER": str(outpath), "count": len(findings)}

    # CLI:
    reconchain -d example.com --plugins-dir ./my_plugins
"""
from __future__ import annotations

import importlib.util
import inspect
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set

if TYPE_CHECKING:
    from reconchain.tools import Tools

from reconchain.config import VALID_PHASES
from reconchain.utils import log

_DEFAULT_PLUGIN_DIR = Path.home() / ".config" / "reconchain" / "plugins"

# PhaseSet type alias for signatures
PhaseSet = Set[str]


class PhasePlugin:
    """Base class for ReconChain plugins.

    Subclass this and set class attributes, then implement ``run()``.
    Each plugin becomes a first-class phase in the pipeline DAG with
    its own stage, dependencies, and resource weight.

    Class Attributes:
        name: Unique phase identifier (e.g. ``"MY-SCANNER"``).
        stage: DAG stage number (0-15). Higher stages run later.
        deps: Set of phase IDs that must complete before this plugin.
        weight: Resource weight (1-10). Affects adaptive concurrency.
        description: Human-readable description shown in ``--list-plugins``.

    Example::

        class MyScanner(PhasePlugin):
            name = "MY-SCANNER"
            stage = 12
            deps = {"05-HARVEST"}
            weight = 5

            async def run(self, outdir, t, only, skip, prev, force=False, **kwargs):
                # ... scan logic ...
                return {"MY-SCANNER": str(outpath)}
    """

    name: str = ""
    stage: int = 15
    deps: Set[str] = set()
    weight: int = 5
    description: str = ""

    async def run(
        self,
        outdir: Path,
        t: "Tools",
        only: PhaseSet,
        skip: PhaseSet,
        prev: Dict[str, Any],
        force: bool = False,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        from reconchain.exceptions import PluginError
        raise PluginError("plugin subclass must implement run()")


class _PluginMeta:
    __slots__ = ("cls", "source_file", "instance")

    def __init__(
        self, cls: type, source_file: Path, instance: PhasePlugin
    ) -> None:
        self.cls = cls
        self.source_file = source_file
        self.instance = instance


_registry: List[_PluginMeta] = []


def _discover_plugins(directory: Path) -> List[_PluginMeta]:
    """Scan a directory for .py files containing PhasePlugin subclasses."""
    found: List[_PluginMeta] = []
    if not directory.is_dir():
        return found

    for py_file in sorted(directory.glob("*.py")):
        if py_file.name.startswith("_"):
            continue
        try:
            spec = importlib.util.spec_from_file_location(
                f"reconchain_plugin_{py_file.stem}", str(py_file)
            )
            if spec is None or spec.loader is None:
                continue
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
        except Exception as exc:
            log(f"warn: failed to load plugin {py_file.name}: {exc}")
            continue

        for attr_name in dir(mod):
            obj = getattr(mod, attr_name)
            if (
                inspect.isclass(obj)
                and issubclass(obj, PhasePlugin)
                and obj is not PhasePlugin
                and getattr(obj, "name", "")
            ):
                try:
                    instance = obj()
                except Exception as exc:
                    log(f"warn: failed to instantiate plugin {obj.__name__}: {exc}")
                    continue
                found.append(_PluginMeta(cls=obj, source_file=py_file, instance=instance))
    return found


def discover_plugins(directories: Optional[List[Path]] = None) -> List[_PluginMeta]:
    """Discover plugins from default + custom directories.

    Scans ``~/.config/reconchain/plugins/`` first, then each directory
    in *directories*.  Duplicate plugin names are rejected with a warning.

    Returns:
        List of discovered plugin metadata objects.
    """
    dirs = list(directories or [])
    if _DEFAULT_PLUGIN_DIR.is_dir():
        dirs.insert(0, _DEFAULT_PLUGIN_DIR)

    seen_names: Set[str] = set()
    result: List[_PluginMeta] = []

    for d in dirs:
        for meta in _discover_plugins(d):
            if meta.instance.name in seen_names:
                log(f"warn: duplicate plugin name '{meta.instance.name}' from {meta.source_file}")
                continue
            seen_names.add(meta.instance.name)
            result.append(meta)

    global _registry
    _registry = result
    return result


def get_registry() -> List[_PluginMeta]:
    """Return the list of plugins discovered by :func:`discover_plugins`."""
    return list(_registry)


def register_plugin_to_pipeline(plugins: List[_PluginMeta]) -> None:
    """Inject discovered plugins into the pipeline data structures.

    This modifies the PIPELINE list, PHASE_DEPS, STAGES, _PHASE_WEIGHTS,
    and VALID_PHASES from reconchain.phases.__init__.
    """
    from reconchain.phases import __init__ as phases_init

    for meta in plugins:
        inst = meta.instance
        phase_id = inst.name

        if phase_id in VALID_PHASES:
            log(f"warn: plugin '{phase_id}' conflicts with built-in phase, skipping")
            continue

        VALID_PHASES.add(phase_id)

        # Build the parameter tuple matching the standard phase signature
        param_names = ("outdir", "t", "only", "skip", "prev", "force")

        # We store the actual bound method directly
        runner = inst.run

        phases_init.PIPELINE.append((phase_id, runner, param_names))

        # Inject dependency edges
        phases_init.PHASE_DEPS[phase_id] = set(inst.deps)

        # Inject into stage ordering (ensure stage list exists)
        while len(phases_init.STAGES) <= inst.stage:
            phases_init.STAGES.append([])
        phases_init.STAGES[inst.stage].append(phase_id)

        # Inject weight
        phases_init._PHASE_WEIGHTS[phase_id] = inst.weight

        log(f"ok: registered plugin '{phase_id}' (stage {inst.stage}, deps={inst.deps})")


def list_plugins_cli() -> None:
    """Print discovered plugins to stdout."""
    plugins = get_registry()
    if not plugins:
        print("No plugins discovered.")
        print(f"Place plugin .py files in: {_DEFAULT_PLUGIN_DIR}")
        print("Or use --plugins-dir <path>")
        return

    print(f"Discovered {len(plugins)} plugin(s):\n")
    for meta in plugins:
        inst = meta.instance
        print(f"  {inst.name}")
        print(f"    Stage:      {inst.stage}")
        print(f"    Deps:       {', '.join(sorted(inst.deps)) or '(none)'}")
        print(f"    Weight:     {inst.weight}")
        print(f"    File:       {meta.source_file}")
        if inst.description:
            print(f"    Description: {inst.description}")
        print()
