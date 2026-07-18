"""HTTP-based plugin marketplace for ReconChain.

Provides a registry interface for discovering, installing, updating,
and removing community-contributed phase plugins.

Usage:
    from reconchain.marketplace import PluginMarketplace
    mp = PluginMarketplace()
    plugins = mp.search("xss")
    mp.install("reconchain-plugin-ssrf")
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from reconchain.utils import ensure, log


DEFAULT_REGISTRY_URL = "https://registry.reconchain.dev/api/v1"
FALLBACK_REGISTRY_URL = "https://raw.githubusercontent.com/reconchain/plugins/main/registry.json"

# Local plugin directories searched for installed plugins
_PLUGIN_SEARCH_PATHS = [
    Path.home() / ".reconchain" / "plugins",
    Path("/usr/local/share/reconchain/plugins"),
]


@dataclass
class PluginManifest:
    """Metadata for a marketplace plugin."""
    name: str
    version: str
    description: str = ""
    author: str = ""
    tags: List[str] = field(default_factory=list)
    phase: str = ""
    min_reconchain: str = ""
    max_reconchain: str = ""
    dependencies: List[str] = field(default_factory=list)
    homepage: str = ""
    download_url: str = ""
    checksum: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "tags": list(self.tags),
            "phase": self.phase,
            "min_reconchain": self.min_reconchain,
            "max_reconchain": self.max_reconchain,
            "dependencies": list(self.dependencies),
            "homepage": self.homepage,
            "download_url": self.download_url,
            "checksum": self.checksum,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PluginManifest":
        return cls(
            name=d.get("name", ""),
            version=d.get("version", "0.0.0"),
            description=d.get("description", ""),
            author=d.get("author", ""),
            tags=d.get("tags", []),
            phase=d.get("phase", ""),
            min_reconchain=d.get("min_reconchain", ""),
            max_reconchain=d.get("max_reconchain", ""),
            dependencies=d.get("dependencies", []),
            homepage=d.get("homepage", ""),
            download_url=d.get("download_url", ""),
            checksum=d.get("checksum", ""),
        )


class PluginMarketplace:
    """HTTP-based plugin registry for discovery, install, and updates."""

    def __init__(
        self,
        registry_url: str = DEFAULT_REGISTRY_URL,
        plugin_dir: Optional[Path] = None,
    ) -> None:
        self._registry_url = registry_url
        self._plugin_dir = plugin_dir or Path.home() / ".reconchain" / "plugins"
        self._installed_path = self._plugin_dir / ".installed.json"
        self._installed: Dict[str, PluginManifest] = {}
        self._cache: Dict[str, Any] = {}
        self._cache_ttl: float = 300.0
        self._cache_ts: float = 0.0
        if self._installed_path.exists():
            self._load_installed()

    def _load_installed(self) -> None:
        try:
            data = json.loads(self._installed_path.read_text(encoding="utf-8"))
            for name, manifest_dict in data.get("plugins", {}).items():
                self._installed[name] = PluginManifest.from_dict(manifest_dict)
        except Exception as e:
            log("warn", f"marketplace: failed to load installed list: {e}")

    def _save_installed(self) -> None:
        ensure(self._installed_path)
        data = {
            "plugins": {name: m.to_dict() for name, m in self._installed.items()},
            "updated_at": time.time(),
        }
        self._installed_path.write_text(json.dumps(data, indent=2))

    def _fetch_registry(self, endpoint: str = "") -> Any:
        """Fetch from the plugin registry with fallback."""
        url = f"{self._registry_url}/{endpoint}".rstrip("/")
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
            log("warn", f"marketplace: primary registry unavailable: {e}")
            # Try fallback
            fallback = f"{FALLBACK_REGISTRY_URL}"
            try:
                req = urllib.request.Request(fallback, headers={"Accept": "application/json"})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except Exception:
                log("warn", f"marketplace: fallback registry also unavailable")
                return {}

    def search(self, query: str = "", *, tags: Optional[List[str]] = None) -> List[PluginManifest]:
        """Search the registry for plugins matching a query or tags.

        Args:
            query: Free-text search term (matched against name, description, tags).
            tags: Filter by specific tags (e.g., ["xss", "sqli"]).

        Returns:
            List of matching PluginManifest objects.
        """
        cached = self._fetch_registry("plugins")
        plugins_raw = cached.get("plugins", []) if isinstance(cached, dict) else []

        results: List[PluginManifest] = []
        for p_dict in plugins_raw:
            manifest = PluginManifest.from_dict(p_dict)
            match = True

            if query:
                q = query.lower()
                searchable = f"{manifest.name} {manifest.description} {' '.join(manifest.tags)}".lower()
                if q not in searchable:
                    match = False

            if tags and match:
                if not any(t in manifest.tags for t in tags):
                    match = False

            if match:
                results.append(manifest)

        return results

    def install(self, name: str, *, force: bool = False) -> Optional[PluginManifest]:
        """Install a plugin from the registry.

        Args:
            name: Plugin name to install.
            force: Reinstall even if already installed.

        Returns:
            The installed PluginManifest, or None on failure.
        """
        if name in self._installed and not force:
            log("info", f"marketplace: {name} already installed (use force=True to reinstall)")
            return self._installed[name]

        # Fetch plugin metadata
        plugin_data = self._fetch_registry(f"plugins/{name}")
        if not plugin_data:
            log("err", f"marketplace: plugin '{name}' not found in registry")
            return None

        manifest = PluginManifest.from_dict(plugin_data)
        download_url = manifest.download_url
        if not download_url:
            log("err", f"marketplace: no download URL for '{name}'")
            return None

        # Download and extract
        plugin_path = self._plugin_dir / name
        try:
            self._plugin_dir.mkdir(parents=True, exist_ok=True)
            tmp_dir = tempfile.mkdtemp(prefix="reconchain_marketplace_")

            # Download
            req = urllib.request.Request(download_url)
            with urllib.request.urlopen(req, timeout=60) as resp:
                archive_path = os.path.join(tmp_dir, "plugin.tar.gz")
                with open(archive_path, "wb") as f:
                    shutil.copyfileobj(resp, f)

            # Extract (tar.gz)
            import tarfile
            with tarfile.open(archive_path, "r:gz") as tar:
                tar.extractall(path=tmp_dir, filter="data")

            # Find extracted directory (single subdirectory expected)
            extracted_dirs = [
                d for d in Path(tmp_dir).iterdir()
                if d.is_dir() and not d.name.startswith(".")
            ]
            src = extracted_dirs[0] if extracted_dirs else Path(tmp_dir)

            # Move to plugin directory
            if plugin_path.exists():
                shutil.rmtree(plugin_path)
            shutil.move(str(src), str(plugin_path))

            # Cleanup
            shutil.rmtree(tmp_dir, ignore_errors=True)

            self._installed[name] = manifest
            self._save_installed()
            log("ok", f"marketplace: installed {name} v{manifest.version} → {plugin_path}")
            return manifest

        except Exception as e:
            log("err", f"marketplace: failed to install '{name}': {e}")
            shutil.rmtree(tmp_dir, ignore_errors=True)
            return None

    def uninstall(self, name: str) -> bool:
        """Remove an installed plugin.

        Returns:
            True if the plugin was removed successfully.
        """
        plugin_path = self._plugin_dir / name
        if plugin_path.exists():
            shutil.rmtree(plugin_path)
        if name in self._installed:
            del self._installed[name]
            self._save_installed()
            log("ok", f"marketplace: uninstalled {name}")
            return True
        log("warn", f"marketplace: {name} is not installed")
        return False

    def update(self, name: str) -> Optional[PluginManifest]:
        """Update an installed plugin to the latest version.

        Returns:
            The updated manifest, or None if already up-to-date or on failure.
        """
        if name not in self._installed:
            log("warn", f"marketplace: {name} is not installed")
            return None

        current = self._installed[name]
        remote_data = self._fetch_registry(f"plugins/{name}")
        if not remote_data:
            return None

        remote = PluginManifest.from_dict(remote_data)
        if remote.version == current.version:
            log("info", f"marketplace: {name} is already at latest version ({current.version})")
            return current

        log("info", f"marketplace: updating {name} from v{current.version} → v{remote.version}")
        return self.install(name, force=True)

    def list_installed(self) -> List[PluginManifest]:
        """Return all installed plugins."""
        return list(self._installed.values())

    def check_updates(self) -> List[Dict[str, Any]]:
        """Check for available updates for installed plugins.

        Returns:
            List of dicts with name, current_version, latest_version.
        """
        updates = []
        for name, current in self._installed.items():
            remote_data = self._fetch_registry(f"plugins/{name}")
            if remote_data:
                remote = PluginManifest.from_dict(remote_data)
                if remote.version != current.version:
                    updates.append({
                        "name": name,
                        "current_version": current.version,
                        "latest_version": remote.version,
                    })
        return updates

    def get_local_plugins(self) -> List[Dict[str, Any]]:
        """Scan local plugin directories for installed plugins.

        Returns list of dicts with name, path, and whether metadata is available.
        """
        results = []
        search_dirs = [self._plugin_dir] + [
            p for p in _PLUGIN_SEARCH_PATHS if p.exists()
        ]
        seen = set()
        for d in search_dirs:
            if not d.exists():
                continue
            for item in d.iterdir():
                if item.is_dir() and item.name not in seen and not item.name.startswith("."):
                    seen.add(item.name)
                    has_meta = (item / "manifest.json").exists()
                    results.append({
                        "name": item.name,
                        "path": str(item),
                        "has_manifest": has_meta,
                        "installed": item.name in self._installed,
                    })
        return results
