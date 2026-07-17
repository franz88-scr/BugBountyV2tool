"""Dedup engine — cross-scan finding deduplication with persistent state and fuzzy matching."""
import contextlib
import hashlib
import json
import os
import re
import threading
from pathlib import Path
from typing import Dict, List, Tuple


class DedupEngine:
    def __init__(self, state_path: Path) -> None:
        self.state_path = state_path
        self._seen: Dict[str, Dict[str, str]] = {}
        self._lock = threading.Lock()  # protects _seen mutations
        self._load()

    def _load(self) -> None:
        if self.state_path.exists():
            try:
                with self.state_path.open() as f:
                    self._seen = json.load(f)
            except (json.JSONDecodeError, OSError):
                self._seen = {}

    def _save(self) -> None:
        import tempfile
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=self.state_path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(self._seen, f)
            os.replace(tmp_path, self.state_path)
        except Exception:
            with contextlib.suppress(Exception):
                try:
                    os.unlink(tmp_path)
                except FileNotFoundError:
                    pass
            raise

    @staticmethod
    def _normalize_key(key: str) -> str:
        key = key.strip().lower()
        key = re.sub(r'[?#].*', '', key)
        key = re.sub(r'/+', '/', key)
        key = key.rstrip('/')
        return key

    @staticmethod
    def _content_fingerprint(content: str) -> str:
        normalized = re.sub(r'\s+', ' ', content.strip())
        return hashlib.sha256(normalized.encode()).hexdigest()

    def is_duplicate(self, key: str, content: str = "") -> Tuple[bool, str]:
        norm_key = self._normalize_key(key)
        with self._lock:
            existing = self._seen.get(norm_key)
            if existing is None:
                return False, norm_key
            if content:
                if existing.get("fingerprint"):
                    if existing["fingerprint"] == self._content_fingerprint(content):
                        return True, norm_key
                    return False, norm_key
                existing["fingerprint"] = self._content_fingerprint(content)
                return False, norm_key
            return True, norm_key

    MAX_SEEN = 50_000  # Cap to prevent unbounded memory growth

    def mark_seen(self, key: str, source: str = "", content: str = "") -> None:
        norm_key = self._normalize_key(key)
        entry: Dict[str, str] = {}
        if source:
            entry["source"] = source
        if content:
            entry["fingerprint"] = self._content_fingerprint(content)
        entry["ts"] = __import__("time").strftime("%Y-%m-%dT%H:%M:%S")
        with self._lock:
            self._seen[norm_key] = entry
            if len(self._seen) > self.MAX_SEEN:
                sorted_keys = sorted(self._seen.keys(), key=lambda k: self._seen[k].get("ts", ""))
                for k in sorted_keys[:len(self._seen) - self.MAX_SEEN]:
                    self._seen.pop(k, None)

    def get_all_seen_keys(self) -> List[str]:
        with self._lock:
            return list(self._seen.keys())

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return {"total_seen": len(self._seen)}

    def save(self) -> None:
        self._save()

    def clear(self) -> None:
        with self._lock:
            self._seen.clear()
        self._save()
