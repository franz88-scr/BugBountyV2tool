"""Dedup engine — cross-scan finding deduplication with persistent state and fuzzy matching."""
import contextlib
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Dict, List, Tuple


class DedupEngine:
    def __init__(self, state_path: Path) -> None:
        self.state_path = state_path
        self._seen: Dict[str, Dict[str, str]] = {}
        self._load()

    def _load(self) -> None:
        if self.state_path.exists():
            try:
                with self.state_path.open() as f:
                    self._seen = json.load(f)
            except (json.JSONDecodeError, OSError):
                self._seen = {}

    def _save(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        try:
            with tmp.open("w") as f:
                json.dump(self._seen, f, indent=2)
            os.replace(tmp, self.state_path)
        except Exception:
            with contextlib.suppress(Exception):
                tmp.unlink(missing_ok=True)
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
        normalized = re.sub(r'\s+', ' ', content.strip().lower())
        return hashlib.md5(normalized.encode()).hexdigest()

    def is_duplicate(self, key: str, content: str = "") -> Tuple[bool, str]:
        norm_key = self._normalize_key(key)
        existing = self._seen.get(norm_key)
        if existing is None:
            return False, norm_key
        if content and existing.get("fingerprint"):
            if existing["fingerprint"] == self._content_fingerprint(content):
                return True, norm_key
            return False, norm_key
        return True, norm_key

    def mark_seen(self, key: str, source: str = "", content: str = "") -> None:
        norm_key = self._normalize_key(key)
        entry: Dict[str, str] = {}
        if source:
            entry["source"] = source
        if content:
            entry["fingerprint"] = self._content_fingerprint(content)
        entry["ts"] = __import__("time").strftime("%Y-%m-%dT%H:%M:%S")
        self._seen[norm_key] = entry

    def get_all_seen_keys(self) -> List[str]:
        return list(self._seen.keys())

    def get_stats(self) -> Dict[str, int]:
        return {"total_seen": len(self._seen)}

    def save(self) -> None:
        self._save()

    def clear(self) -> None:
        self._seen.clear()
        self._save()
