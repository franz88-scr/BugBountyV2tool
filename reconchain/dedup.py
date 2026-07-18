"""Dedup engine — cross-scan finding deduplication with persistent state and fuzzy matching."""
import contextlib
import difflib
import hashlib
import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


class DedupEngine:
    FUZZY_THRESHOLD = 0.85  # Minimum similarity ratio for fuzzy dedup
    MAX_SEEN = 50_000  # Cap to prevent unbounded memory growth
    _PREFIX_LEN = 4  # First N chars used for prefix-based candidate narrowing

    def __init__(self, state_path: Path) -> None:
        self.state_path = state_path
        self._seen: Dict[str, Dict[str, str]] = {}
        self._prefix_index: Dict[str, Set[str]] = {}  # prefix -> set of keys
        self._lock = threading.Lock()  # protects _seen mutations
        self._load()

    def _load(self) -> None:
        if self.state_path.exists():
            try:
                with self.state_path.open() as f:
                    self._seen = json.load(f)
                # Rebuild prefix index
                for k in self._seen:
                    prefix = k[:self._PREFIX_LEN]
                    self._prefix_index.setdefault(prefix, set()).add(k)
            except (json.JSONDecodeError, OSError):
                self._seen = {}
                self._prefix_index = {}

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

    def _add_prefix(self, key: str) -> None:
        prefix = key[:self._PREFIX_LEN]
        self._prefix_index.setdefault(prefix, set()).add(key)

    def _remove_prefix(self, key: str) -> None:
        prefix = key[:self._PREFIX_LEN]
        bucket = self._prefix_index.get(prefix)
        if bucket is not None:
            bucket.discard(key)
            if not bucket:
                self._prefix_index.pop(prefix, None)

    def is_duplicate(self, key: str, content: str = "") -> Tuple[bool, str]:
        norm_key = self._normalize_key(key)
        with self._lock:
            existing = self._seen.get(norm_key)
            if existing is None:
                # Fuzzy matching: only compare against keys sharing the same prefix
                fuzzy_match = self._fuzzy_match(norm_key)
                if fuzzy_match:
                    return True, fuzzy_match
                return False, norm_key
            if content:
                if existing.get("fingerprint"):
                    if existing["fingerprint"] == self._content_fingerprint(content):
                        return True, norm_key
                    return False, norm_key
                existing["fingerprint"] = self._content_fingerprint(content)
                return False, norm_key
            return True, norm_key

    def _fuzzy_match(self, key: str) -> Optional[str]:
        """Check if key is similar to any existing key using prefix-indexed candidates."""
        # Narrow candidates by prefix — only compare keys with matching prefix
        prefix = key[:self._PREFIX_LEN]
        candidates = self._prefix_index.get(prefix, set())
        if not candidates:
            return None
        best_match: Optional[str] = None
        best_ratio = 0.0
        for seen_key in candidates:
            ratio = difflib.SequenceMatcher(None, key, seen_key).ratio()
            if ratio > best_ratio:
                best_ratio = ratio
                best_match = seen_key
        if best_ratio >= self.FUZZY_THRESHOLD and best_match is not None:
            return best_match
        return None

    def mark_seen(self, key: str, source: str = "", content: str = "") -> None:
        norm_key = self._normalize_key(key)
        entry: Dict[str, str] = {}
        if source:
            entry["source"] = source
        if content:
            entry["fingerprint"] = self._content_fingerprint(content)
        entry["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        with self._lock:
            self._seen[norm_key] = entry
            self._add_prefix(norm_key)
            if len(self._seen) > self.MAX_SEEN:
                # Evict oldest entries by timestamp
                evict_count = len(self._seen) - self.MAX_SEEN
                all_keys = [(v.get("ts", ""), k) for k, v in self._seen.items()]
                all_keys.sort(key=lambda x: x[0])
                for _, k in all_keys[:evict_count]:
                    self._seen.pop(k, None)
                    self._remove_prefix(k)

    def get_all_seen_keys(self) -> List[str]:
        with self._lock:
            return list(self._seen.keys())

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return {"total_seen": len(self._seen)}

    def save(self) -> None:
        with self._lock:
            self._save()

    def clear(self) -> None:
        with self._lock:
            self._seen.clear()
            self._prefix_index.clear()
        self._save()
