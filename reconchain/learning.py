"""Learning module — track false positive patterns to improve future scans."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from reconchain.utils import ensure, log


class LearningEngine:
    """Learn from past scan reviews to reduce false positives."""

    def __init__(self, state_path: Path) -> None:
        self.state_path = state_path
        self._fp_patterns: Dict[str, int] = {}  # pattern -> occurrence count
        self._fp_hosts: Set[str] = set()
        self._fp_sources: Dict[str, int] = {}  # source -> fp count
        self._load()

    def _load(self) -> None:
        if self.state_path.exists():
            try:
                data = json.loads(self.state_path.read_text())
                self._fp_patterns = data.get("fp_patterns", {})
                self._fp_hosts = set(data.get("fp_hosts", []))
                self._fp_sources = data.get("fp_sources", {})
            except Exception:
                pass

    def _save(self) -> None:
        data = {
            "fp_patterns": self._fp_patterns,
            "fp_hosts": list(self._fp_hosts),
            "fp_sources": self._fp_sources,
        }
        ensure(self.state_path).write_text(json.dumps(data, indent=2))

    def learn_from_review(self, review_path: Path) -> int:
        """Learn from a finding_reviews.json file. Returns count of patterns learned."""
        if not review_path.exists():
            return 0

        reviews = json.loads(review_path.read_text())
        count = 0

        for finding_text, review in reviews.items():
            if review.get("status") != "false_positive":
                continue

            count += 1

            # Extract patterns from the FP
            # URL patterns
            url_match = re.search(r'https?://([^\s/]+)', finding_text)
            if url_match:
                host = url_match.group(1)
                self._fp_hosts.add(host)

            # Source tracking
            source = review.get("source", "unknown")
            self._fp_sources[source] = self._fp_sources.get(source, 0) + 1

            # Extract key tokens as patterns
            tokens = re.findall(r'\b\w{4,}\b', finding_text.lower())
            for token in tokens:
                self._fp_patterns[token] = self._fp_patterns.get(token, 0) + 1

        if count > 0:
            self._save()
            log("info", f"Learning: learned from {count} false positive patterns")

        return count

    def should_skip(self, finding_text: str) -> bool:
        """Check if a finding matches known FP patterns."""
        lower = finding_text.lower()

        # Check host patterns
        url_match = re.search(r'https?://([^\s/]+)', finding_text)
        if url_match:
            host = url_match.group(1)
            if host in self._fp_hosts:
                return True

        # Check if most tokens are FP patterns
        tokens = re.findall(r'\b\w{4,}\b', lower)
        if tokens:
            fp_count = sum(1 for t in tokens if t in self._fp_patterns and self._fp_patterns[t] >= 3)
            if fp_count / len(tokens) > 0.6:
                return True

        return False

    def get_stats(self) -> Dict[str, Any]:
        return {
            "fp_patterns": len(self._fp_patterns),
            "fp_hosts": len(self._fp_hosts),
            "fp_sources": dict(self._fp_sources),
        }
