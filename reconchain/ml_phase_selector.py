"""ML-assisted phase selection for ReconChain pipeline.

Uses statistical heuristics and TargetProfile data to predict which phases
are most likely to yield findings, enabling adaptive scan ordering.

This is a rule-based ML system (no external training data required) that
improves over time via feedback loops from scan results.

Usage:
    from reconchain.ml_phase_selector import select_optimal_phases, PhaseSelector
    selector = PhaseSelector()
    ranked = selector.rank_phases(profile, existing_findings)
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from reconchain.config import VALID_PHASES, DISCOVERY_PHASES
from reconchain.utils import ensure, log


# Phase → category mapping for scoring
PHASE_CATEGORIES: Dict[str, str] = {
    "01a-SCOPE-VALIDATE": "recon",
    "01b-APPS-RECORD": "recon",
    "02-SUBDOMAIN-ENUM": "recon",
    "03a-DNS-RESOLVE": "recon",
    "03b-REVERSE-DNS": "recon",
    "03c-PORT-SCAN": "discovery",
    "04a-SCREENSHOT": "discovery",
    "04b-TAKEOVER-VALIDATE": "discovery",
    "05-JAVASCRIPT-INTEL": "vuln",
    "06-PARAM-MINING": "vuln",
    "07-CORS-TEST": "vuln",
    "08-SSL-TEST": "vuln",
    "09-NUCLEI-SCAN": "vuln",
    "10-WAF-DETECT": "vuln",
    "11-XSS-SCAN": "vuln",
    "12-SQLI-SCAN": "vuln",
    "13-SSRF-TEST": "vuln",
    "14-LFI-SCAN": "vuln",
    "15-HEADER-SECURITY": "vuln",
    "16-WORDLIST-SCAN": "discovery",
    "17-SECRETS-SCAN": "vuln",
    "18-API-ENUM": "vuln",
    "19-GraphQL-SCAN": "vuln",
    "20-CLOUD-ENUM": "vuln",
    "21-CMS-DETECT": "discovery",
    "22-WEB-TECH": "recon",
    "23-CRAWL": "recon",
    "24-FUZZ": "vuln",
    "25-AUTH-TEST": "vuln",
    "26-REPORT": "meta",
    "27-CLEANUP": "meta",
}

# Findings-per-phase historical averages (baseline for scoring)
DEFAULT_PHASE_YIELD: Dict[str, float] = {
    "01a-SCOPE-VALIDATE": 1.0,
    "01b-APPS-RECORD": 2.0,
    "02-SUBDOMAIN-ENUM": 15.0,
    "03a-DNS-RESOLVE": 10.0,
    "03b-REVERSE-DNS": 3.0,
    "03c-PORT-SCAN": 8.0,
    "04a-SCREENSHOT": 0.0,
    "04b-TAKEOVER-VALIDATE": 1.0,
    "05-JAVASCRIPT-INTEL": 5.0,
    "06-PARAM-MINING": 4.0,
    "07-CORS-TEST": 2.0,
    "08-SSL-TEST": 2.0,
    "09-NUCLEI-SCAN": 5.0,
    "10-WAF-DETECT": 1.0,
    "11-XSS-SCAN": 3.0,
    "12-SQLI-SCAN": 1.5,
    "13-SSRF-TEST": 1.0,
    "14-LFI-SCAN": 1.5,
    "15-HEADER-SECURITY": 2.0,
    "16-WORDLIST-SCAN": 3.0,
    "17-SECRETS-SCAN": 2.0,
    "18-API-ENUM": 4.0,
    "19-GraphQL-SCAN": 2.0,
    "20-CLOUD-ENUM": 1.0,
    "21-CMS-DETECT": 1.0,
    "22-WEB-TECH": 3.0,
    "23-CRAWL": 10.0,
    "24-FUZZ": 4.0,
    "25-AUTH-TEST": 1.0,
}

# Priority weights for phase categories
CATEGORY_WEIGHTS = {
    "recon": 1.0,
    "discovery": 0.9,
    "vuln": 0.8,
    "meta": 0.1,
}


@dataclass
class PhaseScore:
    """Score and metadata for a single phase."""
    phase: str
    score: float
    category: str
    estimated_yield: float
    confidence: float
    reason: str


class PhaseSelector:
    """Rule-based ML system for phase selection and prioritization.

    Learns from historical scan results to improve phase ordering.
    Feedback is persisted to a JSON file in the output directory.
    """

    def __init__(self, feedback_path: Optional[Path] = None) -> None:
        self._feedback_path = feedback_path
        self._history: Dict[str, List[float]] = {}  # phase → list of yields
        if feedback_path and feedback_path.exists():
            self._load_feedback()

    def _load_feedback(self) -> None:
        if not self._feedback_path or not self._feedback_path.exists():
            return
        try:
            data = json.loads(self._feedback_path.read_text(encoding="utf-8"))
            self._history = data.get("history", {})
        except Exception:
            pass

    def _save_feedback(self) -> None:
        if not self._feedback_path:
            return
        ensure(self._feedback_path)
        data = {
            "history": self._history,
            "updated_at": time.time(),
        }
        self._feedback_path.write_text(json.dumps(data, indent=2))

    def record_result(self, phase: str, findings_count: int) -> None:
        """Record scan results for learning."""
        with _FEEDBACK_LOCK:
            if phase not in self._history:
                self._history[phase] = []
            self._history[phase].append(float(findings_count))
            # Keep last 100 results per phase
            if len(self._history[phase]) > 100:
                self._history[phase] = self._history[phase][-100:]
            self._save_feedback()

    def _get_historical_yield(self, phase: str) -> float:
        if phase in self._history and self._history[phase]:
            return sum(self._history[phase]) / len(self._history[phase])
        return DEFAULT_PHASE_YIELD.get(phase, 1.0)

    def _score_phase(
        self,
        phase: str,
        target_info: Dict[str, Any],
        existing_findings: Dict[str, int],
    ) -> PhaseScore:
        """Score a phase based on target characteristics and historical data."""
        category = PHASE_CATEGORIES.get(phase, "vuln")
        base_yield = self._get_historical_yield(phase)
        confidence = min(1.0, len(self._history.get(phase, [])) / 10.0)

        # Factor 1: Historical yield
        yield_score = min(1.0, base_yield / 20.0)

        # Factor 2: Target characteristics boost
        target_boost = 1.0
        reasons = []

        tech_stack = target_info.get("tech_stack", [])
        cms = target_info.get("cms", "")
        has_api = target_info.get("has_api", False)
        has_auth = target_info.get("has_auth", False)
        scope_size = target_info.get("scope_size", 0)

        # Tech-specific boosts
        if phase == "19-GraphQL-SCAN" and any("graphql" in t.lower() for t in tech_stack):
            target_boost = 2.0
            reasons.append("GraphQL detected in tech stack")
        elif phase == "21-CMS-DETECT" and cms:
            target_boost = 1.5
            reasons.append(f"CMS present: {cms}")
        elif phase == "18-API-ENUM" and has_api:
            target_boost = 1.8
            reasons.append("API endpoints detected")
        elif phase == "25-AUTH-TEST" and has_auth:
            target_boost = 1.5
            reasons.append("Authentication detected")

        # Scope-based scaling
        if scope_size > 1000:
            # Large scope: favor fast recon phases
            if category == "recon":
                target_boost *= 1.3
                reasons.append("large scope favors recon")
        elif scope_size < 10:
            # Small scope: skip to vuln phases
            if category == "vuln":
                target_boost *= 1.4
                reasons.append("small scope favors vuln scanning")

        # Factor 3: Discovery dependency — skip vuln phases if recon incomplete
        dep_penalty = 1.0
        if category in ("vuln", "discovery"):
            recon_findings = sum(
                existing_findings.get(p, 0)
                for p in DISCOVERY_PHASES
            )
            if recon_findings == 0 and not any(
                existing_findings.get(p, 0) > 0
                for p in ["01a-SCOPE-VALIDATE", "02-SUBDOMAIN-ENUM"]
            ):
                dep_penalty = 0.3
                reasons.append("penalized: no recon data yet")

        # Factor 4: Already-run phase penalty
        already_done_penalty = 1.0
        if phase in existing_findings and existing_findings[phase] > 0:
            already_done_penalty = 0.5
            reasons.append("phase already yielded findings")

        # Composite score
        cat_weight = CATEGORY_WEIGHTS.get(category, 0.5)
        final_score = (
            yield_score * 0.4
            + target_boost * 0.3
            + dep_penalty * 0.2
            + cat_weight * 0.1
        ) * already_done_penalty

        reason_str = "; ".join(reasons) if reasons else "baseline scoring"

        return PhaseScore(
            phase=phase,
            score=round(final_score, 4),
            category=category,
            estimated_yield=round(base_yield, 2),
            confidence=round(confidence, 2),
            reason=reason_str,
        )

    def rank_phases(
        self,
        target_info: Optional[Dict[str, Any]] = None,
        existing_findings: Optional[Dict[str, int]] = None,
        *,
        only_phases: Optional[Set[str]] = None,
    ) -> List[PhaseScore]:
        """Rank all phases by predicted usefulness.

        Args:
            target_info: Dict with keys like tech_stack, cms, has_api, has_auth, scope_size.
            existing_findings: Map of phase → finding count from current scan.
            only_phases: Restrict ranking to these phases.

        Returns:
            List of PhaseScore sorted by score descending.
        """
        target_info = target_info or {}
        existing_findings = existing_findings or {}
        phases = sorted(only_phases if only_phases else VALID_PHASES)

        scores = []
        for phase in phases:
            score = self._score_phase(phase, target_info, existing_findings)
            scores.append(score)

        scores.sort(key=lambda s: s.score, reverse=True)
        return scores

    def suggest_phases(
        self,
        target_info: Optional[Dict[str, Any]] = None,
        existing_findings: Optional[Dict[str, int]] = None,
        *,
        budget_phases: int = 15,
    ) -> List[str]:
        """Suggest the top N phases for a scan run.

        Args:
            target_info: Target characteristics for adaptive scoring.
            existing_findings: Current scan progress.
            budget_phases: Maximum number of phases to recommend.

        Returns:
            List of phase names ordered by priority.
        """
        ranked = self.rank_phases(target_info, existing_findings)
        # Always include metadata phases
        mandatory = {"01a-SCOPE-VALIDATE", "26-REPORT", "27-CLEANUP"}
        selected = [s.phase for s in ranked if s.phase in mandatory]
        for s in ranked:
            if s.phase not in mandatory and len(selected) < budget_phases:
                selected.append(s.phase)
        return selected

    def get_insights(self) -> Dict[str, Any]:
        """Return analysis of historical scan patterns."""
        insights: Dict[str, Any] = {}
        for phase, yields in self._history.items():
            if yields:
                insights[phase] = {
                    "runs": len(yields),
                    "avg_yield": round(sum(yields) / len(yields), 2),
                    "max_yield": round(max(yields), 2),
                    "min_yield": round(min(yields), 2),
                }
        return insights


_FEEDBACK_LOCK: object = object()


def select_optimal_phases(
    target_info: Optional[Dict[str, Any]] = None,
    existing_findings: Optional[Dict[str, int]] = None,
    feedback_path: Optional[Path] = None,
    **kwargs: Any,
) -> List[str]:
    """Convenience function for one-shot phase selection.

    Args:
        target_info: Target characteristics for scoring.
        existing_findings: Current findings per phase.
        feedback_path: Path to persist learning feedback.

    Returns:
        Ordered list of phase names to execute.
    """
    selector = PhaseSelector(feedback_path=feedback_path)
    return selector.suggest_phases(target_info, existing_findings, **kwargs)
