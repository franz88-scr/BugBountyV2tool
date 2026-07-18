"""Target profiling — pre-scan analysis that auto-tunes scanning parameters.

Builds a TargetProfile from initial recon data and adjusts pipeline
configuration for optimal scan performance and accuracy.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from reconchain.utils import log, read_lines


@dataclass
class TargetProfile:
    """Profile of a scan target built from initial recon."""
    domain: str = ""
    subdomain_count: int = 0
    ip_count: int = 0
    url_count: int = 0
    tech_stack: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)
    cdn: str = ""
    cloud_provider: str = ""
    waf_detected: bool = False
    has_api: bool = False
    has_graphql: bool = False
    has_auth: bool = False
    size_category: str = "medium"  # small, medium, large, huge
    recommended_profile: str = "standard"

    def should_run(self, phase_name: str) -> bool:
        """Determine if a phase should run based on the profile."""
        phase_upper = phase_name.upper()

        # Skip framework-specific phases if framework not detected
        framework_phase_map = {
            "121-IISASPNET": ["iis", "asp.net", "microsoft-iis"],
            "122-TOMCAT": ["tomcat", "apache-tomcat"],
            "123-NODEJS": ["node.js", "express", "next.js"],
            "124-LARAVEL": ["laravel", "php"],
            "125-DJANGO": ["django", "python"],
            "126-SYMFONY": ["symfony"],
        }
        if phase_upper in framework_phase_map:
            required_techs = framework_phase_map[phase_upper]
            if not any(t.lower() in [s.lower() for s in self.tech_stack + self.frameworks] for t in required_techs):
                return False

        # Skip cloud phases if not cloud-hosted
        cloud_phases = {"18-CLOUD", "46-BUCKET", "50-BUCKET-PERMS", "52-SERVERLESS"}
        if phase_upper in cloud_phases and not self.cloud_provider:
            return False

        # Skip GraphQL if no GraphQL detected
        if "GRAPHQL" in phase_upper and not self.has_graphql:
            return False

        # Skip auth phases if no auth detected (conservative)
        auth_phases = {"39-OAUTH", "40-PWRESET", "61-OAUTH-ADV", "82-OAUTHDEEP", "92-SAML"}
        if phase_upper in auth_phases and not self.has_auth:
            return False

        # For huge targets, skip low-signal phases
        if self.size_category == "huge":
            skip_huge = {
                "84-WHOIS", "85-ASN", "89-PASSIVEDNS",
                "115-BANNER", "116-PHPINFO", "117-SRVSTATUS",
                "119-WILDCARDDNS", "120-DNSREBIND",
            }
            if phase_upper in skip_huge:
                return False

        return True

    def get_sampling_multiplier(self) -> float:
        """Get a multiplier for sample sizes based on target size."""
        multipliers = {
            "small": 2.0,
            "medium": 1.0,
            "large": 0.5,
            "huge": 0.25,
        }
        return multipliers.get(self.size_category, 1.0)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "subdomain_count": self.subdomain_count,
            "ip_count": self.ip_count,
            "url_count": self.url_count,
            "tech_stack": self.tech_stack,
            "frameworks": self.frameworks,
            "cdn": self.cdn,
            "cloud_provider": self.cloud_provider,
            "waf_detected": self.waf_detected,
            "has_api": self.has_api,
            "has_graphql": self.has_graphql,
            "has_auth": self.has_auth,
            "size_category": self.size_category,
            "recommended_profile": self.recommended_profile,
        }


def _detect_tech_from_httpx(tech_line: str) -> List[str]:
    """Extract technology names from httpx tech output."""
    techs = []
    for part in re.split(r'[,;\s]+', tech_line):
        part = part.strip().strip('[]')
        if part and len(part) > 1:
            techs.append(part)
    return techs


def _detect_cloud_provider(techs: List[str]) -> str:
    """Detect cloud provider from technology stack."""
    tech_str = " ".join(techs).lower()
    if "cloudflare" in tech_str:
        return "cloudflare"
    if any(x in tech_str for x in ["aws", "amazon", "s3", "cloudfront"]):
        return "aws"
    if any(x in tech_str for x in ["gcp", "google", "firebase"]):
        return "gcp"
    if any(x in tech_str for x in ["azure", "microsoft"]):
        return "azure"
    if "akamai" in tech_str:
        return "akamai"
    if "fastly" in tech_str:
        return "fastly"
    return ""


def _detect_frameworks(techs: List[str]) -> List[str]:
    """Detect web frameworks from technology stack."""
    frameworks = []
    known = [
        "django", "flask", "express", "next.js", "react", "angular", "vue",
        "laravel", "spring", "rails", "rails", "asp.net", "tomcat",
        "nginx", "apache", "caddy", "node.js", "php", "python", "ruby",
        "wordpress", "drupal", "joomla", "magento", "shopify",
    ]
    for t in techs:
        t_lower = t.lower()
        for k in known:
            if k in t_lower:
                frameworks.append(t)
                break
    return frameworks


def build_target_profile(outdir: Path, domain: str) -> TargetProfile:
    """Build a target profile from existing scan artifacts."""
    profile = TargetProfile(domain=domain)

    # Count subdomains
    subs_file = outdir / "all_subs.txt"
    if subs_file.exists():
        profile.subdomain_count = len(read_lines(subs_file))

    # Count IPs
    resolved_file = outdir / "resolved.txt"
    if resolved_file.exists():
        ips = set()
        for line in read_lines(resolved_file):
            parts = line.split()
            if len(parts) >= 2 and re.match(r'^\d+\.\d+\.\d+\.\d+$', parts[1]):
                ips.add(parts[1])
        profile.ip_count = len(ips)

    # Count URLs
    urls_file = outdir / "urls_all.txt"
    if urls_file.exists():
        profile.url_count = len(read_lines(urls_file))

    # Detect tech stack
    tech_file = outdir / "tech.txt"
    if tech_file.exists():
        all_techs = []
        for line in read_lines(tech_file):
            all_techs.extend(_detect_tech_from_httpx(line))
        profile.tech_stack = list(set(all_techs))
        profile.frameworks = _detect_frameworks(all_techs)
        profile.cloud_provider = _detect_cloud_provider(all_techs)

    # Detect CDN
    tech_str = " ".join(profile.tech_stack).lower()
    for cdn in ["cloudflare", "akamai", "fastly", "cloudfront", "maxcdn", "incapsula"]:
        if cdn in tech_str:
            profile.cdn = cdn
            break

    # Detect WAF
    waf_file = outdir / "waf_detection.txt"
    if waf_file.exists():
        waf_text = " ".join(read_lines(waf_file)).lower()
        profile.waf_detected = "detected" in waf_text and "no waf" not in waf_text

    # Detect API
    api_file = outdir / "api_specs.txt"
    if api_file.exists() and api_file.stat().st_size > 0:
        profile.has_api = True

    # Detect GraphQL
    gql_file = outdir / "graphql_introspection.txt"
    if gql_file.exists() and gql_file.stat().st_size > 0:
        profile.has_graphql = True

    # Detect auth endpoints
    urls_file = outdir / "urls_all.txt"
    if urls_file.exists():
        auth_patterns = re.compile(r'(login|signin|auth|oauth|saml|register|signup|callback)', re.I)
        for line in read_lines(urls_file)[:500]:
            if auth_patterns.search(line):
                profile.has_auth = True
                break

    # Determine size category
    total = profile.subdomain_count + profile.url_count
    if total < 50:
        profile.size_category = "small"
    elif total < 500:
        profile.size_category = "medium"
    elif total < 5000:
        profile.size_category = "large"
    else:
        profile.size_category = "huge"

    # Recommend profile
    if profile.size_category == "small":
        profile.recommended_profile = "full"
    elif profile.size_category == "large":
        profile.recommended_profile = "standard"
    elif profile.size_category == "huge":
        profile.recommended_profile = "quick"

    log("info", f"Target profile: {profile.size_category} ({profile.subdomain_count} subs, "
        f"{profile.url_count} urls, {profile.ip_count} IPs, cdn={profile.cdn or 'none'})")

    return profile


def save_profile(profile: TargetProfile, outdir: Path) -> Path:
    """Save target profile to JSON."""
    out = outdir / "target_profile.json"
    out.write_text(json.dumps(profile.to_dict(), indent=2, default=str))
    return out


def load_profile(outdir: Path) -> Optional[TargetProfile]:
    """Load target profile from JSON."""
    path = outdir / "target_profile.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        p = TargetProfile(**{k: v for k, v in data.items() if hasattr(TargetProfile, k)})
        return p
    except Exception:
        return None
