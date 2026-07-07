"""Configuration constants, dataclasses, and pipeline definitions."""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import List, Set

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)
__version__ = "1.5.1"

VALID_PHASES = {
    "00-SCOPE", "01-RECON", "02-RESOLVE", "03-PERMUTE", "04-SCAN",
    "04b-TAKEOVER-VALIDATE", "05-HARVEST", "05b-APISPEC", "06-JSINTEL",
    "07-PARAMS", "08-FUZZ", "09-VULNSCAN", "10-TLSCMS", "11-INJECT",
    "11a-DOMXSS", "11b-SQLMAP", "12-SSTI", "13-OOB", "14-ORIGIN", "15-SECRETS",
    "16A-AUTHZ", "16B-MASSASSIGN", "17-IDOR", "17B-SSRFMETA", "18-CLOUD",
    "19-GIT", "20-GRAPHQL", "21-WAF", "22-NOSQLI", "23-RACE", "24-JWT",
    "25-XXE", "26-CMDINJECT", "27-SSPP", "28-CACHED", "29-DEPCHECK",
    "30-LFI", "31-OPENREDIR", "32-CLICKJACK", "33-CRLF", "34-RATELIMIT",
    "35-CORSADV", "36-JWTADV", "37-FILEUPLOAD", "38-SMUGGLE", "38b-H2SMUGGLE",
    "39-OAUTH", "40-PWRESET", "41-WEBSOCKET", "42-LDAP", "43-DESERIAL", "44-CHAIN",
    "45-EVIDENCE", "46-BUCKET", "47-CDN", "48-CONTENT", "49-FRAMEWORKS",
}
FAST_PHASES = {"00-SCOPE", "01-RECON", "02-RESOLVE", "04-SCAN", "05-HARVEST"}
PhaseSet = Set[str]

_SAFE_HOST = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$")


@dataclass
class PipelineConfig:
    """Shared configuration carried through the pipeline."""
    sqlmap_level: int = 1
    sqlmap_risk: int = 1
    delay: float = 0.0
    rate_limit: int = 0
    sample_urls_fuzz: int = 200
    sample_urls_params: int = 15
    sample_urls_arjun_waf: int = 5
    sample_hosts_ssl: int = 3
    sample_hosts_origin: int = 10
    sample_endpoints_l: int = 20
    sample_urls_xss_blind: int = 20
    sample_urls_ssti: int = 5
    sample_endpoints_post: int = 5
    sample_endpoints_cors: int = 10
    nuclei_exclude_tags: str = ""
    proxy: str = ""
    sample_hosts_cloud: int = 5
    sample_hosts_git: int = 5
    sample_hosts_graphql: int = 5
    sample_hosts_waf: int = 5
    sample_urls_nosqli: int = 30
    sample_endpoints_race: int = 10
    sample_hosts_jwt: int = 20
    sample_urls_xxe: int = 10
    sample_urls_cmdi: int = 30
    sample_endpoints_sspp: int = 10
    sample_hosts_cached: int = 10
    sample_urls_depcheck: int = 30
    sample_urls_redirect: int = 30
    sample_hosts_clickjack: int = 20
    sample_urls_crlf: int = 20
    sample_hosts_ratelimit: int = 10
    sample_endpoints_ratelimit: int = 5
    sample_endpoints_corsadv: int = 10
    sample_hosts_jwtadv: int = 20
    sample_urls_upload: int = 10
    sample_hosts_smuggle: int = 10
    sample_endpoints_oauth: int = 10
    sample_endpoints_pwreset: int = 10
    sample_hosts_websocket: int = 10
    sample_urls_ldap: int = 20
    sample_endpoints_deserial: int = 10
    sample_urls_lfi: int = 30
    sample_urls_idor: int = 50
    sample_urls_apisec: int = 50
    sample_urls_domxss: int = 30
    sample_hosts_h2smuggle: int = 10
    sample_hosts_frameworks: int = 20
    takeover_validate: bool = True
    waf_detected: bool = False
    waf_evasion_throttle: float = 0.0
    credentials_queue: List[str] = field(default_factory=list)



