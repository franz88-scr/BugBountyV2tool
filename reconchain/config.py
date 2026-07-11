"""Configuration constants, dataclasses, and pipeline definitions."""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import List, Set

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.?$"
)
__version__ = "1.5.1"

VALID_PHASES = {
    "00-SCOPE", "01-RECON", "02-RESOLVE", "03-PERMUTE", "04-SCAN",
    "04b-TAKEOVER-VALIDATE", "05-HARVEST", "05b-APISPEC", "06-JSINTEL",
    "07-PARAMS", "08-FUZZ", "09-VULNSCAN", "10-TLSCMS", "11-INJECT",
    "11a-DOMXSS", "11b-SQLMAP", "12-SSTI", "13-OOB", "14-ORIGIN", "15-SECRETS",
    "16a-AUTHZ", "16b-MASSASSIGN", "17-IDOR", "17b-SSRFMETA", "18-CLOUD",
    "19-GIT", "20-GRAPHQL",     "21-WAF", "21b-WAFBYPASS", "22-NOSQLI", "23-RACE", "24-JWT",
    "25-XXE", "26-CMDINJECT", "27-SSPP", "28-CACHED", "29-DEPCHECK",
    "30-LFI", "31-OPENREDIR", "32-CLICKJACK", "33-CRLF", "34-RATELIMIT",
    "35-CORSADV", "36-JWTADV", "37-FILEUPLOAD", "38-SMUGGLE", "38b-H2SMUGGLE",
    "39-OAUTH", "40-PWRESET", "41-WEBSOCKET", "42-LDAP", "43-DESERIAL", "44-CHAIN",
    "45-EVIDENCE", "46-BUCKET", "47-CDN", "48-CONTENT", "49-FRAMEWORKS",
    "50-BUCKET-PERMS", "51-HPP", "52-SERVERLESS", "53-CSP", "54-WS-FUZZ",
    "55-CSV-INJECT", "56-EXPOSED-DB", "57-DEFAULT-CREDS", "58-HOST-INJECT",
    "59-EMAIL-SEC", "60-SMTP-ENUM", "61-OAUTH-ADV", "62-LOG-INJECT",     "63-DOC-ATTACK", "64-IDEMPOTENCY",
     "65-SESSION", "66-SSRF-FULL", "67-PATHNORM", "68-DEPCVE",
     "69-DNSZT", "70-PORTFULL", "71-EMHARVEST",
    "72-ACCOUNTENUM", "73-CSPBYPASS", "74-GHTOOLS", "75-MOBILEAPI",
    "76-WORKFLOW", "77-CACHEKEY", "78-FILEUPLOADADV", "79-SECRETDIFF",
     "80-STOREXSS", "81-IDORFUZZ", "82-OAUTHDEEP", "83-RACEBURST",
    "84-WHOIS", "85-ASN", "86-DORK", "87-SHODAN", "88-EMPLOYEE", "89-PASSIVEDNS",
    "90-CSRF", "91-SESSIONFIX", "92-SAML", "93-PWDSPRAY", "94-COOKIEAUDIT",
    "95-POSTTEST", "96-METHODOVERRIDE", "97-FORCEDBROWSE", "98-CASEBYPASS",
    "99-APIPAGE", "99a-TABNAB", "99b-APIKEYLEAK", "99c-REDIRABUSE",
    "99d-LOGTRIGGER", "99e-XSSSTORED", "99f-HOSTABUSE", "99g-AUTHBYPASSADV",
    "100-SSI", "101-JSONINJECT", "102-NULLBYTE", "103-DOUBLEENCOD", "104-UNICODE",
    "105-POSTMSGXSS", "106-JSONP", "107-SRI", "108-MIXEDCONTENT", "109-HSTSPRELOAD",
    "110-THIRDPARTYJS", "111-BROWSERSTORAGE", "112-RFI", "113-WEBDAV", "114-SNMP",
    "115-BANNER", "116-PHPINFO", "117-SRVSTATUS", "118-ERRORLEAK",
    "119-WILDCARDDNS", "120-DNSREBIND",
    "121-IISASPNET", "122-TOMCAT", "123-NODEJS", "124-LARAVEL", "125-DJANGO", "126-SYMFONY",
    "127-CICD", "128-DOCKER", "129-K8S", "130-TERRAFORM", "131-ENVDEEP",
    "132-GQLABUSE", "133-APIVERSION", "134-LBDETECT", "135-VHOST", "136-RATELIMITBYPASS",
}
FAST_PHASES = {"00-SCOPE", "01-RECON", "02-RESOLVE", "04-SCAN", "05-HARVEST"}
DOS_PHASES = {
    "20-GRAPHQL",      # 100-alias batching, depth-10 nested queries
    "23-RACE",         # 5 concurrent requests + TOCTOU write+read
    "34-RATELIMIT",    # Burst of 10-50 requests per URL
    "38-SMUGGLE",      # CL.TE/TE.CL raw socket smuggling (can crash proxies)
    "38b-H2SMUGGLE",   # 500x RST_STREAM (CVE-2023-44487), 100KB HPACK bomb
    "54-WS-FUZZ",      # 10KB+ WebSocket payload injection
    "83-RACEBURST",    # 10 concurrent "turbo" burst requests per endpoint
    "93-PWDSPRAY",     # Up to 300 login attempts across 3 URLs
    "132-GQLABUSE",    # 50-query batching, depth-10 nested GraphQL
    "136-RATELIMITBYPASS",  # Multi-vector rate limit bypass
}
DISCOVERY_PHASES = {
    "00-SCOPE", "01-RECON", "02-RESOLVE", "03-PERMUTE", "04-SCAN",
    "04b-TAKEOVER-VALIDATE", "05-HARVEST", "05b-APISPEC", "06-JSINTEL",
    "07-PARAMS", "08-FUZZ", "21-WAF",
}

PhaseSet = Set[str]

_SAFE_HOST = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$")


@dataclass
class PipelineConfig:
    """Shared configuration carried through the pipeline."""
    dos_mode: bool = True
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
    vuln_proxy: str = ""
    proxy_timeout_multiplier: float = 1.5
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
    cookie2: str = ""
    idor_session_a: str = ""
    idor_session_b: str = ""
    sample_urls_csrf: int = 20
    sample_hosts_sessionfix: int = 10
    sample_endpoints_saml: int = 10
    sample_users_spray: int = 20
    sample_hosts_cookie: int = 20
    sample_urls_posttest: int = 30
    sample_urls_methodoverride: int = 20
    sample_hosts_forcedbrowse: int = 20
    sample_urls_casebypass: int = 20
    sample_urls_apipage: int = 20
    sample_urls_tabnab: int = 30
    sample_urls_apikeyleak: int = 30
    sample_urls_redirabuse: int = 20
    sample_urls_logtrigger: int = 20
    sample_urls_xssstored: int = 10
    sample_hosts_hostabuse: int = 10
    sample_urls_authbypassadv: int = 20
    sample_urls_ssi: int = 20
    sample_urls_jsoninject: int = 20
    sample_urls_nullbyte: int = 20
    sample_urls_doubleencod: int = 20
    sample_urls_unicode: int = 20
    sample_hosts_postmsg: int = 15
    sample_hosts_jsonp: int = 20
    sample_hosts_sri: int = 20
    sample_hosts_mixedcontent: int = 20
    sample_hosts_hstspreload: int = 20
    sample_hosts_thirdpartyjs: int = 15
    sample_hosts_browserstorage: int = 15
    sample_urls_rfi: int = 20
    sample_hosts_webdav: int = 10
    sample_hosts_snmp: int = 10
    sample_hosts_banner: int = 15
    sample_hosts_phpinfo: int = 15
    sample_hosts_srvstatus: int = 15
    sample_urls_errorleak: int = 20
    sample_hosts_wildcarddns: int = 10
    sample_hosts_dnsrebind: int = 10
    sample_hosts_iisaspnet: int = 10
    sample_hosts_tomcat: int = 10
    sample_hosts_nodejs: int = 10
    sample_hosts_laravel: int = 10
    sample_hosts_django: int = 10
    sample_hosts_symfony: int = 10
    sample_hosts_cicd: int = 10
    sample_hosts_docker: int = 10
    sample_hosts_k8s: int = 10
    sample_hosts_terraform: int = 10
    sample_hosts_envdeep: int = 10
    sample_hosts_gqlabuse: int = 10
    sample_urls_apiversion: int = 20
    sample_hosts_lbdetect: int = 15
    sample_hosts_vhost: int = 10
    sample_urls_ratelimitbypass: int = 20



