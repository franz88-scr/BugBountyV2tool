"""VulnForge -- bug bounty reconnaissance pipeline orchestrator.

VulnForge chains 45+ security tools across 185+ phases to perform
comprehensive, automated reconnaissance and vulnerability assessment.

Quick start::

    from vulnforge import run_pipeline, PipelineConfig
    import asyncio, argparse

    # Create a minimal args namespace and run
    args = argparse.Namespace(domain="example.com", out="./out/example.com", ...)
    asyncio.run(run_pipeline(args))

For CLI usage::

    vulnforge -d example.com
    vulnforge -d example.com --fast
    vulnforge -i          # interactive wizard
"""

from __future__ import annotations

import re as _re

from vulnforge.ai import (
    LLMProvider,
    ai_complete,
    get_provider,
    parse_json_response,
)
from vulnforge.ai import (
    configure as ai_configure,
)
from vulnforge.ai_exploit import suggest_exploit_chains
from vulnforge.ai_triage import run_triage
from vulnforge.attack_surface import (
    build_graph,
    write_attack_surface_html,
    write_attack_surface_json,
)
from vulnforge.exceptions import (
    AIAnalysisError as AIAnalysisError,
)
from vulnforge.exceptions import (
    BotError as BotError,
)
from vulnforge.exceptions import (
    CircuitBreakerOpenError as CircuitBreakerOpenError,
)
from vulnforge.exceptions import (
    ConfigError as ConfigError,
)
from vulnforge.exceptions import (
    DashboardError as DashboardError,
)
from vulnforge.exceptions import (
    HTTP2NotSupportedError as HTTP2NotSupportedError,
)
from vulnforge.exceptions import (
    InsufficientResourcesError as InsufficientResourcesError,
)
from vulnforge.exceptions import (
    IntegrationError as IntegrationError,
)
from vulnforge.exceptions import (
    InteractshError as InteractshError,
)
from vulnforge.exceptions import (
    InvalidCookieError as InvalidCookieError,
)
from vulnforge.exceptions import (
    InvalidDomainError as InvalidDomainError,
)
from vulnforge.exceptions import (
    InvalidPhaseError as InvalidPhaseError,
)
from vulnforge.exceptions import (
    NetworkError as NetworkError,
)
from vulnforge.exceptions import (
    OutputPathError as OutputPathError,
)
from vulnforge.exceptions import (
    PhaseCrashError as PhaseCrashError,
)
from vulnforge.exceptions import (
    PhaseTimeoutError as PhaseTimeoutError,
)
from vulnforge.exceptions import (
    PipelineError as PipelineError,
)
from vulnforge.exceptions import (
    PluginError as PluginError,
)
from vulnforge.exceptions import (
    PluginLoadError as PluginLoadError,
)
from vulnforge.exceptions import (
    ProxyError as ProxyError,
)
from vulnforge.exceptions import (
    ReportError as ReportError,
)
from vulnforge.exceptions import (
    ReportGenerationError as ReportGenerationError,
)
from vulnforge.exceptions import (
    StateWriteError as StateWriteError,
)
from vulnforge.exceptions import (
    ToolError as ToolError,
)
from vulnforge.exceptions import (
    ToolExecutionError as ToolExecutionError,
)
from vulnforge.exceptions import (
    ToolNotFoundError as ToolNotFoundError,
)
from vulnforge.exceptions import (
    ToolTimeoutError as ToolTimeoutError,
)
from vulnforge.exceptions import (
    VulnForgeError as VulnForgeError,
)

try:
    from vulnforge.bot import start_bot, start_bot_thread
except ImportError:
    start_bot = None  # type: ignore[assignment]
    start_bot_thread = None  # type: ignore[assignment]
from vulnforge.cli import InteractiveWizard, build_parser, main
from vulnforge.conf import apply_config_to_args, find_config, load_config

# Backward-compatible re-exports: all public symbols from submodules are
# available directly via `from vulnforge import ...`.
from vulnforge.config import (
    _HOSTNAME_RE,
    _SAFE_HOST,
    DOS_PHASES,
    FAST_PHASES,
    QUICK_SKIP_PHASES,
    VALID_PHASES,
    PipelineConfig,
    __version__,
)

try:
    from vulnforge.dashboard_server import start_dashboard, start_dashboard_thread
except ImportError:
    start_dashboard = None  # type: ignore[assignment]
    start_dashboard_thread = None  # type: ignore[assignment]
# v3.0 modules
from vulnforge.artifacts import (
    ARTIFACT_REGISTRY,
    ARTIFACTS,
    FILENAME_TO_ARTIFACT,
    get_counts,
    get_coverage,
    get_findings_by_severity,
    get_findings_for_triage,
    get_report_files,
    guess_severity,
)
from vulnforge.certainty import (
    Confidence,
    score_all_findings,
    score_finding,
    write_confidence_report,
)
from vulnforge.dedup import DedupEngine
from vulnforge.distributed import SSHScanner, create_scanner_from_config

# New v2.1 modules
from vulnforge.events import Event, EventBus, bus
from vulnforge.exploit_chain import analyze_exploit_chains
from vulnforge.interactsh import Interactsh
from vulnforge.notify import send_notification, send_scan_summary
from vulnforge.proof import generate_all_pocs, generate_pocs
from vulnforge.scheduler import MonitorEngine
from vulnforge.target_profile import TargetProfile, build_target_profile, load_profile, save_profile

try:
    from vulnforge.tool_health import ToolHealthMonitor, get_tool_health_monitor
except ImportError:
    get_tool_health_monitor = None  # type: ignore[assignment]
    ToolHealthMonitor = None  # type: ignore[assignment, misc]
from vulnforge.adapters import LearningEngine
from vulnforge.api import start_api_server, stop_api_server
from vulnforge.audit import disable as audit_disable
from vulnforge.audit import enable as audit_enable
from vulnforge.audit import init_audit_log
from vulnforge.audit import log_event as audit_log_event
from vulnforge.diff import ScanDiff, compare_scans

# v3.1 modules
from vulnforge.finding import Finding, FindingStore, finding_from_text
from vulnforge.fleet import BatchScan
from vulnforge.phases import (
    _AUTH_BYPASS_HEADERS,
    _JS_SECRET_PATTERNS,
    _MASS_ASSIGN_FIELDS,
    _PHASE_WEIGHTS,
    _RECON_LEVELS,
    _SOURCE_MAP_RE,
    PHASE_DEPS,
    PIPELINE,
    STAGES,
    PhaseSet,
    _parse_semver,
    _semver_lt,
    phase_00_SCOPE,
    phase_01_RECON,
    phase_02_RESOLVE,
    phase_03_PERMUTE,
    phase_04_SCAN,
    phase_04b_TAKEOVER_VALIDATE,
    phase_05_HARVEST,
    phase_05b_APISPEC,
    phase_06_JSINTEL,
    phase_07_PARAMS,
    phase_08_FUZZ,
    phase_09_VULNSCAN,
    phase_10_TLSCMS,
    phase_11_INJECT,
    phase_11a_DOMXSS,
    phase_11b_SQLMAP,
    phase_12_SSTI,
    phase_13_OOB,
    phase_14_ORIGIN,
    phase_15_SECRETS,
    phase_16a_AUTHZ,
    phase_16b_MASSASSIGN,
    phase_17_IDOR,
    phase_17b_SSRFMETA,
    phase_18_CLOUD,
    phase_19_GIT,
    phase_20_GRAPHQL,
    phase_21_WAF,
    phase_21b_WAFBYPASS,
    phase_22_NOSQLI,
    phase_23_RACE,
    phase_24_JWT,
    phase_25_XXE,
    phase_26_CMDINJECT,
    phase_27_SSPP,
    phase_28_CACHED,
    phase_29_DEPCHECK,
    phase_30_LFI,
    phase_31_OPENREDIR,
    phase_32_CLICKJACK,
    phase_33_CRLF,
    phase_34_RATELIMIT,
    phase_35_CORSADV,
    phase_36_JWTADV,
    phase_37_FILEUPLOAD,
    phase_38_SMUGGLE,
    phase_38b_H2SMUGGLE,
    phase_39_OAUTH,
    phase_40_PWRESET,
    phase_41_WEBSOCKET,
    phase_42_LDAP,
    phase_43_DESERIAL,
    phase_44_CHAIN,
    phase_45_EVIDENCE,
    phase_46_BUCKET,
    phase_47_CDN,
    phase_48_CONTENT,
    phase_49_FRAMEWORKS,
    phase_50_BUCKET_PERMS,
    phase_51_HPP,
    phase_52_SERVERLESS,
    phase_53_CSP,
    phase_54_WS_FUZZ,
    phase_55_CSV_INJECT,
    phase_56_EXPOSED_DB,
    phase_57_DEFAULT_CREDS,
    phase_58_HOST_INJECT,
    phase_59_EMAIL_SEC,
    phase_60_SMTP_ENUM,
    phase_61_OAUTH_ADV,
    phase_62_LOG_INJECT,
    phase_63_DOC_ATTACK,
    phase_64_IDEMPOTENCY,
    phase_65_SESSION,
    phase_66_SSRF_FULL,
    phase_67_PATHNORM,
    phase_68_DEPCVE,
    phase_69_DNSZT,
    phase_70_PORTFULL,
    phase_71_EMHARVEST,
    phase_72_ACCOUNTENUM,
    phase_73_CSPBYPASS,
    phase_74_GHTOOLS,
    phase_75_MOBILEAPI,
    phase_76_WORKFLOW,
    phase_77_CACHEKEY,
    phase_78_FILEUPLOADADV,
    phase_79_SECRETDIFF,
    phase_80_STOREXSS,
    phase_81_IDORFUZZ,
    phase_82_OAUTHDEEP,
    phase_83_RACEBURST,
    phase_84_WHOIS,
    phase_85_ASN,
    phase_86_DORK,
    phase_87_SHODAN,
    phase_88_EMPLOYEE,
    phase_89_PASSIVEDNS,
    phase_90_CSRF,
    phase_91_SESSIONFIX,
    phase_92_SAML,
    phase_93_PWDSPRAY,
    phase_94_COOKIEAUDIT,
    phase_95_POSTTEST,
    phase_96_METHODOVERRIDE,
    phase_97_FORCEDBROWSE,
    phase_98_CASEBYPASS,
    phase_99_APIPAGE,
    phase_99a_TABNAB,
    phase_99b_APIKEYLEAK,
    phase_99c_REDIRABUSE,
    phase_99d_LOGTRIGGER,
    phase_99e_XSSSTORED,
    phase_99f_HOSTABUSE,
    phase_99g_AUTHBYPASSADV,
    phase_100_SSI,
    phase_101_JSONINJECT,
    phase_102_NULLBYTE,
    phase_103_DOUBLEENCOD,
    phase_104_UNICODE,
    phase_105_POSTMSGXSS,
    phase_106_JSONP,
    phase_107_SRI,
    phase_108_MIXEDCONTENT,
    phase_109_HSTSPRELOAD,
    phase_110_THIRDPARTYJS,
    phase_111_BROWSERSTORAGE,
    phase_112_RFI,
    phase_113_WEBDAV,
    phase_114_SNMP,
    phase_115_BANNER,
    phase_116_PHPINFO,
    phase_117_SRVSTATUS,
    phase_118_ERRORLEAK,
    phase_119_WILDCARDDNS,
    phase_120_DNSREBIND,
    phase_121_IISASPNET,
    phase_122_TOMCAT,
    phase_123_NODEJS,
    phase_124_LARAVEL,
    phase_125_DJANGO,
    phase_126_SYMFONY,
    phase_127_CICD,
    phase_128_DOCKER,
    phase_129_K8S,
    phase_130_TERRAFORM,
    phase_131_ENVDEEP,
    phase_132_GQLABUSE,
    phase_133_APIVERSION,
    phase_134_LBDETECT,
    phase_135_VHOST,
    phase_136_RATELIMITBYPASS,
    phase_137_EMAILFINDER,
    phase_138_METAGOOFIL,
    phase_139_PORCHPIRATE,
    phase_140_DORKHUNTER,
    phase_141_CRTSH,
    phase_142_GITHUBSUB,
    phase_143_TLSX,
    phase_144_ANALYTICSRELS,
    phase_145_FAVIRECON,
    phase_146_JSLUICE,
    phase_147_SHORTSCAN,
    phase_148_GRPCURL,
    phase_149_LLMSEC,
    phase_150_LLMLEAK,
    phase_151_RAGPOISON,
    phase_152_LLMADV,
    phase_153_BIZLOGIC,
    phase_154_PAYMENT,
    phase_155_COUPON,
    phase_156_MTENANT,
    phase_157_2FA,
    phase_158_SSO,
    phase_159_SAMLADV,
    phase_160_SSOCONF,
    phase_161_ELECTRON,
    phase_162_ELECTRONRCE,
    phase_163_ELECTRONPROTO,
    phase_164_ELECTRONUPD,
    phase_165_DEPCONF,
    phase_166_TYPOSQUAT,
    phase_167_H2RAPID,
    phase_168_H3QUIC,
    phase_169_WEBTRANSPORT,
)
from vulnforge.pipeline import run_pipeline
from vulnforge.plugin import PhasePlugin, discover_plugins, get_registry
from vulnforge.process import (
    _JOB_SEM,
    _PIPELINE_CFG,
    _SPAWNED_PIDS,
    _SPAWNED_PIDS_LOCK,
    _TOOL_RC_REGISTRY,
    _USE_PROXYCHAINS,
    MAX_PARALLEL_JOBS,
    StepResult,
    _atomic_write_json,
    _cleanup_child_procs,
    _csv_from_phases,
    _domain_arg,
    _kill_proc,
    _maybe_timeout,
    _needs_proxychains,
    _parse_phase_csv,
    _register_proc,
    _run,
    _run_blocking,
    _update_nuclei_templates,
    _wait_proc,
    run_parallel,
)
from vulnforge.remediation import (
    get_all_remediations,
    get_remediation,
    get_remediation_text,
    has_remediation,
)
from vulnforge.reporting import (
    _counts,
    write_faraday,
    write_full_summary,
    write_html,
    write_html_dashboard,
    write_markdown,
    write_sarif,
    write_summary,
)
from vulnforge.review import FindingReview, run_interactive_review
from vulnforge.severity import RiskScore, calculate_risk_score, write_risk_score
from vulnforge.spoof import UARotator
from vulnforge.throttle import (
    GlobalRateLimiter,
    RateLimiter,
    TokenBucket,
    configure_rate_limiter,
    get_rate_limiter,
)
from vulnforge.tools import Tools
from vulnforge.tui import TUIDashboard
from vulnforge.utils import (
    LVL,
    C,
    Progress,
    ScanStatus,
    _async_urlopen,
    _async_urlopen_no_redirect,
    _auto_detect_cookies,
    _auto_detect_proxy,
    _color,
    _dedupe_by_host_params,
    _dedupe_by_host_path,
    _downsample_file,
    _existing_artifacts,
    _extra_headers_dict,
    _extra_http_args,
    _extract_urls_from_ffuf_json,
    _get_no_redirect_urlopener,
    _get_urlopener,
    _is_under_domain,
    _is_valid_hostname,
    _load_live_hosts,
    _merge_dnsx_output,
    _mmh3_hash,
    _NoRedirectHandler,
    _parse_httpx_tech,
    _safe_name,
    _set_proxy_env,
    _target_lines,
    _target_token,
    _throttle,
    _throttle_rate,
    _throttle_sync,
    _write_target_tokens,
    count_nonblank,
    disable_color,
    ensure,
    html_escape,
    iter_lines,
    log,
    md_escape,
    merge_unique,
    merge_unique_str,
    read_jsonl,
    read_lines,
    safe_suffix,
    write_findings,
)

__all__ = [
    # ── Core ─────────────────────────────────────────────────────────
    "__version__",
    "PipelineConfig",
    "VALID_PHASES",
    "FAST_PHASES",
    "QUICK_SKIP_PHASES",
    "DOS_PHASES",
    "PhaseSet",
    "PIPELINE",
    "PHASE_DEPS",
    "STAGES",
    # ── Utilities (public) ───────────────────────────────────────────
    "C",
    "LVL",
    "log",
    "disable_color",
    "ensure",
    "safe_suffix",
    "read_lines",
    "iter_lines",
    "count_nonblank",
    "read_jsonl",
    "merge_unique",
    "merge_unique_str",
    "html_escape",
    "md_escape",
    "write_findings",
    "Progress",
    "ScanStatus",
    # ── Process / tools ──────────────────────────────────────────────
    "Tools",
    "StepResult",
    "run_parallel",
    "MAX_PARALLEL_JOBS",
    # ── Reporting ────────────────────────────────────────────────────
    "write_summary",
    "write_html",
    "write_full_summary",
    "write_markdown",
    "write_sarif",
    "write_faraday",
    "write_html_dashboard",
    # ── Phase functions ──────────────────────────────────────────────
    "phase_00_SCOPE",
    "phase_01_RECON",
    "phase_02_RESOLVE",
    "phase_03_PERMUTE",
    "phase_04_SCAN",
    "phase_04b_TAKEOVER_VALIDATE",
    "phase_05_HARVEST",
    "phase_05b_APISPEC",
    "phase_06_JSINTEL",
    "phase_07_PARAMS",
    "phase_08_FUZZ",
    "phase_09_VULNSCAN",
    "phase_10_TLSCMS",
    "phase_11_INJECT",
    "phase_11a_DOMXSS",
    "phase_11b_SQLMAP",
    "phase_12_SSTI",
    "phase_13_OOB",
    "phase_14_ORIGIN",
    "phase_15_SECRETS",
    "phase_16a_AUTHZ",
    "phase_16b_MASSASSIGN",
    "phase_17_IDOR",
    "phase_17b_SSRFMETA",
    "phase_18_CLOUD",
    "phase_19_GIT",
    "phase_20_GRAPHQL",
    "phase_21_WAF",
    "phase_21b_WAFBYPASS",
    "phase_22_NOSQLI",
    "phase_23_RACE",
    "phase_24_JWT",
    "phase_25_XXE",
    "phase_26_CMDINJECT",
    "phase_27_SSPP",
    "phase_28_CACHED",
    "phase_29_DEPCHECK",
    "phase_30_LFI",
    "phase_31_OPENREDIR",
    "phase_32_CLICKJACK",
    "phase_33_CRLF",
    "phase_34_RATELIMIT",
    "phase_35_CORSADV",
    "phase_36_JWTADV",
    "phase_37_FILEUPLOAD",
    "phase_38_SMUGGLE",
    "phase_38b_H2SMUGGLE",
    "phase_39_OAUTH",
    "phase_40_PWRESET",
    "phase_41_WEBSOCKET",
    "phase_42_LDAP",
    "phase_43_DESERIAL",
    "phase_44_CHAIN",
    "phase_45_EVIDENCE",
    "phase_46_BUCKET",
    "phase_47_CDN",
    "phase_48_CONTENT",
    "phase_49_FRAMEWORKS",
    "phase_50_BUCKET_PERMS",
    "phase_51_HPP",
    "phase_52_SERVERLESS",
    "phase_53_CSP",
    "phase_54_WS_FUZZ",
    "phase_55_CSV_INJECT",
    "phase_56_EXPOSED_DB",
    "phase_57_DEFAULT_CREDS",
    "phase_58_HOST_INJECT",
    "phase_59_EMAIL_SEC",
    "phase_60_SMTP_ENUM",
    "phase_61_OAUTH_ADV",
    "phase_62_LOG_INJECT",
    "phase_63_DOC_ATTACK",
    "phase_64_IDEMPOTENCY",
    "phase_65_SESSION",
    "phase_66_SSRF_FULL",
    "phase_67_PATHNORM",
    "phase_68_DEPCVE",
    "phase_69_DNSZT",
    "phase_70_PORTFULL",
    "phase_71_EMHARVEST",
    "phase_72_ACCOUNTENUM",
    "phase_73_CSPBYPASS",
    "phase_74_GHTOOLS",
    "phase_75_MOBILEAPI",
    "phase_76_WORKFLOW",
    "phase_77_CACHEKEY",
    "phase_78_FILEUPLOADADV",
    "phase_79_SECRETDIFF",
    "phase_80_STOREXSS",
    "phase_81_IDORFUZZ",
    "phase_82_OAUTHDEEP",
    "phase_83_RACEBURST",
    "phase_84_WHOIS",
    "phase_85_ASN",
    "phase_86_DORK",
    "phase_87_SHODAN",
    "phase_88_EMPLOYEE",
    "phase_89_PASSIVEDNS",
    "phase_90_CSRF",
    "phase_91_SESSIONFIX",
    "phase_92_SAML",
    "phase_93_PWDSPRAY",
    "phase_94_COOKIEAUDIT",
    "phase_95_POSTTEST",
    "phase_96_METHODOVERRIDE",
    "phase_97_FORCEDBROWSE",
    "phase_98_CASEBYPASS",
    "phase_99_APIPAGE",
    "phase_99a_TABNAB",
    "phase_99b_APIKEYLEAK",
    "phase_99c_REDIRABUSE",
    "phase_99d_LOGTRIGGER",
    "phase_99e_XSSSTORED",
    "phase_99f_HOSTABUSE",
    "phase_99g_AUTHBYPASSADV",
    "phase_100_SSI",
    "phase_101_JSONINJECT",
    "phase_102_NULLBYTE",
    "phase_103_DOUBLEENCOD",
    "phase_104_UNICODE",
    "phase_105_POSTMSGXSS",
    "phase_106_JSONP",
    "phase_107_SRI",
    "phase_108_MIXEDCONTENT",
    "phase_109_HSTSPRELOAD",
    "phase_110_THIRDPARTYJS",
    "phase_111_BROWSERSTORAGE",
    "phase_112_RFI",
    "phase_113_WEBDAV",
    "phase_114_SNMP",
    "phase_115_BANNER",
    "phase_116_PHPINFO",
    "phase_117_SRVSTATUS",
    "phase_118_ERRORLEAK",
    "phase_119_WILDCARDDNS",
    "phase_120_DNSREBIND",
    "phase_121_IISASPNET",
    "phase_122_TOMCAT",
    "phase_123_NODEJS",
    "phase_124_LARAVEL",
    "phase_125_DJANGO",
    "phase_126_SYMFONY",
    "phase_127_CICD",
    "phase_128_DOCKER",
    "phase_129_K8S",
    "phase_130_TERRAFORM",
    "phase_131_ENVDEEP",
    "phase_132_GQLABUSE",
    "phase_133_APIVERSION",
    "phase_134_LBDETECT",
    "phase_135_VHOST",
    "phase_136_RATELIMITBYPASS",
    "phase_137_EMAILFINDER",
    "phase_138_METAGOOFIL",
    "phase_139_PORCHPIRATE",
    "phase_140_DORKHUNTER",
    "phase_141_CRTSH",
    "phase_142_GITHUBSUB",
    "phase_143_TLSX",
    "phase_144_ANALYTICSRELS",
    "phase_145_FAVIRECON",
    "phase_146_JSLUICE",
    "phase_147_SHORTSCAN",
    "phase_148_GRPCURL",
    # ── CLI ──────────────────────────────────────────────────────────
    "build_parser",
    "main",
    "InteractiveWizard",
    # ── Pipeline / orchestration ─────────────────────────────────────
    "run_pipeline",
    # ── Engines ──────────────────────────────────────────────────────
    "DedupEngine",
    "MonitorEngine",
    "RateLimiter",
    "UARotator",
    # ── Config ───────────────────────────────────────────────────────
    "load_config",
    "apply_config_to_args",
    "find_config",
    # ── Notifications ────────────────────────────────────────────────
    "send_notification",
    "send_scan_summary",
    # ── Network ──────────────────────────────────────────────────────
    "Interactsh",
    "SSHScanner",
    "create_scanner_from_config",
    # ── Events / plugins ─────────────────────────────────────────────
    "bus",
    "Event",
    "EventBus",
    "PhasePlugin",
    "discover_plugins",
    "get_registry",
    # ── AI ───────────────────────────────────────────────────────────
    "get_provider",
    "ai_complete",
    "ai_configure",
    "parse_json_response",
    "LLMProvider",
    "run_triage",
    "suggest_exploit_chains",
    "analyze_exploit_chains",
    # ── Attack surface / dashboard ───────────────────────────────────
    "build_graph",
    "write_attack_surface_html",
    "write_attack_surface_json",
    "start_dashboard",
    "start_dashboard_thread",
    # ── Bot ──────────────────────────────────────────────────────────
    "start_bot",
    "start_bot_thread",
    # ── Artifacts ────────────────────────────────────────────────────
    "ARTIFACTS",
    "ARTIFACT_REGISTRY",
    "FILENAME_TO_ARTIFACT",
    "get_counts",
    "get_findings_by_severity",
    "get_findings_for_triage",
    "get_report_files",
    "get_coverage",
    "guess_severity",
    # ── Target profiling ─────────────────────────────────────────────
    "TargetProfile",
    "build_target_profile",
    "save_profile",
    "load_profile",
    # ── Confidence / PoC / risk ──────────────────────────────────────
    "Confidence",
    "score_finding",
    "score_all_findings",
    "write_confidence_report",
    "generate_pocs",
    "generate_all_pocs",
    "RiskScore",
    "calculate_risk_score",
    "write_risk_score",
    # ── Tool health ──────────────────────────────────────────────────
    "get_tool_health_monitor",
    "ToolHealthMonitor",
    # ── Batch / compare ──────────────────────────────────────────────
    "BatchScan",
    "ScanDiff",
    "compare_scans",
    # ── TUI / review ─────────────────────────────────────────────────
    "TUIDashboard",
    "FindingReview",
    "run_interactive_review",
    # ── Learning ─────────────────────────────────────────────────────
    "LearningEngine",
    # ── Exceptions (v3.1) ────────────────────────────────────────────
    "VulnForgeError",
    "ConfigError",
    "InvalidDomainError",
    "InvalidPhaseError",
    "InvalidCookieError",
    "PipelineError",
    "OutputPathError",
    "InsufficientResourcesError",
    "PhaseTimeoutError",
    "PhaseCrashError",
    "ToolError",
    "ToolNotFoundError",
    "ToolExecutionError",
    "ToolTimeoutError",
    "CircuitBreakerOpenError",
    "NetworkError",
    "ProxyError",
    "HTTP2NotSupportedError",
    "InteractshError",
    "PluginError",
    "PluginLoadError",
    "ReportError",
    "StateWriteError",
    "ReportGenerationError",
    "IntegrationError",
    "AIAnalysisError",
    "BotError",
    "DashboardError",
]
