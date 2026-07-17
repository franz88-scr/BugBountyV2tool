"""External TOML configuration file support.

Searches for reconchain.cfg in:
  1. --config CLI flag (explicit path)
  2. ./reconchain.cfg (current directory)
  3. ~/.config/reconchain/reconchain.cfg (XDG)

Falls back gracefully if no config file exists.

Wizard profiles are stored in ~/.config/reconchain/profiles/ as TOML files.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # pip install tomli
    except ImportError:
        tomllib = None  # type: ignore[assignment]


CONFIG_FILENAME = "reconchain.cfg"

# Default search paths (in priority order)
_CONFIG_SEARCH_PATHS = [
    Path("reconchain.cfg"),
    Path.home() / ".config" / "reconchain" / "reconchain.cfg",
]


def find_config(explicit_path: Optional[str] = None) -> Optional[Path]:
    """Locate the config file. Returns None if not found."""
    if explicit_path:
        p = Path(explicit_path)
        if p.is_file():
            return p
        return None
    for p in _CONFIG_SEARCH_PATHS:
        if p.is_file():
            return p
    return None


def load_config(path: Optional[Path] = None) -> Dict[str, Any]:
    """Load and parse a TOML config file. Returns empty dict on failure."""
    if path is None:
        path = find_config()
    if path is None:
        return {}
    if tomllib is None:
        # Minimal key=value parser for when tomllib is unavailable
        return _parse_simple(path)
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except Exception as exc:
        print(f"[W] config parse error ({path}): {exc}", file=sys.stderr)
        return {}


def _parse_simple(path: Path) -> Dict[str, Any]:
    """Fallback parser for simple key = value files with optional [section] headers."""
    result: Dict[str, Any] = {}
    current_section: Optional[Dict[str, Any]] = result
    try:
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Handle [section] headers
            if line.startswith("[") and line.endswith("]"):
                section_name = line[1:-1].strip()
                if section_name:
                    current_section = result.setdefault(section_name, {})
                else:
                    current_section = result
                continue
            if current_section is None:
                current_section = result
            if "=" in line:
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip()
                # Strip inline comments (only if # is preceded by whitespace)
                if ' #' in val:
                    val = val.split(' #')[0].strip()
                elif val.startswith('#'):
                    continue
                val = val.strip('"').strip("'")
                # Type coercion
                if val.lower() in ("true", "yes"):
                    val = True
                elif val.lower() in ("false", "no"):
                    val = False
                else:
                    try:
                        val = int(val)
                    except ValueError:
                        try:
                            val = float(val)
                        except ValueError:
                            pass
                current_section[key] = val
    except Exception:
        pass
    return result


def apply_config_to_args(cfg: Dict[str, Any], args: Any) -> Any:
    """Apply config values to argparse Namespace. CLI flags take precedence.

    Config keys map to args like:
      [general]
      proxy = "socks5://127.0.0.1:9050"    -> args.proxy
      delay = 0.5                           -> args.delay
      rate_limit = 50                       -> args.rate_limit

      [scan]
      dos_mode = false                      -> args.dos_mode
      sqlmap_level = 2                      -> args.sqlmap_level

      [idor]
      cookie_a = "session=user1"            -> args.cookie_a
      cookie_b = "session=user2"            -> args.cookie_b

      [api]
      shodan_key = "xxx"                    -> os.environ["SHODAN_API_KEY"]
      github_tokens = ["tok1", "tok2"]      -> written to ~/Tools/.github_tokens

      [notify]
      slack_webhook = "https://..."         -> os.environ["SLACK_WEBHOOK_URL"]
      discord_webhook = "https://..."       -> os.environ["DISCORD_WEBHOOK_URL"]
      telegram_bot_token = "xxx"            -> os.environ["TELEGRAM_BOT_TOKEN"]
      telegram_chat_id = "yyy"              -> os.environ["TELEGRAM_CHAT_ID"]
    """
    if not cfg:
        return args

    # [general] section
    gen = cfg.get("general", cfg)  # fallback: top-level keys
    _set_arg_if_default(args, "proxy", gen.get("proxy"))
    _set_arg_if_default(args, "vuln_proxy", gen.get("vuln_proxy"))
    _set_arg_if_default(args, "delay", gen.get("delay"))
    _set_arg_if_default(args, "rate_limit", gen.get("rate_limit"))
    _set_arg_if_default(args, "jobs", gen.get("parallel_jobs"))
    _set_arg_if_default(args, "cookie", gen.get("cookie"))
    if gen.get("no_color"):
        args.no_color = True
    # Safe mode: conservative settings for VMs / low-resource systems
    if gen.get("safe_mode") and not getattr(args, 'safe', False):
        args.safe = True

    # [scan] section
    scan = cfg.get("scan", {})
    _set_arg_if_default(args, "dos_mode", scan.get("dos_mode"))
    _set_arg_if_default(args, "sqlmap_level", scan.get("sqlmap_level"))
    _set_arg_if_default(args, "sqlmap_risk", scan.get("sqlmap_risk"))
    _set_arg_if_default(args, "exclude_tags", scan.get("nuclei_exclude_tags"))

    # Safe mode support in TOML config
    if scan.get("safe_mode") and not getattr(args, 'safe', False):
        args.safe = True

    # [idor] section
    idor = cfg.get("idor", {})
    _set_arg_if_default(args, "cookie_a", idor.get("cookie_a"))
    _set_arg_if_default(args, "cookie_b", idor.get("cookie_b"))

    # [api] section — set environment variables
    api = cfg.get("api", {})
    _set_env_if_present("SHODAN_API_KEY", api.get("shodan_key"))
    _set_env_if_present("WHOISXML_API", api.get("whoisxml_key"))
    _set_env_if_present("PDCP_API_KEY", api.get("projectdiscovery_key"))
    _set_env_if_present("COLLAB_SERVER", api.get("collab_server"))
    _set_env_if_present("XSS_SERVER", api.get("xss_server"))
    # GitHub tokens: write to file if provided as list
    gh_tokens = api.get("github_tokens")
    if isinstance(gh_tokens, list) and gh_tokens:
        tokens_dir = Path.home() / "Tools"
        tokens_dir.mkdir(parents=True, exist_ok=True)
        try:
            tokens_dir.chmod(0o700)
        except OSError:
            pass
        tokens_file = tokens_dir / ".github_tokens"
        existing = set()
        if tokens_file.exists():
            existing = set(tokens_file.read_text().strip().splitlines())
        new_tokens = [t for t in gh_tokens if t and t not in existing]
        if new_tokens:
            import os as _os
            fd = _os.open(str(tokens_file), _os.O_WRONLY | _os.O_CREAT | _os.O_APPEND, 0o600)
            with _os.fdopen(fd, "a") as f:
                f.write("\n".join(new_tokens) + "\n")

    # [notify] section
    notify = cfg.get("notify", {})
    _set_env_if_present("SLACK_WEBHOOK_URL", notify.get("slack_webhook"))
    _set_env_if_present("DISCORD_WEBHOOK_URL", notify.get("discord_webhook"))
    _set_env_if_present("TELEGRAM_BOT_TOKEN", notify.get("telegram_bot_token"))
    _set_env_if_present("TELEGRAM_CHAT_ID", notify.get("telegram_chat_id"))

    # [proxy] section (overrides general.proxy)
    proxy_sec = cfg.get("proxy", {})
    if proxy_sec.get("url"):
        _set_arg_if_default(args, "proxy", proxy_sec["url"])
    if proxy_sec.get("vuln_url"):
        _set_arg_if_default(args, "vuln_proxy", proxy_sec["vuln_url"])

    # [paths] section
    paths = cfg.get("paths", {})
    # Tool paths are used by install.sh, not directly by pipeline

    return args


def _set_arg_if_default(args: Any, attr: str, val: Any) -> None:
    """Set an argparse attribute only if it hasn't been explicitly set by the user.

    When running from the interactive wizard, _defaults is not set on the namespace.
    In that case, we only apply config values if the current value is the same as
    the argparse parser default (which we store in _defaults when available).
    """
    if val is None:
        return
    current = getattr(args, attr, None)
    parser_defaults = getattr(args, '_defaults', {})
    # Validate proxy URLs have a recognised scheme
    if attr in ("proxy", "vuln_proxy") and isinstance(val, str) and val.strip():
        val = val.strip()
        if not val.startswith(("http://", "https://", "socks4://", "socks5://", "socks5h://", "socks4a://")):
            print(f"[W] config: invalid proxy URL scheme in {attr}={val!r}; ignoring", file=sys.stderr)
            return
    if attr in parser_defaults:
        # CLI path: only override if current value matches the parser default
        if current == parser_defaults[attr]:
            setattr(args, attr, val)
    elif current is None:
        # Wizard path: no _defaults set, only override if current is None
        setattr(args, attr, val)
    # If current is not None and not in parser_defaults, the wizard/user set it — don't override


def _set_env_if_present(key: str, val: Any) -> None:
    """Set an environment variable if value is provided."""
    if val and isinstance(val, str) and val.strip():
        os.environ[key] = val.strip()


def generate_example_config() -> str:
    """Return a string with an example config file."""
    return """# ReconChain configuration file
# Place this as reconchain.cfg in the project root or ~/.config/reconchain/
# CLI flags always override these values.

[general]
# proxy = "socks5://127.0.0.1:9050"
# vuln_proxy = "socks5://127.0.0.1:9050"
# delay = 0.0
# rate_limit = 0
# parallel_jobs = 4
# cookie = ""
# no_color = false

[scan]
dos_mode = true
sqlmap_level = 1
sqlmap_risk = 1
# nuclei_exclude_tags = "dos,brute-force"

[api]
# shodan_key = ""
# whoisxml_key = ""
# projectdiscovery_key = ""
# collab_server = ""
# xss_server = ""
# github_tokens = ["ghp_xxx", "ghp_yyy"]

[notify]
# slack_webhook = "https://hooks.slack.com/services/xxx"
# discord_webhook = "https://discord.com/api/webhooks/xxx"
# telegram_bot_token = ""
# telegram_chat_id = ""

[proxy]
# url = "socks5://127.0.0.1:9050"
# vuln_url = "socks5://127.0.0.1:9050"
"""


# ── Wizard profile save/load ─────────────────────────────────────────────────

_PROFILES_DIR = Path.home() / ".config" / "reconchain" / "profiles"


def _ensure_profiles_dir() -> Path:
    """Create the profiles directory if it doesn't exist."""
    _PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    try:
        _PROFILES_DIR.chmod(0o700)
    except OSError:
        pass
    return _PROFILES_DIR


def list_profiles() -> List[Dict[str, Any]]:
    """List all saved wizard profiles.

    Returns a list of dicts with keys: name, preset, domain, phases, path.
    """
    _ensure_profiles_dir()
    profiles = []
    for p in sorted(_PROFILES_DIR.glob("*.json")):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            profiles.append({
                "name": data.get("profile_name", p.stem),
                "preset": data.get("preset", "custom"),
                "domain": data.get("domain", ""),
                "phases": len(data.get("selected_phases", [])),
                "path": str(p),
            })
        except (json.JSONDecodeError, OSError):
            continue
    return profiles


def load_profile(name: str) -> Optional[Dict[str, Any]]:
    """Load a wizard profile by name. Returns None if not found."""
    path = _ensure_profiles_dir() / f"{name}.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def save_profile(name: str, data: Dict[str, Any]) -> bool:
    """Save a wizard profile. Returns True on success."""
    _ensure_profiles_dir()
    path = _ensure_profiles_dir() / f"{name}.json"
    try:
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        path.chmod(0o600)
        return True
    except OSError:
        return False


def delete_profile(name: str) -> bool:
    """Delete a wizard profile by name. Returns True if deleted."""
    path = _ensure_profiles_dir() / f"{name}.json"
    if path.is_file():
        path.unlink()
        return True
    return False
