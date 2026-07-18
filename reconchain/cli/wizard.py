"""Interactive setup wizard for ReconChain CLI."""
from __future__ import annotations

import argparse
import os
import sys
import unicodedata as _unicodedata
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from reconchain.config import DOS_PHASES, PHASE_CATEGORIES, VALID_PHASES, WIZARD_PRESETS
from reconchain.process import MAX_PARALLEL_JOBS
from reconchain.utils import C, _auto_detect_proxy, _is_valid_hostname, log


def _is_float(s: str) -> bool:
    try:
        float(s)
        return True
    except (ValueError, TypeError):
        return False


def _clean_input(raw: str) -> str:
    """Strip all Unicode whitespace, zero-width / invisible characters, and control chars."""
    ZERO_WIDTH = dict.fromkeys(range(0x200B, 0x200F + 1))  # zero-width spaces, LRM, RLM
    ZERO_WIDTH.update({0xFEFF: None, 0x00A0: None, 0x2060: None})  # BOM, NBSP, WJ
    cleaned = raw.translate(ZERO_WIDTH)
    CONTROL = dict.fromkeys(i for i in range(0x20) if i not in (0x09, 0x0A, 0x0D))
    CONTROL.update(dict.fromkeys(range(0x7F, 0xA0)))
    cleaned = cleaned.translate(CONTROL)
    cleaned = _unicodedata.normalize("NFKC", cleaned)
    return cleaned.strip()


def _prompt(prompt_text: str, default: str = "", validator: Optional[Callable[[str], bool]] = None, error_msg: str = "", max_retries: int = 20, sensitive: bool = False) -> str:
    import getpass
    import time as _time
    for attempt in range(max_retries):
        if attempt > 0:
            _time.sleep(0.1)
        suffix = f" [{default}]" if default and not sensitive else ""
        if sensitive:
            try:
                val = getpass.getpass(f"  {prompt_text}{suffix}: ")
            except (EOFError, KeyboardInterrupt):
                val = ""
        else:
            val = _clean_input(input(f"  {prompt_text}{suffix}: "))
        if not val:
            if sensitive and default:
                log("warn", "sensitive field returned default value — ensure this is intended")
            return default
        if validator is None or validator(val):
            return val
        log("err", error_msg or "invalid input")
    return default


def _prompt_yes_no(prompt_text: str, default: bool = True) -> bool:
    suffix = " [Y/n]" if default else " [y/N]"
    val = input(f"  {prompt_text}{suffix}: ").strip().lower()
    if not val:
        return default
    return val in ("y", "yes")


def _get_total_ram_gb() -> float:
    try:
        import psutil
        return psutil.virtual_memory().total / (1024**3)
    except Exception:
        return 4.0


def _validate_count(v: str) -> bool:
    return v.lower() == "all" or (v.isdigit() and int(v) > 0)


def _all_phase_list() -> List[tuple]:
    """Flatten all phases across categories into a list of (pid, desc)."""
    result = []
    for cat_data in PHASE_CATEGORIES.values():
        result.extend(cat_data["phases"])
    return result


class InteractiveWizard:
    """Interactive setup wizard with menu navigation, presets, and profile save/load.

    Replaces the old linear interactive_setup() with a numbered-section menu.
    Flow:  Profile selection  ->  Preset selection  ->  Main menu loop  ->  Namespace.
    """

    def __init__(self) -> None:
        self.domain: str = ""
        self.out: str = ""
        self.preset: str = "standard"
        self.profile_name: str = ""
        self.selected_phases: Set[str] = set(WIZARD_PRESETS["standard"]["phases"])
        self.config: Dict[str, Any] = {
            "sqlmap_level": 1,
            "sqlmap_risk": 1,
            "delay": 0.0,
            "rate_limit": 10,
            "safe_mode": False,
            "adaptive_enabled": True,
            "adaptive_start": min(os.cpu_count() or 4, 6),
            "adaptive_max": 0,
            "adaptive_interval": 5.0,
            "adaptive_cpu_high": 80,
            "adaptive_ram_crit": 1.0,
            "adaptive_max_procs": 0,
            "max_procs": 0,
            "proxy": "",
            "cookie": "",
            "cookie_a": "",
            "cookie_b": "",
            "extra_headers": [],
            "report_format": "html",
            "fast": False,
            "dos_mode": False,
            "sample_mode": "normal",
            "resume": False,
            "force": False,
            "sample_urls_fuzz": "5",
            "sample_urls_params": "50",
            "compliance_frameworks": [],
            "compliance_report": False,
            "threat_intel": False,
            "threat_intel_feeds": "",
            "ml_phase_selection": True,
            "credential_store": False,
            "collaborative_mode": False,
            "workspace_name": "",
        }

    # ── Public entry point ───────────────────────────────────────────────────

    def run(self) -> argparse.Namespace:
        """Run the wizard and return a fully configured argparse.Namespace."""
        from reconchain.cli.banner import _banner
        _banner()
        log("info", "Interactive setup wizard v2 — press Ctrl+C anytime to abort\n")
        self._profile_menu()
        if not self.profile_name:
            self._preset_menu()
        self._target_menu()
        self._main_menu_loop()
        return self._build_namespace()

    # ── Profile selection ────────────────────────────────────────────────────

    def _profile_menu(self) -> None:
        from reconchain.conf import list_profiles, load_profile
        profiles = list_profiles()
        print(f"\n{C['b']}Saved profiles:{C['r']}")
        if profiles:
            for i, p in enumerate(profiles, 1):
                print(f"  {C['y']}{i}{C['r']}  {p['name']:20}  preset={p['preset']}  phases={p['phases']}")
        else:
            print(f"  {C['d']}(none){C['r']}")
        print(f"  {C['y']}N{C['r']}  New scan (no profile)")
        choice = _prompt("Select profile", default="N").strip()
        if choice.upper() == "N" or not choice:
            self.profile_name = ""
            return
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(profiles):
                data = load_profile(profiles[idx]["name"])
                if data:
                    self.profile_name = profiles[idx]["name"]
                    self._apply_profile(data)
                    log("ok", f"Loaded profile: {self.profile_name}")
                    return
        log("warn", "Invalid selection — starting new scan")
        self.profile_name = ""

    def _apply_profile(self, data: Dict[str, Any]) -> None:
        self.domain = data.get("domain", "")
        self.preset = data.get("preset", "standard")
        self.selected_phases = set(data.get("selected_phases", []))
        for k, v in data.get("config", {}).items():
            self.config[k] = v

    # ── Preset selection ─────────────────────────────────────────────────────

    def _preset_menu(self) -> None:
        print(f"\n{C['b']}Choose scan preset:{C['r']}")
        presets = list(WIZARD_PRESETS.items())
        for i, (key, preset) in enumerate(presets, 1):
            phase_count = len(preset["phases"])
            print(f"  {C['y']}{i}{C['r']}  {preset['name']:20}  ({phase_count} phases)")
            print(f"      {C['d']}{preset['desc']}{C['r']}")
        choice = _prompt("Preset", default="2").strip()
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(presets):
                key, preset = presets[idx]
                self.preset = key
                self.selected_phases = set(preset["phases"])
                for k, v in preset.get("defaults", {}).items():
                    self.config[k] = v
                log("ok", f"Preset: {preset['name']}")
                return
        log("warn", "Invalid selection — using standard")
        self.preset = "standard"
        self.selected_phases = set(WIZARD_PRESETS["standard"]["phases"])

    # ── Target menu (always shown first) ─────────────────────────────────────

    def _target_menu(self) -> None:
        print(f"\n{C['b']}Target configuration:{C['r']}")
        if self.domain:
            print(f"  {C['d']}Current: {self.domain}{C['r']}")
        domain = _prompt(
            "Target domain(s) (comma-separated for multi-domain)",
            default=self.domain,
            validator=lambda v: all(_is_valid_hostname(d.strip()) for d in v.split(",") if d.strip()),
            error_msg="Enter valid domain(s) with at least one dot each",
        )
        self.domain = domain
        self.out = _prompt("Output directory", default=f"./out_{self.domain}")

    # ── Main menu loop ───────────────────────────────────────────────────────

    def _main_menu_loop(self) -> None:
        while True:
            self._print_main_menu()
            choice = input(f"  {C['y']}Select section:{C['r']} ").strip().lower()
            if choice == "1":
                self._edit_target()
            elif choice == "2":
                self._edit_depth()
            elif choice == "3":
                self._edit_phases()
            elif choice == "4":
                self._edit_auth()
            elif choice == "5":
                self._edit_performance()
            elif choice == "6":
                self._edit_dos()
            elif choice == "7":
                self._edit_report()
            elif choice == "8":
                self._edit_compliance()
            elif choice == "9":
                self._edit_threat_intel()
            elif choice == "0":
                self._edit_sample_size()
            elif choice == "s":
                self._do_save_profile()
            elif choice == "l":
                self._do_load_profile()
            elif choice == "r":
                self._reset_to_preset()
            elif choice == "p":
                self._preview_scan()
            elif choice == "" or choice.lower() in ("start", "\r"):
                if self.domain:
                    if _prompt_yes_no("Start scan", default=True):
                        break
                    log("info", "Aborted by user")
                    sys.exit(0)
                else:
                    log("err", "Domain is required — set it in section [1]")
            elif choice == "q":
                log("info", "Aborted by user")
                sys.exit(0)

    def _print_main_menu(self) -> None:
        n = len(self.selected_phases)
        total = len(VALID_PHASES)
        d = self.domain or "not set"
        prox = self.config.get("proxy", "") or "auto"
        dos = "ON" if self.config.get("dos_mode") else "OFF"
        rate = self.config.get("rate_limit", 10)
        fmt = self.config.get("report_format", "html")
        adaptive = "ON" if self.config.get("adaptive_enabled") else "OFF"
        sample_mode = self.config.get("sample_mode", "normal")
        sqlmap = f"{self.config.get('sqlmap_level', 1)}/{self.config.get('sqlmap_risk', 1)}"
        delay = f"{self.config.get('delay', 0)}s"
        prof = f"  Profile: {self.profile_name}" if self.profile_name else ""
        compliance = ", ".join(self.config.get("compliance_frameworks", [])) or "none"
        threat = "ON" if self.config.get("threat_intel") else "OFF"
        ml = "ON" if self.config.get("ml_phase_selection") else "OFF"
        print(f"""
{C['b']}{'─' * 60}{C['r']}
 {C['c']}ReconChain Setup Wizard{C['r']}{prof}  Preset: {C['y']}{self.preset}{C['r']}
{C['b']}{'─' * 60}{C['r']}
  {C['y']}[1]{C['r']} Target & Scope              {C['c']}{d}{C['r']}
  {C['y']}[2]{C['r']} Scan Depth & Timing          sqlmap={C['c']}{sqlmap}{C['r']}  delay={C['c']}{delay}{C['r']}
  {C['y']}[3]{C['r']} Phase Selection              {C['c']}{n}/{total} active{C['r']}
  {C['y']}[4]{C['r']} Auth & Cookies               cookie={C['c']}{'set' if self.config.get('cookie') else 'none'}{C['r']}
  {C['y']}[5]{C['r']} Performance & Proxy          adaptive={C['c']}{adaptive}{C['r']}  proxy={C['c']}{prox}{C['r']}
  {C['y']}[6]{C['r']} DoS & Rate Limits            dos={C['c']}{dos}{C['r']}  rate={C['c']}{rate} r/s{C['r']}
  {C['y']}[7]{C['r']} Reporting                    {C['c']}{fmt}{C['r']}
  {C['y']}[8]{C['r']} Compliance & Audit           {C['c']}{compliance}{C['r']}  threat_intel={C['c']}{threat}{C['r']}
  {C['y']}[9]{C['r']} Intelligence & ML            ml_select={C['c']}{ml}{C['r']}
  {C['y']}[0]{C['r']} Sampling                    sample_mode={C['c']}{sample_mode}{C['r']}
{C['b']}{'─' * 60}{C['r']}
  {C['g']}[S]{C['r']} Save profile   {C['g']}[L]{C['r']} Load profile   {C['g']}[R]{C['r']} Reset to preset
  {C['g']}[P]{C['r']} Preview scan   {C['g']}[Enter]{C['r']} Start scan     {C['g']}[Q]{C['r']} Quit
{C['b']}{'─' * 60}{C['r']}""")

    # ── Section 1: Target ────────────────────────────────────────────────────

    def _edit_target(self) -> None:
        print(f"\n{C['b']}Target & Scope:{C['r']}")
        self.domain = _prompt(
            "Target domain(s)",
            default=self.domain,
            validator=lambda v: all(_is_valid_hostname(d.strip()) for d in v.split(",") if d.strip()),
            error_msg="Enter valid domain(s) with at least one dot each",
        )
        self.out = _prompt("Output directory", default=f"./out_{self.domain}")
        self.config["resume"] = self._check_resume()

    def _check_resume(self) -> bool:
        state_path = Path(self.out) / "state.json"
        if state_path.exists():
            return _prompt_yes_no("State file exists — resume previous scan", default=True)
        return False

    # ── Section 2: Scan Depth ────────────────────────────────────────────────

    def _edit_depth(self) -> None:
        print(f"\n{C['b']}Scan depth configuration:{C['r']}")
        self.config["sqlmap_level"] = int(_prompt(
            "SQLmap --level (1=fast/basic, 5=deep/slow)",
            default=str(self.config["sqlmap_level"]),
            validator=lambda v: v.isdigit() and 1 <= int(v) <= 5,
            error_msg="Enter a number between 1 and 5",
        ))
        self.config["sqlmap_risk"] = int(_prompt(
            "SQLmap --risk (1=safe, 3=aggressive/destructive)",
            default=str(self.config["sqlmap_risk"]),
            validator=lambda v: v.isdigit() and 1 <= int(v) <= 3,
            error_msg="Enter a number between 1 and 3",
        ))
        try:
            delay_val = float(_prompt(
                "Delay between requests in seconds (0=fast, 2=polite, 5=stealth)",
                default=str(self.config["delay"]),
                validator=lambda v: _is_float(v) and float(v) >= 0,
                error_msg="Enter a non-negative number (e.g. 0, 0.5, 2)",
            ))
            self.config["delay"] = delay_val
        except (ValueError, TypeError):
            pass

    # ── Section 3: Phase Selection ───────────────────────────────────────────

    def _edit_phases(self) -> None:
        cats = list(PHASE_CATEGORIES.items())
        while True:
            n = len(self.selected_phases)
            total = len(VALID_PHASES)
            print(f"\n{C['b']}Phase Selection ({n}/{total} active) — Preset: {self.preset}{C['r']}")
            for i, (cat_name, cat_data) in enumerate(cats, 1):
                phases = cat_data["phases"]
                active = sum(1 for pid, _ in phases if pid in self.selected_phases)
                color = C["g"] if active == len(phases) else (C["y"] if active > 0 else C["d"])
                print(f"  {C['y']}{i}{C['r']}  {color}{cat_name}{C['r']}  ({active}/{len(phases)})")
            print(f"\n  {C['g']}[a]{C['r']} Select all   {C['g']}[n]{C['r']} Deselect all   {C['g']}[s]{C['r']} Search   {C['g']}[b]{C['r']} Back")
            choice = input(f"  {C['y']}Category:{C['r']} ").strip().lower()
            if choice == "b":
                break
            elif choice == "a":
                self.selected_phases = set(VALID_PHASES)
                log("ok", "All phases selected")
            elif choice == "n":
                self.selected_phases = set()
                log("ok", "All phases deselected")
            elif choice == "s":
                self._phase_search()
            elif choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(cats):
                    self._edit_category(cats[idx][0], cats[idx][1])

    def _edit_category(self, cat_name: str, cat_data: Dict[str, Any]) -> None:
        phases = cat_data["phases"]
        while True:
            active = sum(1 for pid, _ in phases if pid in self.selected_phases)
            print(f"\n  {C['b']}{cat_name}{C['r']}  ({active}/{len(phases)} active)")
            print(f"  {C['d']}{cat_data['desc']}{C['r']}\n")
            for i, (pid, desc) in enumerate(phases, 1):
                mark = f"{C['g']}x{C['r']}" if pid in self.selected_phases else f"{C['d']}-{C['r']}"
                print(f"    [{mark}] {C['y']}{i:2}{C['r']}  {pid:24} {C['d']}{desc}{C['r']}")
            print(f"\n    {C['g']}[a]{C['r']} Toggle all   {C['g']}[b]{C['r']} Back")
            choice = input(f"    {C['y']}Toggle (e.g. 1,3,5 or 1-5):{C['r']} ").strip().lower()
            if choice == "b":
                break
            elif choice == "a":
                all_on = all(pid in self.selected_phases for pid, _ in phases)
                for pid, _ in phases:
                    if all_on:
                        self.selected_phases.discard(pid)
                    else:
                        self.selected_phases.add(pid)
            else:
                self._toggle_phases_by_input(choice, phases)

    def _toggle_phases_by_input(self, raw: str, phases: List[tuple]) -> None:
        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                try:
                    start_s, end_s = part.split("-", 1)
                    start, end = int(start_s), int(end_s)
                    for j in range(start, end + 1):
                        if 1 <= j <= len(phases):
                            pid = phases[j - 1][0]
                            if pid in self.selected_phases:
                                self.selected_phases.discard(pid)
                            else:
                                self.selected_phases.add(pid)
                except ValueError:
                    log("err", f"Invalid range: {part}")
            elif part.isdigit():
                idx = int(part)
                if 1 <= idx <= len(phases):
                    pid = phases[idx - 1][0]
                    if pid in self.selected_phases:
                        self.selected_phases.discard(pid)
                    else:
                        self.selected_phases.add(pid)
                else:
                    log("err", f"Number out of range: {part}")
            else:
                upper = part.upper()
                matches = [pid for pid, _ in phases if upper in pid.upper()]
                if matches:
                    for pid in matches:
                        if pid in self.selected_phases:
                            self.selected_phases.discard(pid)
                        else:
                            self.selected_phases.add(pid)
                else:
                    log("err", f"No matching phase for: {part}")

    def _phase_search(self) -> None:
        query = _prompt("Search phases (keyword)").strip().lower()
        if not query:
            return
        matches = [(pid, desc) for pid, desc in _all_phase_list() if query in pid.lower() or query in desc.lower()]
        if not matches:
            log("warn", f"No phases matching '{query}'")
            return
        print(f"\n  {C['b']}Found {len(matches)} matching phases:{C['r']}")
        for i, (pid, desc) in enumerate(matches, 1):
            mark = f"{C['g']}x{C['r']}" if pid in self.selected_phases else f"{C['d']}-{C['r']}"
            print(f"    [{mark}] {C['y']}{i:3}{C['r']}  {pid:24} {C['d']}{desc}{C['r']}")
        print(f"\n    {C['g']}[a]{C['r']} Toggle all matches   {C['g']}[b]{C['r']} Back")
        choice = input(f"    {C['y']}Toggle (e.g. 1,3,5 or 1-5):{C['r']} ").strip().lower()
        if choice == "a":
            all_on = all(pid in self.selected_phases for pid, _ in matches)
            for pid, _ in matches:
                if all_on:
                    self.selected_phases.discard(pid)
                else:
                    self.selected_phases.add(pid)
        elif choice != "b":
            self._toggle_phases_by_input(choice, matches)

    # ── Section 4: Auth & Cookies ────────────────────────────────────────────

    def _edit_auth(self) -> None:
        print(f"\n{C['b']}Authentication:{C['r']}")
        self.config["cookie"] = _prompt(
            "Cookie string (e.g. 'session=abc123'), or leave empty",
            default=self.config.get("cookie", ""),
            sensitive=True,
        )
        if self.config["cookie"]:
            self.config["cookie_a"] = _prompt(
                "Session A cookie for IDOR cross-session diffing, or leave empty",
                default=self.config.get("cookie_a", ""),
                sensitive=True,
            )
            if self.config["cookie_a"]:
                self.config["cookie_b"] = _prompt(
                    "Session B cookie for IDOR cross-session diffing, or leave empty",
                    default=self.config.get("cookie_b", ""),
                    sensitive=True,
                )
        else:
            self.config["cookie_a"] = ""
            self.config["cookie_b"] = ""
        extra_raw = _prompt(
            "Extra HTTP headers, comma-separated (e.g. 'Authorization: Bearer xyz'), or leave empty",
            default=",".join(self.config.get("extra_headers", [])),
        )
        self.config["extra_headers"] = [h.strip() for h in extra_raw.split(",") if h.strip()] if extra_raw else []

    # ── Section 5: Performance & Proxy ───────────────────────────────────────

    def _edit_performance(self) -> None:
        print(f"\n{C['b']}Performance mode:{C['r']}")
        print(f"  {C['y']}1{C['r']}  Safe mode       — Conservative: start=1, max=4, max_procs=2")
        print(f"  {C['y']}2{C['r']}  Balanced        — Mid-tier: auto-scales between safe and aggressive (default)")
        print(f"  {C['y']}3{C['r']}  Aggressive      — Max resources: all cores, minimal throttling")
        mode = _prompt("Performance mode", default="2").strip()
        if mode == "1":
            self.config["safe_mode"] = True
            self.config["adaptive_enabled"] = True
            self.config["adaptive_start"] = 1
            self.config["adaptive_max"] = 4
            self.config["adaptive_interval"] = 10.0
            self.config["adaptive_cpu_high"] = 60
            self.config["adaptive_ram_crit"] = 2
            self.config["adaptive_max_procs"] = 2
            self.config["max_procs"] = 0
        elif mode == "3":
            self.config["safe_mode"] = False
            self.config["adaptive_enabled"] = True
            cpu_count = os.cpu_count() or 4
            self.config["adaptive_start"] = cpu_count
            self.config["adaptive_max"] = 0  # unlimited
            self.config["adaptive_interval"] = 1.0
            self.config["adaptive_cpu_high"] = 95
            self.config["adaptive_ram_crit"] = 0.2
            self.config["adaptive_max_procs"] = 0
            self.config["max_procs"] = 0
        else:
            self.config["safe_mode"] = False
            self.config["adaptive_enabled"] = True
            cpu_count = os.cpu_count() or 4
            self.config["adaptive_start"] = max(cpu_count // 2, 2)
            self.config["adaptive_max"] = cpu_count * 2
            self.config["adaptive_interval"] = 5.0
            self.config["adaptive_cpu_high"] = 75
            self.config["adaptive_ram_crit"] = 1.0
            self.config["adaptive_max_procs"] = 0
            self.config["max_procs"] = 0

        proxy = _prompt(
            "Proxy URL (e.g. socks5://127.0.0.1:9050), or leave empty for auto-detect",
            default=self.config.get("proxy", ""),
            validator=lambda v: not v or "://" in v,
            error_msg="Enter a valid proxy URL or leave empty",
        )
        if not proxy:
            proxy = _auto_detect_proxy()
        self.config["proxy"] = proxy

    # ── Section 6: DoS & Rate Limits ─────────────────────────────────────────

    def _edit_dos(self) -> None:
        print(f"\n{C['b']}DoS & Rate Limits:{C['r']}")
        self.config["rate_limit"] = int(_prompt(
            "Rate limit: max requests/sec per tool (0=unlimited, 5=gentle, 10=polite, 50=fast)",
            default=str(self.config.get("rate_limit", 10)),
            validator=lambda v: v.isdigit() and int(v) >= 0,
            error_msg="Enter 0 or a positive number",
        ))
        self.config["dos_mode"] = _prompt_yes_no(
            "DoS mode — enable aggressive attacks (race bursts, HTTP smuggling, GraphQL depth DoS)",
            default=self.config.get("dos_mode", False),
        )
        if not self.config["dos_mode"]:
            print(f"  {C['y']}DoS phases disabled:{C['r']} 20-GRAPHQL, 23-RACE, 34-RATELIMIT, 38-SMUGGLE, 38b-H2SMUGGLE, 54-WS-FUZZ, 83-RACEBURST, 93-PWDSPRAY, 132-GQLABUSE, 136-RATELIMITBYPASS")

    # ── Section 7: Reporting ─────────────────────────────────────────────────

    def _edit_report(self) -> None:
        print(f"\n{C['b']}Reporting:{C['r']}")
        self.config["report_format"] = _prompt(
            "Report format (html, md, json, sarif)",
            default=self.config.get("report_format", "html"),
            validator=lambda v: v in ("html", "md", "json", "sarif"),
            error_msg="Enter html, md, json, or sarif",
        )
        print(f"\n{C['b']}Scan depth fine-tuning:{C['r']}")
        self.config["sample_urls_fuzz"] = _prompt(
            "Number of URLs to fuzz (enter 'all' for every URL)",
            default=str(self.config.get("sample_urls_fuzz", "5")),
            validator=_validate_count,
            error_msg="Enter a positive number or 'all'",
        )
        self.config["sample_urls_params"] = _prompt(
            "Number of URLs for parameter discovery (enter 'all' for every URL)",
            default=str(self.config.get("sample_urls_params", "50")),
            validator=_validate_count,
            error_msg="Enter a positive number or 'all'",
        )
        self.config["fast"] = _prompt_yes_no(
            "Fast mode — reduce sample sizes for quicker scans",
            default=self.config.get("fast", False),
        )

    # ── Section 8: Compliance & Audit ────────────────────────────────────────

    def _edit_compliance(self) -> None:
        print(f"\n{C['b']}Compliance & Audit:{C['r']}")
        print(f"  {C['d']}Generate compliance reports mapping findings to regulatory frameworks{C['r']}")
        print(f"\n  {C['y']}1{C['r']}  PCI DSS v4.0     — Payment card industry data security")
        print(f"  {C['y']}2{C['r']}  HIPAA             — Healthcare data protection")
        print(f"  {C['y']}3{C['r']}  SOC 2 Type II     — Service organization controls")
        print(f"  {C['y']}4{C['r']}  All frameworks")
        print(f"  {C['y']}0{C['r']}  None (skip)")
        choice = _prompt("Compliance framework", default="0").strip()
        frameworks = []
        if choice == "1":
            frameworks = ["pci_dss"]
        elif choice == "2":
            frameworks = ["hipaa"]
        elif choice == "3":
            frameworks = ["soc2"]
        elif choice == "4":
            frameworks = ["pci_dss", "hipaa", "soc2"]
        self.config["compliance_frameworks"] = frameworks
        self.config["compliance_report"] = len(frameworks) > 0

        if frameworks:
            log("ok", f"Compliance frameworks: {', '.join(frameworks)}")

    # ── Section 9: Intelligence & ML ─────────────────────────────────────────

    def _edit_threat_intel(self) -> None:
        print(f"\n{C['b']}Intelligence & Machine Learning:{C['r']}")
        self.config["threat_intel"] = _prompt_yes_no(
            "Enable MITRE ATT&CK mapping (maps findings to attack techniques)",
            default=self.config.get("threat_intel", False),
        )
        if self.config["threat_intel"]:
            self.config["threat_intel_feeds"] = _prompt(
                "Path to threat feed JSON file (or leave empty for built-in only)",
                default=self.config.get("threat_intel_feeds", ""),
            )

        self.config["ml_phase_selection"] = _prompt_yes_no(
            "Enable ML-assisted phase selection (adapts scan order based on results)",
            default=self.config.get("ml_phase_selection", True),
        )

        self.config["credential_store"] = _prompt_yes_no(
            "Enable encrypted credential storage (for API keys, passwords)",
            default=self.config.get("credential_store", False),
        )

        self.config["collaborative_mode"] = _prompt_yes_no(
            "Enable collaborative scanning (team workspace, shared findings)",
            default=self.config.get("collaborative_mode", False),
        )
        if self.config["collaborative_mode"]:
            self.config["workspace_name"] = _prompt(
                "Workspace name",
                default=self.config.get("workspace_name", self.domain or "default"),
            )
            log("ok", f"Collaborative workspace: {self.config['workspace_name']}")

    # ── Section 10: Sampling ────────────────────────────────────────────────

    def _edit_sample_size(self) -> None:
        print(f"\n{C['b']}Sample Size:{C['r']}")
        print(f"  {C['y']}1{C['r']}  Minimal       — Test 1 item per tool/phase (fastest, least coverage)")
        print(f"  {C['y']}2{C['r']}  Normal        — Default sample sizes per tool (balanced)")
        print(f"  {C['y']}3{C['r']}  All           — No sampling limits (slowest, full coverage)")
        mode = _prompt("Sample mode", default="2").strip()
        if mode == "1":
            self.config["sample_mode"] = "minimal"
            log("ok", "Sample mode: minimal — all sample sizes set to 1")
        elif mode == "3":
            self.config["sample_mode"] = "all"
            log("ok", "Sample mode: all — no sampling limits applied")
        else:
            self.config["sample_mode"] = "normal"
            log("ok", "Sample mode: normal — default sample sizes")

    # ── Profile save/load helpers ────────────────────────────────────────────

    def _do_save_profile(self) -> None:
        name = _prompt("Profile name", default=self.profile_name or self.domain).strip()
        if not name:
            log("err", "Profile name required")
            return
        from reconchain.conf import save_profile
        data = {
            "profile_name": name,
            "domain": self.domain,
            "preset": self.preset,
            "selected_phases": sorted(self.selected_phases),
            "config": self.config,
        }
        if save_profile(name, data):
            self.profile_name = name
            log("ok", f"Profile saved: {name}")
        else:
            log("err", "Failed to save profile")

    def _do_load_profile(self) -> None:
        from reconchain.conf import list_profiles, load_profile
        profiles = list_profiles()
        if not profiles:
            log("warn", "No saved profiles found")
            return
        print(f"\n{C['b']}Saved profiles:{C['r']}")
        for i, p in enumerate(profiles, 1):
            print(f"  {C['y']}{i}{C['r']}  {p['name']:20}  preset={p['preset']}  phases={p['phases']}")
        choice = _prompt("Load profile", default="").strip()
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(profiles):
                data = load_profile(profiles[idx]["name"])
                if data:
                    self._apply_profile(data)
                    self.profile_name = profiles[idx]["name"]
                    log("ok", f"Loaded profile: {self.profile_name}")

    def _reset_to_preset(self) -> None:
        if self.preset in WIZARD_PRESETS:
            self.selected_phases = set(WIZARD_PRESETS[self.preset]["phases"])
            for k, v in WIZARD_PRESETS[self.preset].get("defaults", {}).items():
                self.config[k] = v
            log("ok", f"Reset to preset: {WIZARD_PRESETS[self.preset]['name']}")

    # ── Preview ──────────────────────────────────────────────────────────────

    def _preview_scan(self) -> None:
        n = len(self.selected_phases)
        proxy = self.config.get("proxy", "")
        adaptive = self.config.get("adaptive_enabled", True)
        compliance = ", ".join(self.config.get("compliance_frameworks", [])) or "none"
        threat = "ON" if self.config.get("threat_intel") else "OFF"
        ml = "ON" if self.config.get("ml_phase_selection") else "OFF"
        creds = "ON" if self.config.get("credential_store") else "OFF"
        collab = self.config.get("workspace_name") or "none"
        print(f"\n{C['b']}{'─' * 60}{C['r']}")
        print(f" {C['g']}Scan summary:{C['r']}")
        print(f"   Domain:           {C['y']}{self.domain}{C['r']}")
        print(f"   Output:           {C['y']}{self.out}{C['r']}")
        print(f"   Preset:           {C['y']}{self.preset}{C['r']}")
        print(f"   Profile:          {C['y']}{self.profile_name or '(none)'}{C['r']}")
        print(f"   Proxy:            {C['y']}{proxy or 'auto-detected'}{C['r']}")
        print(f"   Phases:           {C['y']}{n} active of {len(VALID_PHASES)}{C['r']}")
        if adaptive:
            print(f"   Adaptive:         {C['y']}ON (start={self.config.get('adaptive_start')}, max={self.config.get('adaptive_max')}){C['r']}")
        else:
            print(f"   Max procs:        {C['y']}{self.config.get('max_procs', 0) or 'auto'}{C['r']}")
        print(f"   Rate limit:       {C['y']}{self.config.get('rate_limit', 0)} req/s{C['r']}")
        print(f"   SQLmap level/risk:{C['y']} {self.config.get('sqlmap_level')}/{self.config.get('sqlmap_risk')}{C['r']}")
        print(f"   Delay:            {C['y']}{self.config.get('delay')}s{C['r']}")
        print(f"   Cookie:           {C['y']}{'set' if self.config.get('cookie') else 'none'}{C['r']}")
        print(f"   Report:           {C['y']}{self.config.get('report_format')}{C['r']}")
        print(f"   Fast mode:        {C['y']}{'yes' if self.config.get('fast') else 'no'}{C['r']}")
        print(f"   DoS mode:         {C['y']}{'yes' if self.config.get('dos_mode') else 'no'}{C['r']}")
        print(f"   Safe mode:        {C['y']}{'ON' if self.config.get('safe_mode') else 'OFF'}{C['r']}")
        print(f"   Compliance:       {C['y']}{compliance}{C['r']}")
        print(f"   Threat Intel:     {C['y']}{threat}{C['r']}")
        print(f"   ML Phase Select:  {C['y']}{ml}{C['r']}")
        print(f"   Cred Store:       {C['y']}{creds}{C['r']}")
        print(f"   Workspace:        {C['y']}{collab}{C['r']}")
        print(f" {C['b']}{'─' * 60}{C['r']}")

    # ── Build argparse.Namespace ─────────────────────────────────────────────

    def _build_namespace(self) -> argparse.Namespace:
        cfg = self.config
        selected = set(self.selected_phases)
        if not cfg.get("dos_mode"):
            selected = selected - DOS_PHASES
        speed = cfg.get("fast", False)
        proxy = cfg.get("proxy", "")
        adaptive = cfg.get("adaptive_enabled", True)
        safe_mode = cfg.get("safe_mode", False)
        ns = argparse.Namespace()
        ns.domain = self.domain
        ns.out = str(Path(self.out).resolve())
        ns.only = selected
        ns.skip = set()
        ns.jobs = MAX_PARALLEL_JOBS
        ns.adaptive = adaptive
        ns.adaptive_start = cfg.get("adaptive_start", 1)
        ns.adaptive_max = cfg.get("adaptive_max", 4)
        ns.adaptive_interval = cfg.get("adaptive_interval", 5.0)
        ns.adaptive_cpu_high = cfg.get("adaptive_cpu_high", 80)
        ns.adaptive_ram_crit = cfg.get("adaptive_ram_crit", 1.0)
        ns.adaptive_max_procs = cfg.get("adaptive_max_procs", 0)
        ns.safe = safe_mode
        ns.max_procs = 0 if adaptive else cfg.get("max_procs", 0)
        ns.fast = speed
        ns.dos_mode = cfg.get("dos_mode", False)
        ns.sample_mode = cfg.get("sample_mode", "normal")
        ns.resume = cfg.get("resume", False)
        ns.force = cfg.get("resume", False) is False
        ns.sample = False
        ns.quiet = False
        ns.no_color = False
        ns.interactive = True
        ns.sqlmap_level = cfg.get("sqlmap_level", 1)
        ns.sqlmap_risk = cfg.get("sqlmap_risk", 1)
        ns.delay = float(cfg.get("delay", 0))
        ns.proxy = proxy
        ns.rate_limit = cfg.get("rate_limit", 10)
        ns.vuln_proxy = ""
        ns.cookie = cfg.get("cookie", "")
        ns.cookie_a = cfg.get("cookie_a", "")
        ns.cookie_b = cfg.get("cookie_b", "")
        ns.extra_headers = cfg.get("extra_headers", [])
        ns.daemon = False
        ns.status = ""
        ns.format = cfg.get("report_format", "html")

        def _resolve_count(v: str) -> int:
            return sys.maxsize if v.lower() == "all" else int(v)

        ns.sample_urls_fuzz = _resolve_count(str(cfg.get("sample_urls_fuzz", "5")))
        ns.sample_urls_params = _resolve_count(str(cfg.get("sample_urls_params", "50")))
        ns.exclude_tags = ""
        ns.proxy_timeout_multiplier = 1.5
        ns.incremental = False
        ns.notify = ""
        ns.distributed = False
        ns.distributed_hosts = []
        ns.distributed_workers = 5
        ns.distributed_ssh_key = ""
        ns.distributed_ssh_user = "root"
        ns.no_fix_permissions = False
        ns.config = ""
        ns.dry_run = False
        ns.parallel = True
        ns.gen_config = False
        ns.compliance = cfg.get("compliance_frameworks", [])
        ns.threat_intel = cfg.get("threat_intel", False)
        ns.threat_intel_feeds = cfg.get("threat_intel_feeds", "")
        ns.ml_phase_selection = cfg.get("ml_phase_selection", True)
        ns.credential_store = cfg.get("credential_store", False)
        ns.collaborative = cfg.get("collaborative_mode", False)
        ns.workspace_name = cfg.get("workspace_name", "")

        _set_sample_defaults(ns, speed)
        return ns


def _set_sample_defaults(ns: argparse.Namespace, speed: bool) -> None:
    """Set all sample_* namespace attributes to their default values."""
    ns.sample_urls_xss_blind = 20
    ns.sample_urls_ssti = 5
    ns.sample_urls_nosqli = 30
    ns.sample_endpoints_race = 10
    ns.sample_hosts_jwt = 20
    ns.sample_urls_xxe = 10
    ns.sample_urls_cmdi = 30
    ns.sample_endpoints_sspp = 10
    ns.sample_hosts_cached = 10
    ns.sample_urls_depcheck = 30
    ns.sample_urls_redirect = 30
    ns.sample_hosts_clickjack = 20
    ns.sample_urls_crlf = 20
    ns.sample_hosts_ratelimit = 10
    ns.sample_endpoints_corsadv = 10
    ns.sample_hosts_jwtadv = 20
    ns.sample_urls_upload = 10
    ns.sample_hosts_smuggle = 10
    ns.sample_endpoints_oauth = 10
    ns.sample_endpoints_pwreset = 10
    ns.sample_hosts_websocket = 10
    ns.sample_hosts_h2smuggle = 10
    ns.sample_hosts_frameworks = 20
    ns.sample_urls_domxss = 30
    ns.sample_urls_ldap = 20
    ns.sample_endpoints_deserial = 10
    ns.sample_hosts_ssl = 10
    ns.sample_hosts_origin = 10
    ns.sample_endpoints_cors = 10
    ns.sample_endpoints_l = 20
    ns.sample_endpoints_post = 5
    ns.sample_hosts_iisaspnet = 10
    ns.sample_hosts_tomcat = 10
    ns.sample_hosts_nodejs = 10
    ns.sample_hosts_laravel = 10
    ns.sample_hosts_django = 10
    ns.sample_hosts_symfony = 10
    ns.sample_hosts_cicd = 10
    ns.sample_hosts_docker = 10
    ns.sample_hosts_k8s = 10
    ns.sample_hosts_terraform = 10
    ns.sample_hosts_envdeep = 10
    ns.sample_hosts_gqlabuse = 10
    ns.sample_urls_apiversion = 20
    ns.sample_hosts_lbdetect = 15
    ns.sample_hosts_vhost = 10
    ns.sample_urls_ratelimitbypass = 20
    ns.sample_urls_csrf = 20
    ns.sample_hosts_sessionfix = 10
    ns.sample_endpoints_saml = 10
    ns.sample_users_spray = 20
    ns.sample_hosts_cookie = 20
    ns.sample_urls_posttest = 30
    ns.sample_urls_methodoverride = 20
    ns.sample_hosts_forcedbrowse = 20
    ns.sample_urls_casebypass = 20
    ns.sample_urls_apipage = 20
    ns.sample_urls_tabnab = 30
    ns.sample_urls_apikeyleak = 30
    ns.sample_urls_redirabuse = 20
    ns.sample_urls_logtrigger = 20
    ns.sample_urls_xssstored = 10
    ns.sample_hosts_hostabuse = 10
    ns.sample_urls_authbypassadv = 20
    ns.sample_urls_ssi = 20
    ns.sample_urls_jsoninject = 20
    ns.sample_urls_nullbyte = 20
    ns.sample_urls_doubleencod = 20
    ns.sample_urls_unicode = 20
    ns.sample_hosts_postmsg = 15
    ns.sample_hosts_jsonp = 20
    ns.sample_hosts_sri = 20
    ns.sample_hosts_mixedcontent = 20
    ns.sample_hosts_hstspreload = 20
    ns.sample_hosts_thirdpartyjs = 15
    ns.sample_hosts_browserstorage = 15
    ns.sample_urls_rfi = 20
    ns.sample_hosts_webdav = 10
    ns.sample_hosts_snmp = 10
    ns.sample_hosts_banner = 15
    ns.sample_hosts_phpinfo = 15
    ns.sample_hosts_srvstatus = 15
    ns.sample_urls_errorleak = 20
    ns.sample_hosts_wildcarddns = 10
    ns.sample_hosts_dnsrebind = 10
    ns.sample_hosts_cloud = 5
    ns.sample_hosts_git = 5
    ns.sample_hosts_graphql = 5
    ns.sample_hosts_waf = 5
    ns.sample_endpoints_ratelimit = 5
    ns.sample_hosts_emailfinder = 10
    ns.sample_urls_metagoofil = 50
    ns.sample_hosts_porchpirate = 10
    ns.sample_urls_dorkhunter = 20
    ns.sample_hosts_crtsh = 10
    ns.sample_hosts_githubsub = 10
    ns.sample_hosts_tlsx = 10
    ns.sample_hosts_analyticsrels = 10
    ns.sample_hosts_favirecon = 10
    ns.sample_urls_jsluice = 20
    ns.sample_urls_shortscan = 20
    ns.sample_hosts_grpcurl = 10
    if speed:
        ns.sample_urls_fuzz = min(ns.sample_urls_fuzz, 50)
        ns.sample_urls_params = min(ns.sample_urls_params, 10)
        ns.sample_urls_nosqli = min(ns.sample_urls_nosqli, 5)
        ns.sample_urls_cmdi = min(ns.sample_urls_cmdi, 5)
        ns.sample_urls_xxe = min(ns.sample_urls_xxe, 3)
        ns.sample_urls_crlf = min(ns.sample_urls_crlf, 5)
        ns.sample_urls_redirect = min(ns.sample_urls_redirect, 5)
        ns.sample_urls_ldap = min(ns.sample_urls_ldap, 5)
        ns.sample_urls_depcheck = min(ns.sample_urls_depcheck, 5)
        ns.sample_urls_upload = min(ns.sample_urls_upload, 3)
        ns.sample_urls_xss_blind = min(ns.sample_urls_xss_blind, 5)
        ns.sample_urls_ssti = min(ns.sample_urls_ssti, 2)
        ns.sample_hosts_ssl = min(ns.sample_hosts_ssl, 2)
        ns.sample_hosts_origin = min(ns.sample_hosts_origin, 3)
        ns.sample_hosts_cloud = min(ns.sample_hosts_cloud, 2)
        ns.sample_hosts_git = min(ns.sample_hosts_git, 2)
        ns.sample_hosts_graphql = min(ns.sample_hosts_graphql, 2)
        ns.sample_hosts_waf = min(ns.sample_hosts_waf, 2)
        ns.sample_hosts_jwt = min(ns.sample_hosts_jwt, 5)
        ns.sample_hosts_jwtadv = min(ns.sample_hosts_jwtadv, 5)
        ns.sample_hosts_cached = min(ns.sample_hosts_cached, 3)
        ns.sample_hosts_clickjack = min(ns.sample_hosts_clickjack, 5)
        ns.sample_hosts_ratelimit = min(ns.sample_hosts_ratelimit, 3)
        ns.sample_hosts_smuggle = min(ns.sample_hosts_smuggle, 3)
        ns.sample_hosts_websocket = min(ns.sample_hosts_websocket, 3)
        ns.sample_hosts_h2smuggle = min(ns.sample_hosts_h2smuggle, 3)
        ns.sample_hosts_frameworks = min(ns.sample_hosts_frameworks, 5)
        ns.sample_urls_domxss = min(ns.sample_urls_domxss, 5)
        ns.sample_endpoints_race = min(ns.sample_endpoints_race, 3)
        ns.sample_endpoints_cors = min(ns.sample_endpoints_cors, 3)
        ns.sample_endpoints_corsadv = min(ns.sample_endpoints_corsadv, 3)
        ns.sample_endpoints_sspp = min(ns.sample_endpoints_sspp, 3)
        ns.sample_endpoints_l = min(ns.sample_endpoints_l, 5)
        ns.sample_endpoints_post = min(ns.sample_endpoints_post, 2)
        ns.sample_endpoints_oauth = min(ns.sample_endpoints_oauth, 3)
        ns.sample_endpoints_pwreset = min(ns.sample_endpoints_pwreset, 3)
        ns.sample_endpoints_deserial = min(ns.sample_endpoints_deserial, 3)
        ns.sample_hosts_iisaspnet = min(ns.sample_hosts_iisaspnet, 3)
        ns.sample_hosts_tomcat = min(ns.sample_hosts_tomcat, 3)
        ns.sample_hosts_nodejs = min(ns.sample_hosts_nodejs, 3)
        ns.sample_hosts_laravel = min(ns.sample_hosts_laravel, 3)
        ns.sample_hosts_django = min(ns.sample_hosts_django, 3)
        ns.sample_hosts_symfony = min(ns.sample_hosts_symfony, 3)
        ns.sample_hosts_cicd = min(ns.sample_hosts_cicd, 3)
        ns.sample_hosts_docker = min(ns.sample_hosts_docker, 3)
        ns.sample_hosts_k8s = min(ns.sample_hosts_k8s, 3)
        ns.sample_hosts_terraform = min(ns.sample_hosts_terraform, 3)
        ns.sample_hosts_envdeep = min(ns.sample_hosts_envdeep, 3)
        ns.sample_hosts_gqlabuse = min(ns.sample_hosts_gqlabuse, 3)
        ns.sample_urls_apiversion = min(ns.sample_urls_apiversion, 5)
        ns.sample_hosts_lbdetect = min(ns.sample_hosts_lbdetect, 3)
        ns.sample_hosts_vhost = min(ns.sample_hosts_vhost, 3)
        ns.sample_urls_ratelimitbypass = min(ns.sample_urls_ratelimitbypass, 5)
