"""Tests for vulnforge.conf — external config file handling and wizard profiles."""

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from vulnforge import conf


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch):
    for key in (
        "SHODAN_API_KEY",
        "WHOISXML_API",
        "PDCP_API_KEY",
        "COLLAB_SERVER",
        "XSS_SERVER",
        "SLACK_WEBHOOK_URL",
        "DISCORD_WEBHOOK_URL",
        "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_CHAT_ID",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
    ):
        monkeypatch.delenv(key, raising=False)


class TestFindConfig:
    def test_explicit_path_exists(self, tmp_path):
        p = tmp_path / "vulnforge.cfg"
        p.write_text("[general]\n")
        assert conf.find_config(str(p)) == p

    def test_explicit_path_missing(self, tmp_path):
        assert conf.find_config(str(tmp_path / "nope.cfg")) is None

    def test_search_paths(self, tmp_path, monkeypatch):
        p = tmp_path / "vulnforge.cfg"
        p.write_text("[general]\n")
        monkeypatch.setattr(conf, "_CONFIG_SEARCH_PATHS", [p])
        assert conf.find_config() == p

    def test_search_paths_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr(conf, "_CONFIG_SEARCH_PATHS", [tmp_path / "nope.cfg"])
        assert conf.find_config() is None


class TestLoadConfig:
    def test_no_config(self, monkeypatch):
        monkeypatch.setattr(conf, "find_config", lambda *a: None)
        assert conf.load_config() == {}

    def test_toml_roundtrip(self, tmp_path):
        p = tmp_path / "vulnforge.cfg"
        p.write_text('[general]\nproxy = "socks5://127.0.0.1:9050"\nrate_limit = 50\n')
        cfg = conf.load_config(p)
        assert cfg["general"]["proxy"] == "socks5://127.0.0.1:9050"
        assert cfg["general"]["rate_limit"] == 50

    def test_invalid_toml_returns_empty(self, tmp_path, capsys):
        p = tmp_path / "vulnforge.cfg"
        p.write_text("this is not = [valid toml")
        assert conf.load_config(p) == {}
        assert "config parse error" in capsys.readouterr().err

    def test_fallback_simple_parser(self, tmp_path, monkeypatch):
        monkeypatch.setattr(conf, "tomllib", None)
        p = tmp_path / "vulnforge.cfg"
        p.write_text("[general]\nrate_limit = 50\n")
        assert conf.load_config(p) == {"general": {"rate_limit": 50}}


class TestParseSimple:
    def _parse(self, text):
        return conf._parse_simple(Path(text))

    def test_sections_and_scalars(self, tmp_path):
        p = tmp_path / "c.cfg"
        p.write_text(
            "[general]\n"
            "proxy = socks5://127.0.0.1:9050\n"
            "no_color = true\n"
            "delay = 0.5\n"
            "count = 3\n"
            "quoted = \"x\"\n"
            "comment = value # trailing\n"
        )
        result = conf._parse_simple(p)
        assert result["general"]["no_color"] is True
        assert result["general"]["delay"] == 0.5
        assert result["general"]["count"] == 3
        assert result["general"]["quoted"] == "x"
        assert result["general"]["comment"] == "value"

    def test_arrays(self, tmp_path):
        p = tmp_path / "c.cfg"
        p.write_text('[general]\ntokens = ["a", "b"]\nnums = [1, 2, 3]\nempty = []\n')
        result = conf._parse_simple(p)
        assert result["general"]["tokens"] == ["a", "b"]
        assert result["general"]["nums"] == [1, 2, 3]
        assert result["general"]["empty"] == []

    def test_booleans_and_yes_no(self, tmp_path):
        p = tmp_path / "c.cfg"
        p.write_text("[general]\na = yes\nb = no\nc = false\n")
        result = conf._parse_simple(p)
        assert result["general"]["a"] is True
        assert result["general"]["b"] is False
        assert result["general"]["c"] is False

    def test_blank_and_comment_lines(self, tmp_path):
        p = tmp_path / "c.cfg"
        p.write_text("\n# comment\n[general]\n# inner\nkey = 1\n")
        assert conf._parse_simple(p) == {"general": {"key": 1}}

    def test_bare_value_not_string(self, tmp_path):
        p = tmp_path / "c.cfg"
        p.write_text("[general]\nname = hello\n")
        assert conf._parse_simple(p)["general"]["name"] == "hello"

    def test_unreadable_file(self, tmp_path):
        assert conf._parse_simple(tmp_path / "missing.cfg") == {}


def _args(**overrides):
    base = dict(proxy=None, vuln_proxy=None, delay=None, rate_limit=None, jobs=None,
                cookie=None, no_color=False, safe=False, dos_mode=False, sqlmap_level=1,
                sqlmap_risk=1, exclude_tags=None, sample_mode=None, cookie_a=None,
                cookie_b=None, ai_provider=None, ai_model=None, dashboard=False,
                dashboard_port=0, dashboard_host=None, bot=None, bot_token=None,
                bot_channel=None, bot_mention=False, plugins_dir=None)
    defaults = dict(base)
    defaults.update(overrides.pop("_defaults", {}))
    base.update(overrides)
    ns = SimpleNamespace(**base)
    ns._defaults = defaults
    return ns


class TestApplyConfigToArgs:
    def test_empty_config_noop(self):
        a = _args(proxy="cli-value")
        assert conf.apply_config_to_args({}, a) is a

    def test_general_section(self):
        cfg = {"general": {"proxy": "socks5://127.0.0.1:9050", "delay": 0.5,
                           "rate_limit": 42, "parallel_jobs": 8, "cookie": "c=1",
                           "no_color": True, "safe_mode": True}}
        a = conf.apply_config_to_args(cfg, _args())
        assert a.proxy == "socks5://127.0.0.1:9050"
        assert a.delay == 0.5
        assert a.rate_limit == 42
        assert a.jobs == 8
        assert a.cookie == "c=1"
        assert a.no_color is True
        assert a.safe is True

    def test_scan_section(self):
        cfg = {"scan": {"dos_mode": True, "sqlmap_level": 2, "sqlmap_risk": 3,
                        "nuclei_exclude_tags": "dos", "safe_mode": True}}
        a = conf.apply_config_to_args(cfg, _args())
        assert a.dos_mode is True
        assert a.sqlmap_level == 2
        assert a.sqlmap_risk == 3
        assert a.exclude_tags == "dos"
        assert a.safe is True

    def test_idor_and_env_sections(self, monkeypatch):
        cfg = {"idor": {"cookie_a": "user=1", "cookie_b": "user=2"},
               "api": {"shodan_key": "k1", "whoisxml_key": "k2"},
               "notify": {"slack_webhook": "https://hooks.slack.com/x"}}
        a = conf.apply_config_to_args(cfg, _args())
        assert a.cookie_a == "user=1"
        assert a.cookie_b == "user=2"
        assert os.environ.get("SHODAN_API_KEY") == "k1"
        assert os.environ.get("WHOISXML_API") == "k2"
        assert os.environ.get("SLACK_WEBHOOK_URL") == "https://hooks.slack.com/x"

    def test_proxy_section_sets_when_general_absent(self):
        cfg = {"proxy": {"url": "http://127.0.0.1:8080"}}
        a = conf.apply_config_to_args(cfg, _args())
        assert a.proxy == "http://127.0.0.1:8080"

    def test_invalid_proxy_scheme_ignored(self, capsys):
        cfg = {"general": {"proxy": "ftp://bad.example"}}
        a = conf.apply_config_to_args(cfg, _args())
        assert a.proxy is None
        assert "invalid proxy URL scheme" in capsys.readouterr().err

    def test_ai_section_env(self, monkeypatch):
        cfg = {"ai": {"provider": "anthropic", "model": "claude-3", "api_key": "ak"}}
        a = conf.apply_config_to_args(cfg, _args())
        assert a.ai_provider == "anthropic"
        assert a.ai_model == "claude-3"
        assert os.environ.get("ANTHROPIC_API_KEY") == "ak"

    def test_ai_defaults_to_openai_env(self):
        cfg = {"ai": {"api_key": "ok"}}
        conf.apply_config_to_args(cfg, _args())
        assert os.environ.get("OPENAI_API_KEY") == "ok"

    def test_dashboard_section(self):
        cfg = {"dashboard": {"enabled": True, "port": 9000, "host": "0.0.0.0"}}
        a = conf.apply_config_to_args(cfg, _args())
        assert a.dashboard is True
        assert a.dashboard_port == 9000
        assert a.dashboard_host == "0.0.0.0"

    def test_dashboard_default_port(self):
        cfg = {"dashboard": {"enabled": True}}
        a = conf.apply_config_to_args(cfg, _args())
        assert a.dashboard is True
        assert a.dashboard_port == 8765

    def test_bot_and_plugins_sections(self):
        cfg = {"bot": {"platform": "discord", "token": "t", "channel_id": "c",
                       "mention_on_critical": True},
               "plugins": {"directory": "/tmp/plugs"}}
        a = conf.apply_config_to_args(cfg, _args())
        assert a.bot == "discord"
        assert a.bot_token == "t"
        assert a.bot_channel == "c"
        assert a.bot_mention is True
        assert a.plugins_dir == "/tmp/plugs"

    def test_cli_flag_takes_precedence(self):
        cfg = {"general": {"rate_limit": 42}}
        a = conf.apply_config_to_args(cfg, _args(rate_limit=7, _defaults={"rate_limit": 10}))
        assert a.rate_limit == 7

    def test_config_applied_when_at_default(self):
        cfg = {"general": {"rate_limit": 42}}
        a = conf.apply_config_to_args(cfg, _args(rate_limit=10, _defaults={"rate_limit": 10}))
        assert a.rate_limit == 42

    def test_github_tokens_written(self, tmp_path, monkeypatch):
        fake_home = tmp_path / "home"
        monkeypatch.setattr(Path, "home", lambda: fake_home)
        cfg = {"api": {"github_tokens": ["tok1", "tok2"]}}
        conf.apply_config_to_args(cfg, _args())
        tokens_file = fake_home / "Tools" / ".github_tokens"
        assert tokens_file.read_text().splitlines() == ["tok1", "tok2"]

    def test_github_tokens_dedup(self, tmp_path, monkeypatch):
        fake_home = tmp_path / "home"
        monkeypatch.setattr(Path, "home", lambda: fake_home)
        tokens_file = fake_home / "Tools" / ".github_tokens"
        tokens_file.parent.mkdir(parents=True)
        tokens_file.write_text("tok1\n")
        conf.apply_config_to_args({"api": {"github_tokens": ["tok1", "tok3"]}}, _args())
        assert tokens_file.read_text().splitlines() == ["tok1", "tok3"]

    def test_bool_proxy_coerced(self):
        cfg = {"proxy": {"url": True}}
        a = conf.apply_config_to_args(cfg, _args())
        assert a.proxy == "true"

    def test_top_level_scalars_without_general_section(self):
        cfg = {"proxy": "socks5://127.0.0.1:9050", "rate_limit": 42}
        a = conf.apply_config_to_args(cfg, _args())
        assert a.proxy == "socks5://127.0.0.1:9050"
        assert a.rate_limit == 42

    def test_section_not_leaked_into_general(self):
        cfg = {"proxy": {"url": "http://127.0.0.1:8080"}}
        a = conf.apply_config_to_args(cfg, _args())
        assert a.proxy == "http://127.0.0.1:8080"
        assert isinstance(a.proxy, str)


class TestEnvHelper:
    def test_sets_env_for_nonempty(self):
        conf._set_env_if_present("SHODAN_API_KEY", "  value  ")
        assert os.environ.get("SHODAN_API_KEY") == "value"

    def test_ignores_empty(self):
        conf._set_env_if_present("SHODAN_API_KEY", "   ")
        assert os.environ.get("SHODAN_API_KEY") is None


class TestExampleConfig:
    def test_generate_contains_sections(self):
        text = conf.generate_example_config()
        assert "[general]" in text
        assert "[scan]" in text
        assert "vulnforge.cfg" in text


class TestProfiles:
    @pytest.fixture
    def profiles(self, tmp_path, monkeypatch):
        profiles_dir = tmp_path / "profiles"
        profiles_dir.mkdir()
        monkeypatch.setattr(conf, "_PROFILES_DIR", profiles_dir)
        return profiles_dir

    def test_save_load_roundtrip(self, profiles):
        assert conf.save_profile("my scan", {"preset": "quick", "domain": "x.com"})
        data = conf.load_profile("my scan")
        assert data["preset"] == "quick"
        assert data["domain"] == "x.com"

    def test_list_profiles(self, profiles):
        conf.save_profile("a", {"domain": "a.com"})
        conf.save_profile("b", {"domain": "b.com"})
        names = [p["name"] for p in conf.list_profiles()]
        assert names == ["a", "b"]
        assert conf.list_profiles()[0]["path"]

    def test_sanitizes_name(self, profiles):
        conf.save_profile("a/b..c", {"domain": "x"})
        assert (profiles / "a_b_c.json").exists()

    def test_load_missing(self, profiles):
        assert conf.load_profile("nope") is None

    def test_load_corrupt_json(self, profiles):
        (profiles / "bad.json").write_text("{not json")
        assert conf.load_profile("bad") is None

    def test_save_empty_name(self, profiles):
        assert conf.save_profile("...", {}) is False

    def test_delete(self, profiles):
        conf.save_profile("d", {"domain": "x"})
        assert conf.delete_profile("d") is True
        assert conf.delete_profile("d") is False
