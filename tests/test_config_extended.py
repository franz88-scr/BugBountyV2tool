"""Tests for PipelineConfig and auth configuration."""
import pytest

from reconchain.config import PipelineConfig, VALID_PHASES
from reconchain.exceptions import ConfigError


class TestPipelineConfig:
    def test_defaults(self):
        cfg = PipelineConfig()
        assert cfg.dos_mode is True
        assert cfg.delay == 0.0
        assert cfg.rate_limit == 0
        assert cfg.proxy == ""
        assert cfg.safe_mode is False

    def test_auth_defaults(self):
        cfg = PipelineConfig()
        assert cfg.auth_bearer == ""
        assert cfg.auth_api_key == ""
        assert cfg.auth_api_key_header == "X-API-Key"
        assert cfg.auth_client_cert == ""
        assert cfg.auth_basic == ""

    def test_rate_limit_per_domain_default(self):
        cfg = PipelineConfig()
        assert cfg.rate_limit_per_domain == 0

    def test_auth_bearer_set(self):
        cfg = PipelineConfig(auth_bearer="mytoken123")
        assert cfg.auth_bearer == "mytoken123"

    def test_auth_api_key_set(self):
        cfg = PipelineConfig(auth_api_key="key123", auth_api_key_header="Authorization")
        assert cfg.auth_api_key == "key123"
        assert cfg.auth_api_key_header == "Authorization"

    def test_auth_basic_set(self):
        cfg = PipelineConfig(auth_basic="admin:password")
        assert cfg.auth_basic == "admin:password"

    def test_safe_mode(self):
        cfg = PipelineConfig(safe_mode=True)
        assert cfg.safe_mode is True

    def test_sample_limits(self):
        cfg = PipelineConfig()
        assert cfg.sample_urls_fuzz == 200
        assert cfg.sample_hosts_ssl == 3
        assert cfg.sample_hosts_origin == 10

    def test_all_sample_fields_positive(self):
        cfg = PipelineConfig()
        for attr in dir(cfg):
            if attr.startswith("sample_"):
                val = getattr(cfg, attr)
                assert isinstance(val, int), f"{attr} should be int"
                assert val >= 0, f"{attr} should be non-negative, got {val}"


class TestValidPhases:
    def test_all_unique(self):
        assert len(VALID_PHASES) == len(set(VALID_PHASES))

    def test_count(self):
        assert len(VALID_PHASES) >= 160

    def test_format(self):
        for p in VALID_PHASES:
            assert isinstance(p, str)
            assert "-" in p


class TestConfigAuth:
    def test_bearer_header_format(self):
        cfg = PipelineConfig(auth_bearer="test123")
        header = f"Bearer {cfg.auth_bearer}"
        assert header == "Bearer test123"

    def test_basic_auth_encoding(self):
        import base64
        cfg = PipelineConfig(auth_basic="user:pass")
        encoded = base64.b64encode(cfg.auth_basic.encode()).decode()
        decoded = base64.b64decode(encoded).decode()
        assert decoded == "user:pass"

    def test_api_key_header_custom(self):
        cfg = PipelineConfig(auth_api_key="secret", auth_api_key_header="X-Custom-Key")
        headers = {cfg.auth_api_key_header: cfg.auth_api_key}
        assert headers["X-Custom-Key"] == "secret"


class TestPipelineConfigValidation:
    def test_valid_config_passes(self):
        cfg = PipelineConfig()
        assert cfg.sqlmap_level == 1

    def test_sqlmap_level_too_high(self):
        with pytest.raises(ConfigError, match="sqlmap_level"):
            PipelineConfig(sqlmap_level=10)

    def test_sqlmap_level_zero(self):
        with pytest.raises(ConfigError, match="sqlmap_level"):
            PipelineConfig(sqlmap_level=0)

    def test_sqlmap_risk_too_high(self):
        with pytest.raises(ConfigError, match="sqlmap_risk"):
            PipelineConfig(sqlmap_risk=5)

    def test_sqlmap_risk_zero(self):
        with pytest.raises(ConfigError, match="sqlmap_risk"):
            PipelineConfig(sqlmap_risk=0)

    def test_negative_delay(self):
        with pytest.raises(ConfigError, match="delay"):
            PipelineConfig(delay=-1.0)

    def test_zero_delay_ok(self):
        cfg = PipelineConfig(delay=0.0)
        assert cfg.delay == 0.0

    def test_positive_delay_ok(self):
        cfg = PipelineConfig(delay=2.5)
        assert cfg.delay == 2.5

    def test_negative_rate_limit(self):
        with pytest.raises(ConfigError, match="rate_limit"):
            PipelineConfig(rate_limit=-1)

    def test_proxy_invalid_scheme(self):
        with pytest.raises(ConfigError, match="proxy"):
            PipelineConfig(proxy="ftp://evil.com")

    def test_proxy_http_ok(self):
        cfg = PipelineConfig(proxy="http://127.0.0.1:8080")
        assert cfg.proxy == "http://127.0.0.1:8080"

    def test_proxy_socks4_ok(self):
        cfg = PipelineConfig(proxy="socks4://127.0.0.1:9050")
        assert cfg.proxy == "socks4://127.0.0.1:9050"

    def test_proxy_socks5_ok(self):
        cfg = PipelineConfig(proxy="socks5://127.0.0.1:9050")
        assert cfg.proxy == "socks5://127.0.0.1:9050"

    def test_vuln_proxy_invalid_scheme(self):
        with pytest.raises(ConfigError, match="vuln_proxy"):
            PipelineConfig(vuln_proxy="ftp://evil.com")

    def test_vuln_proxy_http_ok(self):
        cfg = PipelineConfig(vuln_proxy="http://127.0.0.1:8080")
        assert cfg.vuln_proxy == "http://127.0.0.1:8080"

    def test_vuln_proxy_socks5_ok(self):
        cfg = PipelineConfig(vuln_proxy="socks5://127.0.0.1:9050")
        assert cfg.vuln_proxy == "socks5://127.0.0.1:9050"

    def test_negative_sample_field(self):
        with pytest.raises(ConfigError, match="sample_urls_fuzz"):
            PipelineConfig(sample_urls_fuzz=-5)

    def test_proxy_timeout_multiplier_zero(self):
        with pytest.raises(ConfigError, match="proxy_timeout_multiplier"):
            PipelineConfig(proxy_timeout_multiplier=0)

    def test_proxy_timeout_multiplier_negative(self):
        with pytest.raises(ConfigError, match="proxy_timeout_multiplier"):
            PipelineConfig(proxy_timeout_multiplier=-1.0)

    def test_waf_evasion_throttle_negative(self):
        with pytest.raises(ConfigError, match="waf_evasion_throttle"):
            PipelineConfig(waf_evasion_throttle=-0.5)

    def test_credentials_queue_default(self):
        cfg = PipelineConfig()
        assert cfg.credentials_queue == []
