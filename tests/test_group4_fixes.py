"""Fast isolated tests for Gruppe 4 client-side/web-platform fixes."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnforge.phases.client_side import (
    _OPENREDIR_PAYLOADS,
    _cors_misconfig,
    _csp_directives,
    _csp_source_list,
    _frame_ancestors_effective,
    _open_redirect_host,
    _redirect_target_hosts,
    _xfo_effective,
)
from vulnforge.phases.cookie_security import _registrable_domain
from vulnforge.phases.modern_web import _SW_SECRET_ASSIGN_RE


class TestCorsMisconfig:
    def test_wildcard_without_credentials_not_flagged(self):
        assert not _cors_misconfig("*", "", "https://evil.com")

    def test_wildcard_with_credentials_flagged(self):
        assert _cors_misconfig("*", "true", "https://evil.com")

    def test_exact_origin_flagged(self):
        assert _cors_misconfig("https://evil.com", "", "https://evil.com")

    def test_substring_origin_not_flagged(self):
        assert not _cors_misconfig("https://evil.com:8080", "", "https://evil.com")

    def test_different_origin_not_flagged(self):
        assert not _cors_misconfig("https://good.com", "", "https://evil.com")

    def test_empty_acao_not_flagged(self):
        assert not _cors_misconfig("", "", "https://evil.com")

    def test_multi_value_acao_exact_match(self):
        assert _cors_misconfig("https://a.com, https://evil.com", "", "https://evil.com")


class TestCspDirectives:
    def test_parse_simple_directives(self):
        d = _csp_directives("default-src 'self'; script-src 'self' https://cdn.com; img-src *")
        assert d["default-src"] == "'self'"
        assert d["script-src"] == "'self' https://cdn.com"
        assert d["img-src"] == "*"

    def test_source_list_from_script_src(self):
        d = _csp_directives("script-src 'nonce-abc' 'unsafe-inline' https://youtube.com")
        assert _csp_source_list(d, "script-src") == ["'nonce-abc'", "'unsafe-inline'", "https://youtube.com"]

    def test_source_list_falls_back_to_default_src(self):
        d = _csp_directives("default-src 'self' https://cdn.com")
        assert _csp_source_list(d, "script-src") == ["'self'", "https://cdn.com"]

    def test_source_list_empty_without_default_src(self):
        d = _csp_directives("style-src 'self'")
        assert _csp_source_list(d, "script-src") == []

    def test_case_insensitive_directive_names(self):
        d = _csp_directives("SCRIPT-SRC 'self'")
        assert d["script-src"] == "'self'"


class TestClickjackProtection:
    def test_xfo_deny(self):
        assert _xfo_effective("DENY")

    def test_xfo_sameorigin(self):
        assert _xfo_effective("SAMEORIGIN")

    def test_xfo_allow_from_not_protection(self):
        assert not _xfo_effective("ALLOW-FROM https://evil.com")

    def test_xfo_empty_not_protection(self):
        assert not _xfo_effective("")

    def test_frame_ancestors_none(self):
        assert _frame_ancestors_effective("frame-ancestors 'none'", "https://example.com")

    def test_frame_ancestors_self(self):
        assert _frame_ancestors_effective("frame-ancestors 'self'", "https://example.com")

    def test_frame_ancestors_wildcard_not_protection(self):
        assert not _frame_ancestors_effective("frame-ancestors *", "https://example.com")

    def test_frame_ancestors_third_party_not_protection(self):
        assert not _frame_ancestors_effective("frame-ancestors https://evil.com", "https://example.com")

    def test_frame_ancestors_same_origin(self):
        assert _frame_ancestors_effective("frame-ancestors https://example.com", "https://example.com")

    def test_frame_ancestors_missing(self):
        assert not _frame_ancestors_effective("default-src 'self'", "https://example.com")

    def test_http_in_connect_src_ignored(self):
        assert not _frame_ancestors_effective("connect-src http://evil.com", "https://example.com")


class TestRegistrableDomain:
    def test_single_part_tld(self):
        assert _registrable_domain("example.com") == "example.com"

    def test_subdomain_single_part_tld(self):
        assert _registrable_domain("www.example.com") == "example.com"

    def test_uk_co_uk(self):
        assert _registrable_domain("example.co.uk") == "example.co.uk"

    def test_uk_subdomain(self):
        assert _registrable_domain("www.example.co.uk") == "example.co.uk"

    def test_au_com_au(self):
        assert _registrable_domain("shop.example.com.au") == "example.com.au"

    def test_deep_subdomain(self):
        assert _registrable_domain("a.b.example.co.uk") == "example.co.uk"

    def test_empty(self):
        assert _registrable_domain("") == ""

    def test_uppercase(self):
        assert _registrable_domain("WWW.EXAMPLE.CO.UK") == "example.co.uk"


class TestOpenRedirectHost:
    def test_absolute_url(self):
        assert _open_redirect_host("https://evil.com/path") == "evil.com"

    def test_scheme_relative(self):
        assert _open_redirect_host("//evil.com/path") == "evil.com"

    def test_backslash_relative(self):
        assert _open_redirect_host("\\\\evil.com\\path") == "evil.com"

    def test_relative_error_redirect_not_matched(self):
        assert _open_redirect_host("/error?url=https://evil.com") is None

    def test_empty_location(self):
        assert _open_redirect_host("") is None

    def test_evil_domain_substring_not_matched(self):
        assert _open_redirect_host("https://evil.com.evil2.com") == "evil.com.evil2.com"
        assert _open_redirect_host("https://notevil.com") == "notevil.com"

    def test_payload_agreement(self):
        for p in _OPENREDIR_PAYLOADS:
            if p == "https://evil.com.evil2.com":
                continue
            assert "evil.com" in _redirect_target_hosts(p)

    def test_decoded_encoded_payload_targets(self):
        assert "evil.com" in _redirect_target_hosts("https:%2f%2fevil.com")
        assert "evil.com" in _redirect_target_hosts("%2f%2fevil.com")


class TestSwSecretAssignment:
    def test_token_assignment_matches(self):
        assert _SW_SECRET_ASSIGN_RE.search('const token = "abc123secret"')

    def test_api_key_object_matches(self):
        assert _SW_SECRET_ASSIGN_RE.search('apiKey: "xyz789"')

    def test_bare_token_word_not_matched(self):
        assert not _SW_SECRET_ASSIGN_RE.search("if (token) { return token; }")

    def test_auth_import_not_matched(self):
        assert not _SW_SECRET_ASSIGN_RE.search("import { auth } from './auth'")
