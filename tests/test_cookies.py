"""Tests for cookie handling: validation, sanitization, detection, headers, and Set-Cookie parsing."""
import os
import sys
from http.client import HTTPMessage

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from reconchain.utils import (
    _auto_detect_cookies,
    _extra_headers_dict,
    _extra_http_args,
    _sanitize_header_value,
    _validate_cookie,
    parse_set_cookie_headers,
)


class TestSanitizeHeaderValue:
    def test_strips_crlf(self):
        assert _sanitize_header_value("foo\r\nbar") == "foo  bar"

    def test_strips_null_bytes(self):
        assert _sanitize_header_value("foo\x00bar") == "foo bar"

    def test_strips_tab(self):
        assert _sanitize_header_value("foo\tbar") == "foo bar"

    def test_strips_leading_trailing_whitespace(self):
        assert _sanitize_header_value("  session=abc  ") == "session=abc"

    def test_empty_string(self):
        assert _sanitize_header_value("") == ""

    def test_clean_string_unchanged(self):
        assert _sanitize_header_value("session=abc123") == "session=abc123"


class TestValidateCookie:
    def test_valid_single_cookie(self):
        assert _validate_cookie("session=abc123") == "session=abc123"

    def test_valid_multiple_cookies(self):
        result = _validate_cookie("session=abc; token=xyz")
        assert "session=abc" in result
        assert "token=xyz" in result

    def test_strips_dangerous_chars(self):
        result = _validate_cookie("session=abc\r\nX-Injected: yes")
        assert "\r" not in result
        assert "\n" not in result

    def test_empty_raises(self):
        import pytest
        with pytest.raises(ValueError, match="empty"):
            _validate_cookie("")

    def test_whitespace_only_raises(self):
        import pytest
        with pytest.raises(ValueError, match="empty"):
            _validate_cookie("   ")

    def test_strips_and_validates(self):
        result = _validate_cookie("  session=abc  ")
        assert result == "session=abc"


class TestAutoDetectCookies:
    def test_env_var_priority(self, monkeypatch):
        monkeypatch.setenv("COOKIE", "from_env=1")
        result = _auto_detect_cookies()
        assert result == "from_env=1"

    def test_empty_when_no_source(self, monkeypatch):
        monkeypatch.delenv("COOKIE", raising=False)
        result = _auto_detect_cookies()
        assert result == ""

    def test_cookies_txt_in_outdir(self, monkeypatch, tmp_path):
        monkeypatch.delenv("COOKIE", raising=False)
        cookie_file = tmp_path / "cookies.txt"
        cookie_file.write_text("from_file=1\n")
        cookie_file.chmod(0o600)
        result = _auto_detect_cookies(tmp_path)
        assert result == "from_file=1"

    def test_cookies_txt_permission_fix(self, monkeypatch, tmp_path):
        monkeypatch.delenv("COOKIE", raising=False)
        cookie_file = tmp_path / "cookies.txt"
        cookie_file.write_text("session=fixme\n")
        cookie_file.chmod(0o644)
        _auto_detect_cookies(tmp_path, fix_permissions=True)
        mode = cookie_file.stat().st_mode & 0o777
        assert mode == 0o600

    def test_cookies_txt_no_permission_fix(self, monkeypatch, tmp_path):
        monkeypatch.delenv("COOKIE", raising=False)
        cookie_file = tmp_path / "cookies.txt"
        cookie_file.write_text("session=nofix\n")
        cookie_file.chmod(0o644)
        _auto_detect_cookies(tmp_path, fix_permissions=False)
        mode = cookie_file.stat().st_mode & 0o777
        assert mode == 0o644


class TestExtraHeadersDict:
    def test_includes_cookie(self, monkeypatch):
        monkeypatch.setenv("COOKIE", "session=abc")
        monkeypatch.delenv("EXTRA_HEADERS", raising=False)
        headers = _extra_headers_dict()
        assert headers["Cookie"] == "session=abc"

    def test_no_cookie_when_empty(self, monkeypatch):
        monkeypatch.delenv("COOKIE", raising=False)
        monkeypatch.delenv("EXTRA_HEADERS", raising=False)
        headers = _extra_headers_dict()
        assert "Cookie" not in headers

    def test_extra_headers_combined(self, monkeypatch):
        monkeypatch.setenv("COOKIE", "session=abc")
        monkeypatch.setenv("EXTRA_HEADERS", "Authorization: Bearer tok\nX-Custom: val")
        headers = _extra_headers_dict()
        assert headers["Cookie"] == "session=abc"
        assert headers["Authorization"] == "Bearer tok"
        assert headers["X-Custom"] == "val"


class TestExtraHttpArgs:
    def test_includes_cookie_header(self, monkeypatch):
        monkeypatch.setenv("COOKIE", "session=abc")
        monkeypatch.delenv("EXTRA_HEADERS", raising=False)
        args = _extra_http_args()
        assert "-H" in args
        assert "Cookie: session=abc" in args

    def test_no_cookie_when_empty(self, monkeypatch):
        monkeypatch.delenv("COOKIE", raising=False)
        monkeypatch.delenv("EXTRA_HEADERS", raising=False)
        args = _extra_http_args()
        assert args == []

    def test_extra_headers_appended(self, monkeypatch):
        monkeypatch.setenv("COOKIE", "session=abc")
        monkeypatch.setenv("EXTRA_HEADERS", "X-Foo: bar")
        args = _extra_http_args()
        assert "Cookie: session=abc" in args
        assert "X-Foo: bar" in args


class TestParseSetCookieHeaders:
    def test_http_message_object(self):
        headers = HTTPMessage()
        headers["Set-Cookie"] = "session=abc; HttpOnly"
        headers["Set-Cookie"] = "token=xyz; Secure"
        result = parse_set_cookie_headers(headers)
        assert len(result) == 2
        assert any("session=abc" in c for c in result)
        assert any("token=xyz" in c for c in result)

    def test_string_fallback(self):
        headers = "Set-Cookie: session=abc; HttpOnly\nSet-Cookie: token=xyz; Secure"
        result = parse_set_cookie_headers(headers)
        assert len(result) == 2

    def test_empty_headers(self):
        headers = HTTPMessage()
        result = parse_set_cookie_headers(headers)
        assert result == []

    def test_no_set_cookie(self):
        headers = HTTPMessage()
        headers["Content-Type"] = "text/html"
        result = parse_set_cookie_headers(headers)
        assert result == []
