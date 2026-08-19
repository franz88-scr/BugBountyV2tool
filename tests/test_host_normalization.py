"""Fast isolated tests for host normalization and JWT differential helpers."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnforge.phases.auth import _jwt_forge_accepted, _jwt_forge_candidate
from vulnforge.utils import _extract_host


class TestExtractHost:
    def test_httpx_tagged_line(self):
        assert _extract_host("https://example.com [200] [nginx] [title]") == "example.com"

    def test_plain_url(self):
        assert _extract_host("https://example.com") == "example.com"

    def test_http_url_with_port(self):
        assert _extract_host("http://10.0.0.1:8080") == "10.0.0.1"

    def test_bare_host(self):
        assert _extract_host("example.com") == "example.com"

    def test_bare_host_with_port(self):
        assert _extract_host("example.com:8443") == "example.com"

    def test_uppercase_scheme(self):
        assert _extract_host("HTTPS://EXAMPLE.COM") == "example.com"

    def test_empty_input(self):
        assert _extract_host("") == ""
        assert _extract_host("   ") == ""


class TestJwtForgeDifferential:
    def test_accepted_when_forged_200_baseline_401_garbage_401(self):
        assert _jwt_forge_accepted(200, 401, 401, "welcome", "login required", "login required")

    def test_rejected_when_garbage_also_200(self):
        assert not _jwt_forge_accepted(200, 401, 200, "welcome", "login", "welcome")

    def test_accepted_via_markers_when_garbage_differs(self):
        assert _jwt_forge_accepted(200, 200, 401, "welcome dashboard", "static", "login")

    def test_rejected_when_markers_match_garbage(self):
        assert not _jwt_forge_accepted(200, 200, 200, "welcome", "login", "welcome")

    def test_rejected_when_baseline_none(self):
        assert not _jwt_forge_accepted(200, None, None, "welcome", "", "")

    def test_candidate_when_forged_differs_from_garbage(self):
        assert _jwt_forge_candidate(200, 403, 401, "page", "denied", "denied")

    def test_candidate_false_when_garbage_same_status(self):
        assert not _jwt_forge_candidate(200, 403, 200, "page", "denied", "page")

    def test_candidate_false_when_body_same_as_garbage(self):
        assert not _jwt_forge_candidate(200, 200, 200, "same", "other", "same")

    def test_candidate_false_when_status_not_ok(self):
        assert not _jwt_forge_candidate(302, 401, 401, "x", "y", "y")

    def test_candidate_true_when_baseline_none(self):
        assert _jwt_forge_candidate(200, None, None, "page", "", "")
