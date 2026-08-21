"""Fast isolated tests for pure helpers extracted during deep-review fixes."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnforge.phases.advanced_inject import (
    _extract_urls,
    _normalize_race_body,
)


class TestExtractUrls:
    def test_finding_text_with_urls(self):
        lines = [
            "[ssrf-oob-tested] http://example.com/?url=http://internal.host",
            "  [AWS IMDSv1] metadata endpoint reachable: http://169.254.169.254/latest/meta-data/",
        ]
        assert _extract_urls(lines) == [
            "http://example.com/?url=http://internal.host",
            "http://169.254.169.254/latest/meta-data/",
        ]

    def test_finding_text_without_urls(self):
        assert _extract_urls(["[ssrf-oob-tested] no endpoint", "[AWS IMDSv1] blocked"]) == []

    def test_plain_url_lines(self):
        assert _extract_urls(["https://app.example.com/load?dest=http://localhost:8080"]) == [
            "https://app.example.com/load?dest=http://localhost:8080"
        ]

    def test_trailing_punctuation_stripped(self):
        assert _extract_urls(["tested http://example.com/a."]) == ["http://example.com/a"]

    def test_non_http_scheme_ignored(self):
        assert _extract_urls(["ftp://example.com/file", "mailto:x@example.com"]) == []


class TestNormalizeRaceBody:
    def test_json_dynamic_fields_normalized(self):
        b1 = '{"status":"ok","timestamp":"1234567890.123","requestId":"abc-123","coupon":"SAVE5"}'
        b2 = '{"status":"ok","timestamp":"9999999999.999","requestId":"xyz-789","coupon":"SAVE5"}'
        assert _normalize_race_body(b1) == _normalize_race_body(b2)
        assert "1234567890.123" not in _normalize_race_body(b1)
        assert "SAVE5" in _normalize_race_body(b1)

    def test_form_dynamic_fields_normalized(self):
        b1 = "race_test=1&timestamp=1700000000.5&status=accepted"
        b2 = "race_test=1&timestamp=1800000000.5&status=accepted"
        assert _normalize_race_body(b1) == _normalize_race_body(b2)

    def test_real_content_difference_survives(self):
        b3 = "race_test=1&timestamp=1700000000.5&status=accepted"
        b4 = "race_test=1&timestamp=1800000000.5&status=rejected"
        assert _normalize_race_body(b3) != _normalize_race_body(b4)

    def test_no_dynamic_fields_unchanged(self):
        assert _normalize_race_body("plain response") == "plain response"