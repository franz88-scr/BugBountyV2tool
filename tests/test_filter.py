"""Tests for vulnforge.filter — false-positive post-processing filter."""

from vulnforge.filter import _is_false_positive, filter_outputs


class TestIsFalsePositive:
    def test_blank_line_kept(self):
        assert _is_false_positive("", "anything.txt") is False

    def test_tor_error(self):
        assert _is_false_positive("[x] Max retries exceeded", "results.txt") is True
        assert _is_false_positive("Connection refused on host", "results.txt") is True

    def test_noise_prefixes(self):
        assert _is_false_positive("[error] boom", "results.txt") is True
        assert _is_false_positive("[apikeyleak] 0 URLs scanned", "apikey.txt") is True

    def test_obsolete_count_line(self):
        assert _is_false_positive("target_urls=5", "idor.txt") is True
        assert _is_false_positive("target_hosts=3", "results.txt") is True

    def test_domxss_vue_symbol(self):
        assert _is_false_positive('Symbol("evaluating") at line 5', "domxss_findings.txt") is True

    def test_file_specific(self):
        assert _is_false_positive("[error] failed", "csp_analysis.txt") is True
        assert _is_false_positive("no API key leaks found", "api_key_leaks.txt") is True
        assert _is_false_positive("scanned 0 JS files", "depcheck.txt") is True
        assert _is_false_positive("No advanced CORS found", "cors_advanced.txt") is True
        assert _is_false_positive("0 URLs tested", "csrf_findings.txt") is True
        assert _is_false_positive("No SSRF detected", "ssrf_full.txt") is True
        assert _is_false_positive("No SSTI", "ssti.txt") is True
        assert _is_false_positive("No XXE", "xxe.txt") is True
        assert _is_false_positive("No LFI", "lfi.txt") is True
        assert _is_false_positive("No stored XSS", "stored_xss.txt") is True
        assert _is_false_positive("[result] No API spec", "api_specs.txt") is True
        assert _is_false_positive("All targets have clickjacking protection", "clickjacking.txt") is True

    def test_mobile_api_tunnel(self):
        assert _is_false_positive("[firebase-error] x → Tunnel failed", "mobile_api.txt") is True
        assert _is_false_positive("[firebase-error] x → 404 on endpoint", "mobile_api.txt") is True
        assert _is_false_positive("[firebase-error] x → /real/path 200", "mobile_api.txt") is False

    def test_oauth_deep_403_without_path(self):
        assert _is_false_positive("got [403]", "oauth_deep.txt") is True
        assert _is_false_positive("got [403] /oauth/token", "oauth_deep.txt") is False

    def test_real_finding_kept(self):
        line = "https://example.com/login?q=1 param=q reflected"
        assert _is_false_positive(line, "xss_findings.txt") is False


class TestFilterOutputs:
    def test_no_files(self, tmp_path, capsys):
        assert filter_outputs(tmp_path) == 0

    def test_removes_noise_keeps_signal(self, tmp_path):
        p = tmp_path / "idor.txt"
        p.write_text("target_urls=5\nhttps://example.com/real 200 OK\n")
        removed = filter_outputs(tmp_path)
        assert removed == 1
        assert p.read_text() == "https://example.com/real 200 OK\n"

    def test_empties_file_when_nothing_kept(self, tmp_path):
        p = tmp_path / "csp_analysis.txt"
        p.write_text("[error] parse failed\n")
        filter_outputs(tmp_path)
        assert p.read_text() == ""

    def test_unrelated_file_untouched(self, tmp_path):
        p = tmp_path / "other.txt"
        p.write_text("clean line\n")
        filter_outputs(tmp_path)
        assert p.read_text() == "clean line\n"

    def test_counts_across_files(self, tmp_path):
        a = tmp_path / "a.txt"
        b = tmp_path / "b.txt"
        a.write_text("Connection refused\nkeep-a\n")
        b.write_text("[error] nope\nkeep-b\n")
        assert filter_outputs(tmp_path) == 2
