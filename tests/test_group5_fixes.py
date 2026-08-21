"""Fast isolated tests for Gruppe 5 infra/cloud/CMS/secrets fixes."""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnforge.phases.cloud import _lb_origin_confirmed, _origin_candidate_ips
from vulnforge.phases.cms import (
    _is_env_file_content,
    _is_laravel_fingerprint,
    _is_laravel_log_content,
    _nodejs_ssti_triggered,
)
from vulnforge.phases.origin_cloud import (
    _bucket_entry_base,
    _is_cdn_org,
    _s3_bucket_verdict,
    _spf_ip_candidates,
)
from vulnforge.phases.secrets_git import (
    _EXTRA_SECRET_PATTERNS,
    _git_body_indicative,
    _git_parse_shas,
)
from vulnforge.phases.web_infra import _db_banner_sig, _hpp_test_qs


class TestBucketEntryBase:
    def test_aws_tagged_line(self):
        assert _bucket_entry_base("[AWS] http://base.s3.amazonaws.com (HTTP 200)") == "base"

    def test_aws_region_tagged_line(self):
        assert (
            _bucket_entry_base("[AWS-AP] http://base.s3-ap-southeast-1.amazonaws.com (HTTP 403)")
            == "base"
        )

    def test_aws_tagged_without_status(self):
        assert _bucket_entry_base("[AWS] http://base.s3.amazonaws.com") == "base"

    def test_gcp_tagged_line(self):
        assert (
            _bucket_entry_base("[GCP] http://mybucket.storage.googleapis.com (HTTP 200)")
            == "mybucket.storage.googleapis.com"
        )

    def test_plain_url(self):
        assert _bucket_entry_base("https://bucket.s3.amazonaws.com/") == "bucket"


class TestS3BucketVerdict:
    def test_open_listing_with_own_name(self):
        body = "<ListBucketResult><Name>base</Name><Contents><Key>x</Key></Contents></ListBucketResult>"
        assert _s3_bucket_verdict(body, "base") == "open"

    def test_listing_with_foreign_name_not_open(self):
        body = "<ListBucketResult><Name>other</Name></ListBucketResult>"
        assert _s3_bucket_verdict(body, "base") == ""

    def test_access_denied_error(self):
        body = "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>"
        assert _s3_bucket_verdict(body, "base") == "restricted"

    def test_generic_html_not_flagged(self):
        assert _s3_bucket_verdict("<html><body>Welcome</body></html>", "base") == ""


class TestSpfIpCandidates:
    def test_ip4_and_ip6(self):
        assert _spf_ip_candidates("v=spf1 ip4:1.2.3.4 ip6:2001:db8::/32 -all") == [
            "1.2.3.4",
            "2001:db8::/32",
        ]

    def test_ip4_with_cidr(self):
        assert _spf_ip_candidates("v=spf1 ip4:203.0.113.0/24 ~all") == ["203.0.113.0/24"]

    def test_no_mechanisms(self):
        assert _spf_ip_candidates("v=spf1 ~all") == []

    def test_empty(self):
        assert _spf_ip_candidates("") == []


class TestIsCdnOrg:
    def test_cloudflare(self):
        assert _is_cdn_org("AS13335 Cloudflare, Inc.")

    def test_akamai(self):
        assert _is_cdn_org("AS20940 Akamai International B.V.")

    def test_fastly(self):
        assert _is_cdn_org("AS54113 Fastly, Inc.")

    def test_sucuri(self):
        assert _is_cdn_org("AS30148 Sucuri")

    def test_imperva(self):
        assert _is_cdn_org("AS19994 Imperva")

    def test_amazon_cloudfront(self):
        assert _is_cdn_org("AS16509 Amazon.com, Inc.")

    def test_non_cdn_org(self):
        assert not _is_cdn_org("AS3320 Deutsche Telekom AG")
        assert not _is_cdn_org("AS15169 Google LLC")


class TestOriginCandidateIps:
    def test_parses_candidate_lines_only(self):
        lines = [
            "favicon_hash=1234 (url=https://example.com/favicon.ico)",
            "crt.sh: 12 subdomains, 3 unique IPs",
            "  origin_candidate=1.2.3.4",
            "  origin_candidate=5.6.7.8 (from SPF ip-mechanism)",
            "  non_cloudflare_ip=9.9.9.9  org=Example Corp",
        ]
        assert _origin_candidate_ips(lines) == ["1.2.3.4", "5.6.7.8", "9.9.9.9"]

    def test_empty(self):
        assert _origin_candidate_ips([]) == []

    def test_no_candidate_lines(self):
        assert _origin_candidate_ips(["favicon_hash=1", "mx_record=mail.example.com"]) == []


class TestLbOriginConfirmed:
    def test_matching_titles_confirmed(self):
        main = "<html><title>Example Home</title></html>"
        origin = "<title>Example Home</title>"
        assert _lb_origin_confirmed(main, origin)

    def test_different_titles_not_confirmed(self):
        assert not _lb_origin_confirmed("<title>A</title>", "<title>B</title>")

    def test_missing_main_title_not_confirmed(self):
        assert not _lb_origin_confirmed("<html>no title</html>", "<title>B</title>")


class TestGitBodyIndicative:
    def test_git_config_core(self):
        assert _git_body_indicative("[core]\n\trepositoryformatversion = 0")

    def test_git_config_repo_version_only(self):
        assert _git_body_indicative("repositoryformatversion = 0")

    def test_git_head_ref(self):
        assert _git_body_indicative("ref: refs/heads/master")

    def test_plain_html_not_flagged(self):
        assert not _git_body_indicative("<html><body>Not found</body></html>")

    def test_empty(self):
        assert not _git_body_indicative("")


class TestGitParseShas:
    SHA = "5f1d2c3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e"

    def test_single_sha(self):
        assert _git_parse_shas(self.SHA + "\n") == [self.SHA]

    def test_packed_refs(self):
        text = (
            "# pack-refs with: peeled fully-peeled sorted\n"
            f"{self.SHA} refs/heads/main\n"
            "b1d2c3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0 refs/tags/v1.0\n"
        )
        shas = _git_parse_shas(text)
        assert len(shas) == 2
        assert self.SHA in shas

    def test_info_refs(self):
        assert self.SHA in _git_parse_shas(f"{self.SHA}\trefs/heads/dev\n")

    def test_no_shas(self):
        assert _git_parse_shas("no hex here") == []


def _pattern_for(name):
    for n, pat in _EXTRA_SECRET_PATTERNS:
        if n == name:
            return pat
    raise KeyError(name)


def _match_pattern(name, text):
    return re.search(_pattern_for(name), text) is not None


class TestExtraSecretPatterns:
    def test_openai_key(self):
        assert _match_pattern("openai-key", 'const key = "sk-abcdefghijklmnopqrstuvwxyz1234567890";')

    def test_openai_short_value_not_matched(self):
        assert not _match_pattern("openai-key", 'token = "sk-abc"')

    def test_telegram_bot(self):
        assert _match_pattern("telegram-bot", "token=123456789:AAGdYz9abcdefghijklmnopqrstuvwxyz-01_Ab")

    def test_twilio_sid(self):
        assert _match_pattern("twilio-sid", "sid=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")

    def test_private_key(self):
        assert _match_pattern("private-key", "-----BEGIN PRIVATE KEY-----")

    def test_private_key_rsa(self):
        assert _match_pattern("private-key", "-----BEGIN RSA PRIVATE KEY-----")

    def test_discord_bot(self):
        assert _match_pattern(
            "discord-bot",
            'client.token = "Mjg4NDY3MzI4OTI1MzI4OTI1.XyZ.AbCdEfGhIjKlMnOpQrStUvWxYz12"',
        )


class TestHppTestQs:
    def setup_method(self):
        self.qs = {"page": ["1"], "id": ["42"], "search": ["hello"]}

    def test_first_keeps_other_params(self):
        out = _hpp_test_qs(self.qs, "search", "hello", "first")
        assert out["search"] == ["hello", "hpp_test_first"]
        assert out["page"] == ["1"]
        assert out["id"] == ["42"]

    def test_last(self):
        out = _hpp_test_qs(self.qs, "search", "hello", "last")
        assert out["search"] == ["hpp_test_last", "hello"]
        assert out["id"] == ["42"]

    def test_any(self):
        out = _hpp_test_qs(self.qs, "search", "hello", "any")
        assert out["search"] == ["hello", "hpp_test_any"]
        assert out["page"] == ["1"]

    def test_concat(self):
        out = _hpp_test_qs(self.qs, "search", "hello", "concat")
        assert out["search"] == ["hello"]
        assert out["search[]"] == ["hpp_test_concat"]
        assert out["id"] == ["42"]

    def test_original_unchanged(self):
        _hpp_test_qs(self.qs, "search", "hello", "first")
        assert self.qs["search"] == ["hello"]


class TestNodejsSsti:
    def test_evaluated_detected(self):
        assert _nodejs_ssti_triggered("Result: 49", "Result: nothing")

    def test_49_in_control_not_flagged(self):
        assert not _nodejs_ssti_triggered("price 49", "price 49")

    def test_no_49_not_flagged(self):
        assert not _nodejs_ssti_triggered("Result: <%= 7*7 %>", "Result: plain")


class TestLaravelEnvContent:
    def test_env_key_value(self):
        assert _is_env_file_content("APP_KEY=base64:abc\nDB_PASSWORD=secret")

    def test_plain_page_not_env(self):
        assert not _is_env_file_content("<html>APP_KEY</html>")

    def test_lowercase_key_not_env(self):
        assert not _is_env_file_content("app_key=value")

    def test_empty(self):
        assert not _is_env_file_content("")


class TestLaravelLogContent:
    def test_error_line(self):
        assert _is_laravel_log_content("[2024-01-01 12:00:00] production.ERROR: boom")

    def test_info_line(self):
        assert _is_laravel_log_content("[2024-01-01T12:00:00] local.INFO: ok")

    def test_missing_timestamp(self):
        assert not _is_laravel_log_content("production.ERROR: boom")

    def test_generic_log_not_matched(self):
        assert not _is_laravel_log_content("ERROR something failed at line 10")


class TestLaravelFingerprint:
    def test_laravel_session_cookie(self):
        assert _is_laravel_fingerprint({"Set-Cookie": "laravel_session=abc; path=/"}, "")

    def test_xsrf_cookie(self):
        assert _is_laravel_fingerprint({"Set-Cookie": "XSRF-TOKEN=def; path=/"}, "")

    def test_csrf_meta(self):
        assert _is_laravel_fingerprint({}, '<meta name="csrf-token" content="abc">')

    def test_plain_response_not_laravel(self):
        assert not _is_laravel_fingerprint({"Server": "nginx"}, "<html>Hello</html>")


class TestDbBannerSig:
    def test_redis_banner(self):
        assert _db_banner_sig(6379, b"+OK\r\n")

    def test_redis_err(self):
        assert _db_banner_sig(6379, b"-ERR unknown command")

    def test_mongodb_greeting(self):
        assert _db_banner_sig(27017, b"\x3c\x00\x00\x00\x01\x00\x00\x00")

    def test_mysql_handshake(self):
        assert _db_banner_sig(3306, b"\x0a5.7.37-log")

    def test_unknown_port(self):
        assert not _db_banner_sig(4444, b"hello")

    def test_http_banner_on_redis_port(self):
        assert not _db_banner_sig(6379, b"HTTP/1.1 200 OK")
