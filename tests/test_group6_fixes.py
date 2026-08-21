"""Fast isolated tests for CMDINJECT/SSPP/DESERIAL/SSO/takeover-validate fixes."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnforge.phases.injection_misc import (
    _cmdi_output_found,
    _deserial_verdict,
    _sspp_verdict,
)
from vulnforge.phases.recon.scan import (
    _takeover_cname_provider,
    _takeover_signature,
)


class TestCmdiOutputFound:
    def test_id_output_detected(self):
        assert _cmdi_output_found("uid=1000(www-data) gid=1000(www-data) groups=1000")

    def test_uname_output_detected(self):
        assert _cmdi_output_found("Linux target-01 5.15.0-91-generic")

    def test_shadow_line_detected(self):
        assert _cmdi_output_found("www-data:$6$abcdefgh$xyz")

    def test_plain_linux_word_not_flagged(self):
        assert not _cmdi_output_found("Powered by Linux and open source software")

    def test_root_in_footer_not_flagged(self):
        assert not _cmdi_output_found("<footer>root: admin@example.com</footer>")

    def test_empty_body(self):
        assert not _cmdi_output_found("")

    def test_uid_in_docs_not_flagged(self):
        assert not _cmdi_output_found("documentation: the uid is the user id")


class TestSsppVerdict:
    def test_changed_2xx_body_is_candidate(self):
        assert _sspp_verdict(200, "baseline body", 200, "changed body") == "candidate"

    def test_unchanged_2xx_body_not_candidate(self):
        assert _sspp_verdict(200, "same", 200, "same") == ""

    def test_crash_only_when_baseline_ok(self):
        assert _sspp_verdict(200, "ok", 500, "") == "crash"

    def test_crash_with_baseline_5xx_not_flagged(self):
        assert _sspp_verdict(500, "err", 500, "") == ""

    def test_404_not_flagged(self):
        assert _sspp_verdict(200, "ok", 404, "nf") == ""

    def test_302_with_changed_body_is_candidate(self):
        assert _sspp_verdict(302, "a", 302, "b") == "candidate"


class TestDeserialVerdict:
    def test_crash_only_when_baseline_ok(self):
        assert _deserial_verdict(400, "bad request", 500, "") == "crash"

    def test_crash_when_baseline_also_5xx_not_flagged(self):
        assert _deserial_verdict(500, "err", 502, "err") == ""

    def test_new_error_keyword_is_reflected(self):
        assert _deserial_verdict(400, "", 200, "Java exception class") == ""

    def test_framework_signature_is_reflected(self):
        assert _deserial_verdict(400, "", 200, "java.lang.ClassNotFoundException") == "reflected"

    def test_same_keywords_in_baseline_not_flagged(self):
        assert _deserial_verdict(200, "error in baseline page", 200, "error in baseline page") == ""

    def test_plain_2xx_not_flagged(self):
        assert _deserial_verdict(400, "", 200, "hello world") == ""

    def test_2xx_with_common_word_not_flagged(self):
        assert _deserial_verdict(400, "object oriented", 200, "object oriented design") == ""

    def test_404_not_flagged(self):
        assert _deserial_verdict(400, "", 404, "not found") == ""


class TestTakeoverSignature:
    def test_aws_s3_marker(self):
        assert _takeover_signature("The specified bucket does not exist") == "aws-s3"

    def test_github_pages_marker(self):
        assert _takeover_signature("There isn't a GitHub Pages site here.") == "github-pages"

    def test_heroku_marker(self):
        assert _takeover_signature("No such app") == "heroku"

    def test_generic_not_found_not_flagged(self):
        assert _takeover_signature("404 - Page not found") == ""

    def test_plain_page_not_flagged(self):
        assert _takeover_signature("<html><title>Welcome</title></html>") == ""

    def test_empty(self):
        assert _takeover_signature("") == ""

    def test_case_insensitive(self):
        assert _takeover_signature("No Such Bucket") == "aws-s3"


class TestTakeoverCnameProvider:
    def test_s3_cname(self):
        assert _takeover_cname_provider("bucket.s3.amazonaws.com") == "aws-s3"

    def test_github_io_cname(self):
        assert _takeover_cname_provider("user.github.io") == "github-pages"

    def test_azure_cname(self):
        assert _takeover_cname_provider("app.azurewebsites.net") == "azure"

    def test_heroku_cname(self):
        assert _takeover_cname_provider("app.herokuapp.com") == "heroku"

    def test_netlify_cname(self):
        assert _takeover_cname_provider("site.netlify.app") == "netlify"

    def test_unrelated_domain(self):
        assert _takeover_cname_provider("www.example.com") == ""

    def test_empty(self):
        assert _takeover_cname_provider("") == ""
