"""Fast isolated tests for pure helpers extracted during deep-review recon fixes."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnforge.phases.recon.osint import _ddg_employee_name, _ddg_result_url
from vulnforge.phases.recon.params import _arjun_found_urls


class TestArjunFoundUrls:
    def test_dict_with_param_dict(self):
        data = {"https://example.com/x": {"id": ["1"], "page": []}}
        urls = _arjun_found_urls(data)
        assert "https://example.com/x?id=" in urls
        assert "https://example.com/x?page=" in urls

    def test_dict_with_param_list(self):
        data = {"http://example.com/": ["q", "user"]}
        urls = _arjun_found_urls(data)
        assert "http://example.com/?q=" in urls
        assert "http://example.com/?user=" in urls

    def test_url_with_existing_query_uses_amp(self):
        data = {"https://example.com/p?a=1": {"b": []}}
        assert "https://example.com/p?a=1&b=" in _arjun_found_urls(data)

    def test_dict_without_params_keeps_url(self):
        data = {"https://example.com/p": []}
        assert _arjun_found_urls(data) == ["https://example.com/p"]

    def test_list_format(self):
        data = [{"url": "https://example.com/?x=1"}]
        assert _arjun_found_urls(data) == ["https://example.com/?x=1"]

    def test_non_url_keys_ignored(self):
        assert _arjun_found_urls({"meta": {"count": 1}}) == []

    def test_plain_dict_not_in_output(self):
        assert _arjun_found_urls({"x": "y"}) == []


class TestDdgResultUrl:
    def test_uddg_protocol_relative_link(self):
        href = "//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fbackup.sql&rut=abc"
        assert _ddg_result_url(href) == "https://example.com/backup.sql"

    def test_plain_http_link(self):
        assert _ddg_result_url("https://example.com/x") == "https://example.com/x"

    def test_protocol_relative_without_uddg_is_none(self):
        assert _ddg_result_url("//example.com/x") is None

    def test_uddg_with_existing_params(self):
        href = "//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fa%3Fb%3D1"
        assert _ddg_result_url(href) == "https://example.com/a?b=1"


class TestDdgEmployeeName:
    def test_linkedin_title(self):
        anchor = "John Doe - Acme Corp | LinkedIn"
        assert _ddg_employee_name(anchor) == ("john", "doe")

    def test_title_with_company_and_job(self):
        anchor = "Jane Smith - Principal Engineer - Acme | LinkedIn"
        assert _ddg_employee_name(anchor) == ("jane", "smith")

    def test_title_without_company(self):
        anchor = "Bob Ross | LinkedIn"
        assert _ddg_employee_name(anchor) == ("bob", "ross")

    def test_unrelated_title_not_flagged(self):
        assert _ddg_employee_name("View LinkedIn profiles | LinkedIn") is None

    def test_single_word_title(self):
        assert _ddg_employee_name("LinkedIn | LinkedIn") is None

    def test_empty(self):
        assert _ddg_employee_name("") is None
