"""Tests for the REST API module."""
import json
from http.client import HTTPConnection
from pathlib import Path
from threading import Thread

import pytest

from reconchain.api import start_api_server, stop_api_server


@pytest.fixture
def api_with_data(tmp_path):
    """Create API server with sample data."""
    (tmp_path / "xss_findings.txt").write_text("XSS at https://example.com/search\n")
    (tmp_path / "sqlmap_findings.txt").write_text("SQLi in login\n")
    (tmp_path / "hosts.txt").write_text("example.com\napi.example.com\n")
    (tmp_path / "summary.json").write_text(json.dumps({"domain": "example.com", "counts": {"xss": 1}}))
    port = start_api_server(tmp_path, port=0)
    yield tmp_path, port
    stop_api_server()


class TestHealthEndpoint:
    def test_health(self, api_with_data):
        _, port = api_with_data
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/api/v1/health")
        resp = conn.getresponse()
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["status"] == "ok"
        assert "version" in data
        conn.close()

    def test_health_cors(self, api_with_data):
        _, port = api_with_data
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("OPTIONS", "/api/v1/health")
        resp = conn.getresponse()
        assert resp.status == 204
        assert resp.getheader("Access-Control-Allow-Origin") == "*"
        conn.close()


class TestSummaryEndpoint:
    def test_summary(self, api_with_data):
        _, port = api_with_data
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/api/v1/summary")
        resp = conn.getresponse()
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "domain" in data
        conn.close()


class TestFindingsEndpoint:
    def test_findings_all(self, api_with_data):
        _, port = api_with_data
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/api/v1/findings")
        resp = conn.getresponse()
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "findings" in data
        assert "total" in data
        conn.close()

    def test_findings_by_severity(self, api_with_data):
        _, port = api_with_data
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/api/v1/findings?severity=high")
        resp = conn.getresponse()
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "findings" in data
        conn.close()

    def test_findings_by_phase(self, api_with_data):
        _, port = api_with_data
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/api/v1/findings?phase=11-INJECT")
        resp = conn.getresponse()
        assert resp.status == 200
        conn.close()

    def test_findings_by_type(self, api_with_data):
        _, port = api_with_data
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/api/v1/findings?vuln_type=xss")
        resp = conn.getresponse()
        assert resp.status == 200
        conn.close()

    def test_findings_by_severity_endpoint(self, api_with_data):
        _, port = api_with_data
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/api/v1/findings/by-severity")
        resp = conn.getresponse()
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "high" in data
        conn.close()

    def test_findings_by_phase_endpoint(self, api_with_data):
        _, port = api_with_data
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/api/v1/findings/by-phase")
        resp = conn.getresponse()
        assert resp.status == 200
        data = json.loads(resp.read())
        assert isinstance(data, dict)
        conn.close()

    def test_findings_by_type_endpoint(self, api_with_data):
        _, port = api_with_data
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/api/v1/findings/by-type")
        resp = conn.getresponse()
        assert resp.status == 200
        conn.close()


class TestArtifactsEndpoint:
    def test_artifacts(self, api_with_data):
        _, port = api_with_data
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/api/v1/artifacts")
        resp = conn.getresponse()
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "artifacts" in data
        assert "total" in data
        conn.close()


class TestCoverageEndpoint:
    def test_coverage(self, api_with_data):
        _, port = api_with_data
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/api/v1/coverage")
        resp = conn.getresponse()
        assert resp.status == 200
        data = json.loads(resp.read())
        assert "coverage_pct" in data
        conn.close()


class TestNotFound:
    def test_unknown_endpoint(self, api_with_data):
        _, port = api_with_data
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/api/v1/nonexistent")
        resp = conn.getresponse()
        assert resp.status == 404
        data = json.loads(resp.read())
        assert "error" in data
        conn.close()


class TestServerLifecycle:
    def test_start_stop(self, tmp_path):
        port = start_api_server(tmp_path, port=0)
        assert port > 0
        stop_api_server()
