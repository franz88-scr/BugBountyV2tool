"""Fast isolated tests for deep-review injection helpers (G2-1, G2-5, G2-15)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnforge.phases.encoding import _ssi_processing_found
from vulnforge.phases.injection_misc import _cmdi_canary_confirmed, _sspp_verdict


class TestCmdiCanaryConfirmed:
    def test_executed_canary_confirmed(self):
        assert _cmdi_canary_confirmed("uid=0 output CANARY", "baseline", "CANARY", ";echo CANARY#")

    def test_canary_in_baseline_not_confirmed(self):
        assert not _cmdi_canary_confirmed("CANARY page", "CANARY baseline", "CANARY", ";echo CANARY#")

    def test_raw_payload_reflection_excluded(self):
        assert not _cmdi_canary_confirmed(
            "echo: ;echo CANARY# reflected", "baseline", "CANARY", ";echo CANARY#"
        )

    def test_no_canary_no_finding(self):
        assert not _cmdi_canary_confirmed("nothing here", "baseline", "CANARY", ";echo CANARY#")


class TestSsppVerdictPayloadReflection:
    def test_payload_reflection_not_candidate(self):
        payload = '{"__proto__": {"admin": true}}'
        assert _sspp_verdict(200, "baseline", 200, payload, payload) == ""

    def test_body_change_without_payload_is_candidate(self):
        payload = '{"__proto__": {"admin": true}}'
        assert _sspp_verdict(200, "baseline", 200, "changed response", payload) == "candidate"

    def test_crash_still_detected_with_payload(self):
        payload = '{"__proto__": {"admin": true}}'
        assert _sspp_verdict(200, "baseline", 500, "", payload) == "crash"


class TestSsiProcessingFound:
    _INDICATORS = ["uid=", "root:", "gid=", "DOCUMENT_ROOT", "<!--#exec"]

    def test_expansion_new_indicator_is_processing(self):
        assert _ssi_processing_found(
            "uid=1000(www-data)", "plain page", '<!--#exec cmd="id"-->', self._INDICATORS
        )

    def test_indicator_already_in_baseline_not_counted(self):
        assert not _ssi_processing_found(
            "footer root: admin", "footer root: admin", '<!--#exec cmd="id"-->', self._INDICATORS
        )

    def test_payload_reflection_not_processing(self):
        assert not _ssi_processing_found(
            '<!--#echo var="DOCUMENT_ROOT"-->', "plain page", '<!--#echo var="DOCUMENT_ROOT"-->',
            self._INDICATORS,
        )

    def test_plain_body_not_processing(self):
        assert not _ssi_processing_found("hello world", "plain page", '<!--#exec cmd="id"-->', self._INDICATORS)
