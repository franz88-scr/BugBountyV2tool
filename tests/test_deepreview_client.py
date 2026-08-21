"""Fast isolated tests for Gruppe 4 client-side/web-platform pure helpers."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnforge.phases.email_misc import _cache_key_persisted, _workflow_verdict
from vulnforge.phases.webrtc import _stun_binding_response_ok


class TestStunBindingResponse:
    def test_binding_response_detected(self):
        msg = b"\x01\x01\x00\x00" + b"\x21\x12\xa4\x42" + b"\x00" * 12
        assert _stun_binding_response_ok(msg)

    def test_binding_request_not_response(self):
        msg = b"\x00\x01\x00\x00" + b"\x21\x12\xa4\x42" + b"\x00" * 12
        assert not _stun_binding_response_ok(msg)

    def test_short_packet_not_ok(self):
        assert not _stun_binding_response_ok(b"\x01\x01\x00\x00")

    def test_wrong_magic_cookie_not_ok(self):
        msg = b"\x01\x01\x00\x00" + b"\x00" * 4 + b"\x00" * 12
        assert not _stun_binding_response_ok(msg)

    def test_empty_not_ok(self):
        assert not _stun_binding_response_ok(b"")


class TestCacheKeyPersisted:
    def test_same_body_persisted(self):
        assert _cache_key_persisted(b"hello", b"hello")

    def test_different_body_not_persisted(self):
        assert not _cache_key_persisted(b"hello", b"world")

    def test_empty_test_body_not_persisted(self):
        assert not _cache_key_persisted(b"", b"hello")

    def test_empty_clean_body_not_persisted(self):
        assert not _cache_key_persisted(b"hello", b"")


class TestWorkflowVerdict:
    def test_method_2xx_when_get_rejected(self):
        assert _workflow_verdict(405, b"", 200, b"body") == "bypass"

    def test_same_as_get_is_info(self):
        assert _workflow_verdict(200, b"same", 200, b"same") == "info"

    def test_different_body_is_bypass(self):
        assert _workflow_verdict(200, b"baseline", 200, b"changed") == "bypass"

    def test_non_2xx_no_verdict(self):
        assert _workflow_verdict(200, b"x", 404, b"nf") == ""

    def test_2xx_post_on_200_get_is_info(self):
        assert _workflow_verdict(200, b"page", 200, b"page") == "info"
