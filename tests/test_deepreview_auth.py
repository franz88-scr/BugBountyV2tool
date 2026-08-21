"""Fast isolated tests for deep-review auth fixes (group 3)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnforge.phases.account import _reset_token_weak


class TestResetTokenWeak:
    def test_short_numeric_token_is_weak(self):
        assert _reset_token_weak("token=12345")

    def test_long_numeric_token_not_weak(self):
        assert not _reset_token_weak("token=8392018473")

    def test_long_sequential_numeric_token_is_weak(self):
        assert _reset_token_weak("token=12345678")

    def test_short_code_is_weak(self):
        assert _reset_token_weak("code=123456")

    def test_hex_token_not_weak(self):
        assert not _reset_token_weak("key=a1b2c3d4")

    def test_descending_sequence_not_flagged(self):
        assert not _reset_token_weak("token=9876543210")

    def test_repeated_digit_not_flagged(self):
        assert not _reset_token_weak("reset=00000000")
