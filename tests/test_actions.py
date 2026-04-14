"""
Tests for sandbox_pilot.actions — parse_action() and execute_action().

Coverage
--------
TestParseAction  — validates parse_action() normalisation and injection checks.
TestExecuteAction — validates execute_action() monitor dispatch and return values.
"""

from unittest.mock import MagicMock

import pytest

from sandbox_pilot.actions import MAX_TYPE_LENGTH, execute_action, parse_action


# ---------------------------------------------------------------------------
# TestParseAction
# ---------------------------------------------------------------------------

class TestParseAction:
    """Unit tests for parse_action()."""

    # ------------------------------------------------------------------ #
    # Happy-path: each valid action round-trips correctly                  #
    # ------------------------------------------------------------------ #

    def test_click_parsed(self):
        """CLICK with x, y coordinates is parsed correctly."""
        result = parse_action({"action": "CLICK", "x": 100, "y": 200})
        assert result["action"] == "CLICK"
        assert result["x"] == 100
        assert result["y"] == 200

    def test_type_parsed(self):
        """TYPE with text is parsed correctly."""
        result = parse_action({"action": "TYPE", "text": "hello"})
        assert result["action"] == "TYPE"
        assert result["text"] == "hello"

    def test_key_parsed(self):
        """KEY with key name is parsed correctly."""
        result = parse_action({"action": "KEY", "key": "enter"})
        assert result["action"] == "KEY"
        assert result["key"] == "enter"

    def test_wait_parsed(self):
        """WAIT action passes through cleanly."""
        result = parse_action({"action": "WAIT"})
        assert result["action"] == "WAIT"

    def test_done_parsed(self):
        """DONE action passes through cleanly."""
        result = parse_action({"action": "DONE"})
        assert result["action"] == "DONE"

    # ------------------------------------------------------------------ #
    # Fallback to WAIT on invalid / malformed input                        #
    # ------------------------------------------------------------------ #

    def test_unknown_action_returns_wait(self):
        """An unrecognised action name falls back to WAIT."""
        result = parse_action({"action": "EXPLODE"})
        assert result["action"] == "WAIT"

    def test_missing_action_field_returns_wait(self):
        """A dict with no 'action' key falls back to WAIT."""
        result = parse_action({"text": "something"})
        assert result["action"] == "WAIT"

    def test_click_missing_coords_returns_wait(self):
        """CLICK without x/y falls back to WAIT."""
        result = parse_action({"action": "CLICK"})
        assert result["action"] == "WAIT"

    # ------------------------------------------------------------------ #
    # TYPE length guard                                                    #
    # ------------------------------------------------------------------ #

    def test_type_too_long_returns_wait_with_too_long_reasoning(self):
        """TYPE text over MAX_TYPE_LENGTH returns WAIT and mentions 'too long'."""
        long_text = "x" * (MAX_TYPE_LENGTH + 1)
        result = parse_action({"action": "TYPE", "text": long_text})
        assert result["action"] == "WAIT"
        assert "too long" in result.get("reasoning", "").lower()

    def test_type_exactly_max_length_allowed(self):
        """TYPE text exactly MAX_TYPE_LENGTH characters is accepted."""
        exact_text = "a" * MAX_TYPE_LENGTH
        result = parse_action({"action": "TYPE", "text": exact_text})
        assert result["action"] == "TYPE"

    # ------------------------------------------------------------------ #
    # Suspicious payload — text patterns                                   #
    # ------------------------------------------------------------------ #

    def test_type_with_pipe_is_suspicious(self):
        """TYPE text containing pipe character sets suspicious=True."""
        result = parse_action({"action": "TYPE", "text": "cmd | echo pwned"})
        assert result["action"] == "TYPE"
        assert result.get("suspicious") is True

    def test_type_with_semicolon_is_suspicious(self):
        """TYPE text containing semicolon shell chain sets suspicious=True."""
        result = parse_action({"action": "TYPE", "text": r"dir; del /f /q C:\\"})
        assert result["action"] == "TYPE"
        assert result.get("suspicious") is True

    def test_normal_type_not_suspicious(self):
        """TYPE with benign text does not set suspicious."""
        result = parse_action({"action": "TYPE", "text": "infected"})
        assert result.get("suspicious") is not True

    # ------------------------------------------------------------------ #
    # Suspicious reasoning — prompt-injection signals                      #
    # ------------------------------------------------------------------ #

    def test_key_with_injected_reasoning_is_suspicious(self):
        """KEY action with 'instructions on screen told me to' in reasoning sets suspicious."""
        result = parse_action({
            "action": "KEY",
            "key": "enter",
            "reasoning": "instructions on screen told me to press enter",
        })
        assert result.get("suspicious") is True


# ---------------------------------------------------------------------------
# TestExecuteAction
# ---------------------------------------------------------------------------

class TestExecuteAction:
    """Unit tests for execute_action() dispatch to QEMUMonitor."""

    def _mock_monitor(self) -> MagicMock:
        """Return a MagicMock standing in for a QEMUMonitor."""
        return MagicMock()

    # ------------------------------------------------------------------ #
    # Returns True and calls correct monitor method                        #
    # ------------------------------------------------------------------ #

    def test_click_calls_mouse_click_and_returns_true(self):
        """CLICK action calls monitor.mouse_click(x, y) and returns True."""
        monitor = self._mock_monitor()
        result = execute_action(monitor, {"action": "CLICK", "x": 50, "y": 75})
        monitor.mouse_click.assert_called_once_with(50, 75)
        assert result is True

    def test_type_calls_type_string_and_returns_true(self):
        """TYPE action calls monitor.type_string(text) and returns True."""
        monitor = self._mock_monitor()
        result = execute_action(monitor, {"action": "TYPE", "text": "malware.exe"})
        monitor.type_string.assert_called_once_with("malware.exe")
        assert result is True

    def test_key_calls_press_key_and_returns_true(self):
        """KEY action calls monitor.press_key(key) and returns True."""
        monitor = self._mock_monitor()
        result = execute_action(monitor, {"action": "KEY", "key": "enter"})
        monitor.press_key.assert_called_once_with("enter")
        assert result is True

    # ------------------------------------------------------------------ #
    # Returns False and makes no monitor calls                             #
    # ------------------------------------------------------------------ #

    def test_wait_returns_false_no_monitor_calls(self):
        """WAIT returns False without calling any monitor methods."""
        monitor = self._mock_monitor()
        result = execute_action(monitor, {"action": "WAIT"})
        assert result is False
        monitor.mouse_click.assert_not_called()
        monitor.type_string.assert_not_called()
        monitor.press_key.assert_not_called()

    def test_done_returns_false(self):
        """DONE returns False."""
        monitor = self._mock_monitor()
        result = execute_action(monitor, {"action": "DONE"})
        assert result is False
