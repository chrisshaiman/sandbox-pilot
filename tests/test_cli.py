"""Tests for the CLI main loop — integration test with all mocks."""

import json
from unittest.mock import MagicMock, patch

import pytest

from sandbox_pilot.cli import run_loop, ActionRecord


class TestRunLoop:
    def _make_mocks(self, vision_responses: list[dict]):
        monitor = MagicMock()
        vision = MagicMock()
        vision.analyze = MagicMock(side_effect=vision_responses)
        heuristics = MagicMock()
        heuristics.should_analyze = MagicMock(return_value=True)
        return monitor, vision, heuristics

    @patch("sandbox_pilot.cli._take_screenshot", return_value=b"fake_png")
    def test_done_stops_loop(self, mock_screenshot):
        responses = [{"action": "DONE", "reasoning": "Sample running"}]
        monitor, vision, heuristics = self._make_mocks(responses)
        records = run_loop(monitor, vision, heuristics, max_iterations=10, interval=0)
        assert len(records) == 1
        assert records[0].action == "DONE"

    @patch("sandbox_pilot.cli._take_screenshot", return_value=b"fake_png")
    def test_click_then_done(self, mock_screenshot):
        responses = [
            {"action": "CLICK", "x": 100, "y": 200, "reasoning": "Enable Content"},
            {"action": "DONE", "reasoning": "Running"},
        ]
        monitor, vision, heuristics = self._make_mocks(responses)
        records = run_loop(monitor, vision, heuristics, max_iterations=10, interval=0)
        assert len(records) == 2
        assert records[0].action == "CLICK"
        monitor.mouse_click.assert_called_once_with(100, 200)

    @patch("sandbox_pilot.cli._take_screenshot", return_value=b"fake_png")
    def test_max_iterations_stops_loop(self, mock_screenshot):
        responses = [{"action": "WAIT", "reasoning": "Loading"}] * 5
        monitor, vision, heuristics = self._make_mocks(responses)
        records = run_loop(monitor, vision, heuristics, max_iterations=5, interval=0)
        assert len(records) == 5

    @patch("sandbox_pilot.cli._take_screenshot", return_value=b"fake_png")
    def test_heuristic_skip_no_api_call(self, mock_screenshot):
        monitor, vision, heuristics = self._make_mocks([])
        heuristics.should_analyze = MagicMock(return_value=False)
        records = run_loop(monitor, vision, heuristics, max_iterations=3, interval=0)
        vision.analyze.assert_not_called()
        assert len(records) == 3
        assert all(r.action == "WAIT" for r in records)

    @patch("sandbox_pilot.cli._take_screenshot", return_value=b"fake_png")
    def test_heuristic_reset_after_action(self, mock_screenshot):
        responses = [
            {"action": "CLICK", "x": 1, "y": 1, "reasoning": "test"},
            {"action": "DONE", "reasoning": "done"},
        ]
        monitor, vision, heuristics = self._make_mocks(responses)
        run_loop(monitor, vision, heuristics, max_iterations=10, interval=0)
        heuristics.reset.assert_called()


class TestActionRecord:
    def test_format_click(self):
        rec = ActionRecord(elapsed=5.0, action="CLICK", reasoning="Enable Content", x=450, y=320)
        formatted = str(rec)
        assert "00:05" in formatted
        assert "CLICK(450, 320)" in formatted
        assert "Enable Content" in formatted

    def test_format_wait(self):
        rec = ActionRecord(elapsed=10.0, action="WAIT", reasoning="Loading")
        formatted = str(rec)
        assert "WAIT" in formatted
