"""Tests for VisionAnalyzer — Claude vision API interface."""

import json
from unittest.mock import MagicMock, patch

import pytest

from sandbox_pilot.vision import VisionAnalyzer, SYSTEM_PROMPT


class TestSystemPrompt:
    def test_contains_sandbox_context(self):
        assert "isolated sandbox" in SYSTEM_PROMPT
        assert "authorized defensive security research" in SYSTEM_PROMPT

    def test_contains_all_actions(self):
        for action in ["WAIT", "CLICK", "TYPE", "KEY", "DONE"]:
            assert action in SYSTEM_PROMPT

    def test_contains_safety_guidelines(self):
        assert "Enable Content" in SYSTEM_PROMPT
        assert "Do NOT close the malware" in SYSTEM_PROMPT


class TestAnalyze:
    def _make_analyzer(self, mock_response_text: str):
        mock_message = MagicMock()
        mock_message.content = [MagicMock(text=mock_response_text)]
        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_message
        analyzer = VisionAnalyzer.__new__(VisionAnalyzer)
        analyzer._client = mock_client
        analyzer._model = "claude-sonnet-4-20250514"
        return analyzer, mock_client

    def test_analyze_returns_parsed_action(self):
        response = json.dumps({"action": "CLICK", "x": 450, "y": 320, "reasoning": "Enable Content"})
        analyzer, _ = self._make_analyzer(response)
        result = analyzer.analyze(b"fake_png", [], resolution="1920x1080")
        assert result["action"] == "CLICK"
        assert result["x"] == 450

    def test_analyze_sends_image_in_message(self):
        response = json.dumps({"action": "WAIT", "reasoning": "Loading"})
        analyzer, mock_client = self._make_analyzer(response)
        analyzer.analyze(b"fake_png", [], resolution="1920x1080")
        call_kwargs = mock_client.messages.create.call_args
        messages = call_kwargs.kwargs["messages"]
        last_msg = messages[-1]
        assert last_msg["role"] == "user"
        content_types = [block["type"] for block in last_msg["content"]]
        assert "image" in content_types

    def test_analyze_includes_hint_in_system(self):
        response = json.dumps({"action": "WAIT", "reasoning": "Loading"})
        analyzer, mock_client = self._make_analyzer(response)
        analyzer.analyze(b"fake_png", [], resolution="1920x1080", hint="Word doc with macros")
        call_kwargs = mock_client.messages.create.call_args
        system = call_kwargs.kwargs["system"]
        assert "Word doc with macros" in system

    def test_analyze_handles_malformed_json(self):
        analyzer, _ = self._make_analyzer("this is not json at all")
        result = analyzer.analyze(b"fake_png", [], resolution="1920x1080")
        assert result["action"] == "WAIT"

    def test_analyze_includes_history(self):
        response = json.dumps({"action": "WAIT", "reasoning": "idle"})
        analyzer, mock_client = self._make_analyzer(response)
        history = [
            {"role": "user", "content": [{"type": "text", "text": "previous screenshot"}]},
            {"role": "assistant", "content": json.dumps({"action": "CLICK", "x": 1, "y": 1, "reasoning": "test"})},
        ]
        analyzer.analyze(b"fake_png", history, resolution="1920x1080")
        call_kwargs = mock_client.messages.create.call_args
        messages = call_kwargs.kwargs["messages"]
        assert len(messages) == 3  # 2 history + 1 current
