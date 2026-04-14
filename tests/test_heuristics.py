"""Tests for ScreenChangeDetector — heuristic pre-filter."""

import pytest

from sandbox_pilot.heuristics import ScreenChangeDetector


class TestUnchangedScreen:
    def test_first_frame_always_analyzes(self):
        detector = ScreenChangeDetector(stuck_threshold=6, stable_count=2)
        assert detector.should_analyze(b"frame1") is True

    def test_identical_frames_skip_until_threshold(self):
        detector = ScreenChangeDetector(stuck_threshold=3, stable_count=2)
        detector.should_analyze(b"frame1")  # 1st: analyze
        assert detector.should_analyze(b"frame1") is False  # 2nd: skip
        assert detector.should_analyze(b"frame1") is False  # 3rd: skip
        assert detector.should_analyze(b"frame1") is True   # 4th: hit threshold

    def test_threshold_fires_once_then_resets_counter(self):
        detector = ScreenChangeDetector(stuck_threshold=2, stable_count=2)
        detector.should_analyze(b"frame1")  # 1st: analyze
        detector.should_analyze(b"frame1")  # 2nd: skip
        assert detector.should_analyze(b"frame1") is True   # 3rd: threshold
        detector.should_analyze(b"frame1")  # 4th: skip (counter reset)
        assert detector.should_analyze(b"frame1") is True   # 5th: threshold again


class TestChangingScreen:
    def test_changing_frames_skip(self):
        detector = ScreenChangeDetector(stuck_threshold=6, stable_count=2)
        detector.should_analyze(b"frame1")  # 1st: analyze
        assert detector.should_analyze(b"frame2") is False  # changed, not stable
        assert detector.should_analyze(b"frame3") is False  # still changing

    def test_stabilized_after_change_triggers_analysis(self):
        detector = ScreenChangeDetector(stuck_threshold=6, stable_count=2)
        detector.should_analyze(b"frame1")   # 1st: analyze
        detector.should_analyze(b"frame2")   # changed, not stable yet
        detector.should_analyze(b"frame2")   # same as last = 1 stable
        assert detector.should_analyze(b"frame2") is True  # 2 stable = settled


class TestReset:
    def test_reset_clears_state(self):
        detector = ScreenChangeDetector(stuck_threshold=6, stable_count=2)
        detector.should_analyze(b"frame1")
        detector.should_analyze(b"frame1")
        detector.reset()
        assert detector.should_analyze(b"frame1") is True
