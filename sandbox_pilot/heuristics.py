"""Heuristic pre-filters for sandbox analysis decisions."""

import hashlib
import logging

logger = logging.getLogger(__name__)


class ScreenChangeDetector:
    """Compare consecutive screenshots by SHA-256 hash to decide whether to
    call the Claude API.

    Two thresholds govern analysis triggers:
    - stuck_threshold: how many consecutive identical frames to tolerate before
      forcing an analysis (detects a frozen/stuck screen).
    - stable_count: how many consecutive identical frames after a *change*
      indicate the screen has settled and is worth analyzing.
    """

    def __init__(self, stuck_threshold: int = 6, stable_count: int = 2) -> None:
        self.stuck_threshold = stuck_threshold
        self.stable_count = stable_count
        self.reset()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def should_analyze(self, screenshot_png: bytes) -> bool:
        """Return True if this frame warrants a Claude API call.

        Decision logic (in order):
        1. First frame ever  → always analyze.
        2. Screen unchanged from previous frame:
           a. Increment unchanged_count.
           b. If unchanged_count >= stuck_threshold → reset counter, return True
              (stuck-screen forced analysis).
           c. If current hash equals last_analyzed_hash AND stable_same_count
              >= stable_count → return True (screen settled after a change).
           d. Otherwise → return False (still identical, skip).
        3. Screen changed from previous frame:
           → reset unchanged_count and stable_same_count, update prev_hash,
             return False (still in transition).
        """
        current_hash = hashlib.sha256(screenshot_png).hexdigest()

        # Case 1: very first frame
        if self._prev_hash is None:
            logger.debug("First frame — analyzing.")
            self._prev_hash = current_hash
            self._last_analyzed_hash = current_hash
            return True

        # Case 2: screen unchanged from last frame
        if current_hash == self._prev_hash:
            self._unchanged_count += 1
            self._stable_same_count += 1

            # 2b: stuck-screen threshold
            if self._unchanged_count >= self.stuck_threshold:
                logger.debug(
                    "Stuck-screen threshold reached (%d frames) — forcing analysis.",
                    self._unchanged_count,
                )
                self._unchanged_count = 0
                self._last_analyzed_hash = current_hash
                return True

            # 2c: screen has settled after a change
            if (
                current_hash != self._last_analyzed_hash
                and self._stable_same_count >= self.stable_count
            ):
                logger.debug(
                    "Screen settled after change (%d stable frames) — analyzing.",
                    self._stable_same_count,
                )
                self._last_analyzed_hash = current_hash
                return True

            logger.debug(
                "Screen unchanged (unchanged_count=%d, stable_same_count=%d) — skipping.",
                self._unchanged_count,
                self._stable_same_count,
            )
            return False

        # Case 3: screen changed
        logger.debug("Screen changed — resetting counters, skipping.")
        self._prev_hash = current_hash
        self._unchanged_count = 0
        self._stable_same_count = 0
        return False

    def reset(self) -> None:
        """Clear all internal state."""
        self._prev_hash: str | None = None
        self._last_analyzed_hash: str | None = None
        self._unchanged_count: int = 0
        self._stable_same_count: int = 0
