"""
sandbox_pilot.cli — Main CLI entry point and observe-decide-act loop.

Drives a QEMU sandbox through automated malware detonation by:
  1. Taking a screenshot of the VM.
  2. Asking the heuristic layer whether the screen changed enough to warrant
     an API call.
  3. Sending the screenshot to Claude's vision API for a structured action
     decision.
  4. Executing the action against the QEMU monitor.
  5. Recording the event and looping until DONE or iteration/timeout limits.
"""

import argparse
import base64
import io
import json
import logging
import time
import tempfile
from dataclasses import dataclass
from pathlib import Path

from PIL import Image

from sandbox_pilot.actions import execute_action, parse_action
from sandbox_pilot.heuristics import ScreenChangeDetector
from sandbox_pilot.monitor import QEMUMonitor
from sandbox_pilot.vision import VisionAnalyzer

logger = logging.getLogger(__name__)

# Maximum number of history messages kept (10 exchanges = 20 messages).
_MAX_HISTORY = 20

# Seconds to wait after screendump for QEMU to finish writing the PPM file.
_SCREENDUMP_SETTLE = 0.3

# ---------------------------------------------------------------------------
# ActionRecord
# ---------------------------------------------------------------------------


@dataclass
class ActionRecord:
    """A single observation-action event recorded during the run loop."""

    elapsed: float           # Seconds since loop start
    action: str              # Action name (CLICK, TYPE, KEY, WAIT, DONE)
    reasoning: str           # Claude's reasoning (or "Heuristic skip")
    x: int | None = None     # CLICK x coordinate
    y: int | None = None     # CLICK y coordinate
    text: str | None = None  # TYPE text
    key: str | None = None   # KEY name

    def __str__(self) -> str:
        """Format as:  [MM:SS] ACTION(details) — reasoning"""
        mins = int(self.elapsed) // 60
        secs = int(self.elapsed) % 60
        timestamp = f"{mins:02d}:{secs:02d}"

        if self.action == "CLICK" and self.x is not None and self.y is not None:
            detail = f"CLICK({self.x}, {self.y})"
        elif self.action == "TYPE" and self.text is not None:
            preview = self.text[:20] + "..." if len(self.text) > 20 else self.text
            detail = f"TYPE({preview!r})"
        elif self.action == "KEY" and self.key is not None:
            detail = f"KEY({self.key})"
        else:
            detail = self.action

        return f"  [{timestamp}] {detail} — {self.reasoning}"


# ---------------------------------------------------------------------------
# Screenshot helper
# ---------------------------------------------------------------------------


def _take_screenshot(monitor: QEMUMonitor, tmp_dir: Path) -> bytes:
    """
    Capture a VM screenshot and return it as PNG bytes.

    Uses QEMU's screendump command (which writes a PPM), then converts to PNG
    in-memory so the vision layer always sees a consistent image format.
    """
    ppm_path = tmp_dir / "screen.ppm"
    monitor.screendump(str(ppm_path))
    # Give QEMU a moment to finish writing the file.
    time.sleep(_SCREENDUMP_SETTLE)

    img = Image.open(ppm_path)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Main observe-decide-act loop
# ---------------------------------------------------------------------------


def run_loop(
    monitor: QEMUMonitor,
    vision: VisionAnalyzer,
    heuristics: ScreenChangeDetector,
    max_iterations: int = 60,
    interval: float = 5.0,
    resolution: str = "1920x1080",
    hint: str | None = None,
    timeout: float = 300.0,
) -> list[ActionRecord]:
    """
    Run the observe-decide-act loop.

    Parameters
    ----------
    monitor:
        Connected QEMUMonitor.
    vision:
        VisionAnalyzer configured with the desired model.
    heuristics:
        ScreenChangeDetector for pre-filtering API calls.
    max_iterations:
        Hard cap on loop iterations regardless of DONE or timeout.
    interval:
        Seconds to sleep between iterations (0 disables sleep, useful in tests).
    resolution:
        VM display resolution string passed to the vision system prompt.
    hint:
        Optional free-text context about the sample.
    timeout:
        Wall-clock seconds before the loop stops.

    Returns
    -------
    list[ActionRecord]
        All events recorded during the run.
    """
    records: list[ActionRecord] = []
    history: list[dict] = []
    start_time = time.monotonic()

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)

        for iteration in range(max_iterations):
            elapsed = time.monotonic() - start_time

            # --- Timeout guard ---
            if elapsed >= timeout:
                logger.warning("Timeout reached after %.1f seconds.", elapsed)
                break

            # --- Take screenshot ---
            try:
                png_bytes = _take_screenshot(monitor, tmp_dir)
            except Exception as exc:
                logger.error("Screenshot failed on iteration %d: %s", iteration, exc)
                time.sleep(interval)
                continue

            # --- Heuristic pre-filter ---
            if not heuristics.should_analyze(png_bytes):
                logger.debug("Iteration %d: heuristic skip.", iteration)
                records.append(
                    ActionRecord(
                        elapsed=elapsed,
                        action="WAIT",
                        reasoning="Heuristic skip",
                    )
                )
                time.sleep(interval)
                continue

            # --- Vision API call ---
            raw_response = vision.analyze(png_bytes, history, resolution, hint)
            action = parse_action(raw_response)

            # --- Build ActionRecord ---
            rec = ActionRecord(
                elapsed=elapsed,
                action=action["action"],
                reasoning=action.get("reasoning", ""),
                x=action.get("x"),
                y=action.get("y"),
                text=action.get("text"),
                key=action.get("key"),
            )
            records.append(rec)
            logger.info("Iteration %d: %s", iteration, rec)

            # --- Execute action ---
            action_taken = execute_action(monitor, action)

            # --- Update conversation history ---
            # Append user message (screenshot + prompt) and assistant message
            # (the raw JSON response) so future API calls have context.
            image_b64 = base64.standard_b64encode(png_bytes).decode("ascii")
            user_msg: dict = {
                "role": "user",
                "content": [
                    {
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": "image/png",
                            "data": image_b64,
                        },
                    },
                    {
                        "type": "text",
                        "text": "What is the current state of the VM? Respond with the next action JSON.",
                    },
                ],
            }
            assistant_msg: dict = {
                "role": "assistant",
                "content": json.dumps(raw_response),
            }
            history.append(user_msg)
            history.append(assistant_msg)

            # Trim to last _MAX_HISTORY messages (10 exchanges).
            if len(history) > _MAX_HISTORY:
                history = history[-_MAX_HISTORY:]

            # --- Reset heuristics when an input action was taken ---
            if action_taken:
                heuristics.reset()

            # --- Check for completion ---
            if action["action"] == "DONE":
                logger.info("DONE received — stopping loop.")
                break

            time.sleep(interval)

    return records


# ---------------------------------------------------------------------------
# Summary printer
# ---------------------------------------------------------------------------


def _print_summary(records: list[ActionRecord]) -> None:
    """Print a human-readable run summary to stdout."""
    total = len(records)
    api_calls = sum(1 for r in records if r.reasoning != "Heuristic skip")
    action_count = sum(1 for r in records if r.action not in ("WAIT", "DONE"))

    print()
    print("=" * 60)
    print(f"  Iterations : {total}")
    print(f"  API calls  : {api_calls}")
    print(f"  Actions    : {action_count}")
    print("  Events:")
    for rec in records:
        if rec.reasoning != "Heuristic skip":
            print(rec)
    print("=" * 60)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Parse arguments, set up components, and run the loop."""
    parser = argparse.ArgumentParser(
        prog="sandbox-pilot",
        description="AI-assisted malware detonation agent for QEMU sandboxes.",
    )
    parser.add_argument(
        "--socket",
        required=True,
        help="Path to the QEMU monitor Unix socket (e.g. /tmp/qemu.sock).",
    )
    parser.add_argument(
        "--hint",
        default=None,
        help="Optional free-text context about the sample.",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=5.0,
        help="Seconds between iterations (default: 5).",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=60,
        help="Maximum number of loop iterations (default: 60).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=300.0,
        help="Wall-clock timeout in seconds (default: 300).",
    )
    parser.add_argument(
        "--resolution",
        default="1920x1080",
        help="VM display resolution (default: 1920x1080).",
    )
    parser.add_argument(
        "--model",
        default="claude-sonnet-4-20250514",
        help="Claude model ID to use for vision analysis.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable DEBUG-level logging.",
    )

    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )

    print()
    print("  sandbox-pilot")
    print(f"  socket     : {args.socket}")
    print(f"  model      : {args.model}")
    print(f"  resolution : {args.resolution}")
    print(f"  timeout    : {args.timeout}s  max-iter: {args.max_iterations}")
    if args.hint:
        print(f"  hint       : {args.hint}")
    print()

    with QEMUMonitor(args.socket) as monitor:
        try:
            vision = VisionAnalyzer(model=args.model)
            heuristics = ScreenChangeDetector()

            records = run_loop(
                monitor=monitor,
                vision=vision,
                heuristics=heuristics,
                max_iterations=args.max_iterations,
                interval=args.interval,
                resolution=args.resolution,
                hint=args.hint,
                timeout=args.timeout,
            )

            _print_summary(records)

        except KeyboardInterrupt:
            print()
            print("Interrupted by user.")
