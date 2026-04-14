# sandbox-pilot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an AI-assisted malware detonation agent that observes a QEMU VM via monitor socket, analyzes screenshots with Claude vision, and sends keyboard/mouse input to help malware samples execute past stuck dialogs.

**Architecture:** Five Python modules in a pip-installable package. `monitor.py` wraps the QEMU monitor socket (sendkey, mouse, screendump). `heuristics.py` filters unchanged screenshots to avoid unnecessary API calls. `vision.py` sends screenshots to Claude and parses structured JSON actions. `actions.py` translates those actions into monitor commands. `cli.py` ties it all together in an observe-decide-act loop.

**Tech Stack:** Python 3.10+, `anthropic` SDK, `Pillow` for PPM→PNG, standard library for everything else (socket, argparse, logging, json, hashlib).

**Spec:** `docs/superpowers/specs/2026-04-13-sandbox-pilot-design.md`

---

## File Map

| File | Responsibility | Created/Modified |
|------|---------------|-----------------|
| `tools/sandbox-pilot/pyproject.toml` | Package metadata, dependencies, CLI entry point | Create |
| `tools/sandbox-pilot/sandbox_pilot/__init__.py` | Package init, version | Create |
| `tools/sandbox-pilot/sandbox_pilot/monitor.py` | QEMUMonitor class — socket, sendkey, mouse, screendump | Create |
| `tools/sandbox-pilot/sandbox_pilot/heuristics.py` | ScreenChangeDetector — SHA-256 screenshot diffing | Create |
| `tools/sandbox-pilot/sandbox_pilot/vision.py` | VisionAnalyzer — Claude API, system prompt, JSON parsing | Create |
| `tools/sandbox-pilot/sandbox_pilot/actions.py` | execute_action() — translates Claude responses to monitor commands | Create |
| `tools/sandbox-pilot/sandbox_pilot/cli.py` | CLI entry point, main loop, logging, summary | Create |
| `tools/sandbox-pilot/tests/__init__.py` | Test package init | Create |
| `tools/sandbox-pilot/tests/test_monitor.py` | QEMUMonitor unit tests (mocked socket) | Create |
| `tools/sandbox-pilot/tests/test_heuristics.py` | ScreenChangeDetector unit tests | Create |
| `tools/sandbox-pilot/tests/test_actions.py` | execute_action unit tests (mocked monitor) | Create |
| `tools/sandbox-pilot/tests/test_vision.py` | VisionAnalyzer unit tests (mocked API) | Create |
| `tools/sandbox-pilot/tests/test_cli.py` | Integration test for main loop (all mocked) | Create |

---

## Task 1: Project Scaffolding

**Files:**
- Create: `tools/sandbox-pilot/pyproject.toml`
- Create: `tools/sandbox-pilot/sandbox_pilot/__init__.py`
- Create: `tools/sandbox-pilot/tests/__init__.py`

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p tools/sandbox-pilot/sandbox_pilot
mkdir -p tools/sandbox-pilot/tests
```

- [ ] **Step 2: Write pyproject.toml**

Create `tools/sandbox-pilot/pyproject.toml`:

```toml
[build-system]
requires = ["setuptools>=68.0"]
build-backend = "setuptools.backends._legacy:_Backend"

[project]
name = "sandbox-pilot"
version = "0.1.0"
description = "AI-assisted malware detonation agent for QEMU sandboxes"
license = {text = "Apache-2.0"}
authors = [{name = "Christopher Shaiman"}]
requires-python = ">=3.10"
readme = "README.md"

dependencies = [
    "anthropic>=0.40.0",
    "Pillow>=10.0.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0",
]

[project.scripts]
sandbox-pilot = "sandbox_pilot.cli:main"
```

- [ ] **Step 3: Write package __init__.py**

Create `tools/sandbox-pilot/sandbox_pilot/__init__.py`:

```python
"""sandbox-pilot: AI-assisted malware detonation agent for QEMU sandboxes."""

__version__ = "0.1.0"
```

- [ ] **Step 4: Write tests __init__.py**

Create `tools/sandbox-pilot/tests/__init__.py`:

```python
```

(Empty file — just marks the directory as a package.)

- [ ] **Step 5: Install in dev mode and verify**

```bash
cd tools/sandbox-pilot
pip install -e ".[dev]"
python -c "import sandbox_pilot; print(sandbox_pilot.__version__)"
```

Expected: `0.1.0`

- [ ] **Step 6: Commit**

```bash
git add tools/sandbox-pilot/pyproject.toml tools/sandbox-pilot/sandbox_pilot/__init__.py tools/sandbox-pilot/tests/__init__.py
git commit -m "feat(sandbox-pilot): scaffold project structure and pyproject.toml"
```

---

## Task 2: QEMUMonitor (monitor.py)

**Files:**
- Create: `tools/sandbox-pilot/sandbox_pilot/monitor.py`
- Create: `tools/sandbox-pilot/tests/test_monitor.py`

- [ ] **Step 1: Write failing tests for QEMUMonitor**

Create `tools/sandbox-pilot/tests/test_monitor.py`:

```python
"""Tests for QEMUMonitor — QEMU monitor socket interface."""

import socket
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from sandbox_pilot.monitor import QEMUMonitor, QKEY


class FakeMonitor:
    """Minimal fake QEMU monitor that records commands."""

    def __init__(self, socket_path: str):
        self.socket_path = socket_path
        self.commands: list[str] = []
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(socket_path)
        self._server.listen(1)
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while self._running:
            try:
                self._server.settimeout(0.5)
                conn, _ = self._server.accept()
                # Send QEMU monitor banner
                conn.sendall(b"QEMU 8.2.0 monitor - type 'help' for more\r\n(qemu) ")
                buf = b""
                while self._running:
                    conn.settimeout(0.5)
                    try:
                        data = conn.recv(4096)
                        if not data:
                            break
                        buf += data
                        while b"\n" in buf:
                            line, buf = buf.split(b"\n", 1)
                            cmd = line.decode().strip()
                            if cmd:
                                self.commands.append(cmd)
                            conn.sendall(b"(qemu) ")
                    except socket.timeout:
                        continue
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                break

    def stop(self):
        self._running = False
        self._thread.join(timeout=2)
        self._server.close()


@pytest.fixture
def fake_monitor(tmp_path):
    sock_path = str(tmp_path / "monitor.sock")
    fm = FakeMonitor(sock_path)
    yield fm, sock_path
    fm.stop()


class TestQEMUMonitorConnect:
    def test_connect_and_close(self, fake_monitor):
        fm, sock_path = fake_monitor
        mon = QEMUMonitor(sock_path)
        mon.close()

    def test_connect_bad_path_raises(self, tmp_path):
        with pytest.raises(ConnectionError):
            QEMUMonitor(str(tmp_path / "nonexistent.sock"))


class TestSendkey:
    def test_sendkey_letter(self, fake_monitor):
        fm, sock_path = fake_monitor
        mon = QEMUMonitor(sock_path)
        mon.sendkey("a")
        time.sleep(0.2)
        mon.close()
        assert "sendkey a" in fm.commands

    def test_sendkey_special(self, fake_monitor):
        fm, sock_path = fake_monitor
        mon = QEMUMonitor(sock_path)
        mon.sendkey("ret")
        time.sleep(0.2)
        mon.close()
        assert "sendkey ret" in fm.commands


class TestTypeString:
    def test_type_hello(self, fake_monitor):
        fm, sock_path = fake_monitor
        mon = QEMUMonitor(sock_path)
        mon.type_string("Hi")
        time.sleep(0.5)
        mon.close()
        assert "sendkey shift-h" in fm.commands
        assert "sendkey i" in fm.commands

    def test_type_special_chars(self, fake_monitor):
        fm, sock_path = fake_monitor
        mon = QEMUMonitor(sock_path)
        mon.type_string("@")
        time.sleep(0.2)
        mon.close()
        assert "sendkey shift-2" in fm.commands


class TestPressKey:
    def test_press_enter(self, fake_monitor):
        fm, sock_path = fake_monitor
        mon = QEMUMonitor(sock_path)
        mon.press_key("enter")
        time.sleep(0.2)
        mon.close()
        assert "sendkey ret" in fm.commands

    def test_press_tab(self, fake_monitor):
        fm, sock_path = fake_monitor
        mon = QEMUMonitor(sock_path)
        mon.press_key("tab")
        time.sleep(0.2)
        mon.close()
        assert "sendkey tab" in fm.commands

    def test_press_escape(self, fake_monitor):
        fm, sock_path = fake_monitor
        mon = QEMUMonitor(sock_path)
        mon.press_key("escape")
        time.sleep(0.2)
        mon.close()
        assert "sendkey esc" in fm.commands


class TestMouse:
    def test_mouse_move(self, fake_monitor):
        fm, sock_path = fake_monitor
        mon = QEMUMonitor(sock_path)
        mon.mouse_move(100, 200)
        time.sleep(0.2)
        mon.close()
        assert "mouse_move 100 200" in fm.commands

    def test_mouse_click(self, fake_monitor):
        fm, sock_path = fake_monitor
        mon = QEMUMonitor(sock_path)
        mon.mouse_click(450, 320)
        time.sleep(0.5)
        mon.close()
        assert "mouse_move 450 320" in fm.commands
        assert "mouse_button 1" in fm.commands
        assert "mouse_button 0" in fm.commands


class TestScreendump:
    def test_screendump(self, fake_monitor, tmp_path):
        fm, sock_path = fake_monitor
        mon = QEMUMonitor(sock_path)
        out = str(tmp_path / "screen.ppm")
        mon.screendump(out)
        time.sleep(0.2)
        mon.close()
        assert f"screendump {out}" in fm.commands


class TestQKEY:
    def test_all_uppercase_mapped(self):
        for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            assert ch in QKEY
            assert QKEY[ch] == f"shift-{ch.lower()}"

    def test_special_chars_mapped(self):
        assert QKEY[" "] == "spc"
        assert QKEY["@"] == "shift-2"
        assert QKEY["{"] == "shift-bracket_left"
        assert QKEY["|"] == "shift-backslash"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd tools/sandbox-pilot
pytest tests/test_monitor.py -v
```

Expected: `ModuleNotFoundError: No module named 'sandbox_pilot.monitor'`

- [ ] **Step 3: Write monitor.py**

Create `tools/sandbox-pilot/sandbox_pilot/monitor.py`:

```python
"""QEMU monitor socket interface for sandbox-pilot.

Provides keyboard input (sendkey), mouse control, and screendump via the
QEMU human monitor protocol over a Unix socket.

Extracted from labconfig.py and winrm_setup.py helper scripts.
"""

import logging
import socket
import time

logger = logging.getLogger(__name__)

# Key mapping: Python character -> QEMU sendkey name.
# Covers all printable ASCII. Lowercase letters and digits map to themselves.
QKEY: dict[str, str] = {
    " ": "spc",
    "/": "slash",
    "\\": "backslash",
    "_": "shift-minus",
    "-": "minus",
    "=": "equal",
    "+": "shift-equal",
    ".": "dot",
    ",": "comma",
    "@": "shift-2",
    "!": "shift-1",
    "#": "shift-3",
    "$": "shift-4",
    "%": "shift-5",
    "^": "shift-6",
    "&": "shift-7",
    "*": "shift-8",
    "(": "shift-9",
    ")": "shift-0",
    "{": "shift-bracket_left",
    "}": "shift-bracket_right",
    "[": "bracket_left",
    "]": "bracket_right",
    "|": "shift-backslash",
    '"': "shift-apostrophe",
    "'": "apostrophe",
    ":": "shift-semicolon",
    ";": "semicolon",
    "<": "shift-comma",
    ">": "shift-dot",
    "?": "shift-slash",
    "~": "shift-grave_accent",
    "`": "grave_accent",
    "\t": "tab",
    "\n": "ret",
}

# Add uppercase letters
for _c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
    QKEY[_c] = f"shift-{_c.lower()}"

# Friendly key names -> QEMU key names
_KEY_ALIASES: dict[str, str] = {
    "enter": "ret",
    "return": "ret",
    "escape": "esc",
    "space": "spc",
    "backspace": "backspace",
    "delete": "delete",
    "tab": "tab",
    "up": "up",
    "down": "down",
    "left": "left",
    "right": "right",
}
# f1-f12
for _i in range(1, 13):
    _KEY_ALIASES[f"f{_i}"] = f"f{_i}"

# Delay between keystrokes (seconds). Too fast and QEMU drops keys.
KEY_DELAY = 0.08
# Delay between mouse_move and mouse_button to ensure QEMU processes the move.
MOUSE_DELAY = 0.05


class QEMUMonitor:
    """Persistent connection to a QEMU human monitor socket.

    Unlike the earlier helper scripts (labconfig.py, winrm_setup.py) which
    reconnected per command, this keeps the socket open to avoid races between
    rapid mouse_move + mouse_button sequences.
    """

    def __init__(self, socket_path: str, connect_timeout: float = 10.0):
        self._path = socket_path
        self._sock: socket.socket | None = None
        self._connect(connect_timeout)

    def _connect(self, timeout: float) -> None:
        """Connect to the monitor socket with retries."""
        deadline = time.monotonic() + timeout
        last_err: Exception | None = None
        while time.monotonic() < deadline:
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(5.0)
                s.connect(self._path)
                # Read the QEMU banner / prompt
                s.recv(4096)
                self._sock = s
                logger.info("Connected to QEMU monitor at %s", self._path)
                return
            except (ConnectionRefusedError, FileNotFoundError, OSError) as exc:
                last_err = exc
                time.sleep(1.0)
        raise ConnectionError(
            f"Could not connect to QEMU monitor at {self._path}: {last_err}"
        )

    def send_command(self, cmd: str) -> str:
        """Send a raw monitor command and return the response."""
        if self._sock is None:
            raise ConnectionError("Not connected to QEMU monitor")
        self._sock.sendall((cmd + "\n").encode())
        time.sleep(KEY_DELAY)
        # Read response (non-blocking best-effort)
        self._sock.settimeout(0.5)
        try:
            data = self._sock.recv(4096)
            return data.decode(errors="replace")
        except socket.timeout:
            return ""

    def sendkey(self, key: str) -> None:
        """Send a single keystroke via QEMU sendkey."""
        self.send_command(f"sendkey {key}")

    def type_string(self, text: str) -> None:
        """Type a string character by character."""
        for ch in text:
            key = QKEY.get(ch, ch.lower() if ch.isalpha() else ch)
            self.sendkey(key)

    def press_key(self, key: str) -> None:
        """Press a named key (enter, tab, escape, f1, etc.)."""
        qemu_key = _KEY_ALIASES.get(key.lower(), key.lower())
        self.sendkey(qemu_key)

    def mouse_move(self, x: int, y: int) -> None:
        """Move the mouse to absolute pixel coordinates."""
        self.send_command(f"mouse_move {x} {y}")

    def mouse_click(self, x: int, y: int, button: int = 1) -> None:
        """Move mouse to coordinates, press and release a button.

        button: 1=left, 2=middle, 4=right.
        """
        self.mouse_move(x, y)
        time.sleep(MOUSE_DELAY)
        self.send_command(f"mouse_button {button}")
        time.sleep(MOUSE_DELAY)
        self.send_command("mouse_button 0")  # release

    def screendump(self, path: str) -> None:
        """Save a screenshot of the VM to a PPM file."""
        self.send_command(f"screendump {path}")

    def close(self) -> None:
        """Close the socket connection."""
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
            logger.info("Disconnected from QEMU monitor")
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd tools/sandbox-pilot
pytest tests/test_monitor.py -v
```

Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add tools/sandbox-pilot/sandbox_pilot/monitor.py tools/sandbox-pilot/tests/test_monitor.py
git commit -m "feat(sandbox-pilot): add QEMUMonitor with sendkey, mouse, and screendump"
```

---

## Task 3: ScreenChangeDetector (heuristics.py)

**Files:**
- Create: `tools/sandbox-pilot/sandbox_pilot/heuristics.py`
- Create: `tools/sandbox-pilot/tests/test_heuristics.py`

- [ ] **Step 1: Write failing tests**

Create `tools/sandbox-pilot/tests/test_heuristics.py`:

```python
"""Tests for ScreenChangeDetector — heuristic pre-filter."""

import pytest

from sandbox_pilot.heuristics import ScreenChangeDetector


class TestUnchangedScreen:
    """Screen stays the same — detect stuck state."""

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
    """Screen is actively changing — detect when it settles."""

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
    """Reset after an action is taken."""

    def test_reset_clears_state(self):
        detector = ScreenChangeDetector(stuck_threshold=6, stable_count=2)
        detector.should_analyze(b"frame1")
        detector.should_analyze(b"frame1")
        detector.reset()
        # After reset, next frame is treated as first
        assert detector.should_analyze(b"frame1") is True
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_heuristics.py -v
```

Expected: `ModuleNotFoundError: No module named 'sandbox_pilot.heuristics'`

- [ ] **Step 3: Write heuristics.py**

Create `tools/sandbox-pilot/sandbox_pilot/heuristics.py`:

```python
"""Screenshot change detection for sandbox-pilot.

Sits between the screendump step and the Claude API call. Compares
consecutive screenshots by SHA-256 hash to decide whether the screen
has changed meaningfully enough to warrant an API call.

This filter typically eliminates 60-80% of API calls during a detonation.
"""

import hashlib
import logging

logger = logging.getLogger(__name__)


class ScreenChangeDetector:
    """Decides whether a screenshot warrants a Claude API call.

    States:
        - Screen unchanged, under stuck_threshold: skip (normal idle)
        - Screen unchanged, at stuck_threshold: analyze (might be stuck)
        - Screen changed, not yet stable: skip (transition in progress)
        - Screen changed, stable for stable_count: analyze (new dialog settled)
    """

    def __init__(self, stuck_threshold: int = 6, stable_count: int = 2):
        self._stuck_threshold = stuck_threshold
        self._stable_count = stable_count
        self._prev_hash: str | None = None
        self._unchanged_count = 0
        self._stable_same_count = 0
        self._last_analyzed_hash: str | None = None

    def should_analyze(self, screenshot_png: bytes) -> bool:
        """Return True if this screenshot should be sent to Claude."""
        current_hash = hashlib.sha256(screenshot_png).hexdigest()

        # First frame ever — always analyze
        if self._prev_hash is None:
            self._prev_hash = current_hash
            self._last_analyzed_hash = current_hash
            logger.debug("First frame — analyzing")
            return True

        if current_hash == self._prev_hash:
            # Screen unchanged from previous frame
            self._unchanged_count += 1
            self._stable_same_count += 1

            if self._unchanged_count >= self._stuck_threshold:
                # Been static too long — might be stuck
                self._unchanged_count = 0  # reset so it fires again
                logger.debug(
                    "Screen unchanged for %d frames — analyzing (stuck?)",
                    self._stuck_threshold,
                )
                self._last_analyzed_hash = current_hash
                return True

            if (
                current_hash != self._last_analyzed_hash
                and self._stable_same_count >= self._stable_count
            ):
                # Screen changed since last analysis and has now settled
                logger.debug("Screen changed and stabilized — analyzing")
                self._last_analyzed_hash = current_hash
                return True

            logger.debug("Screen unchanged (%d) — skipping", self._unchanged_count)
            return False

        else:
            # Screen changed from previous frame
            self._unchanged_count = 0
            self._stable_same_count = 0
            self._prev_hash = current_hash
            logger.debug("Screen changing — skipping (waiting to settle)")
            return False

    def reset(self) -> None:
        """Reset all state. Call after taking an action."""
        self._prev_hash = None
        self._unchanged_count = 0
        self._stable_same_count = 0
        self._last_analyzed_hash = None
        logger.debug("Detector state reset")
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_heuristics.py -v
```

Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add tools/sandbox-pilot/sandbox_pilot/heuristics.py tools/sandbox-pilot/tests/test_heuristics.py
git commit -m "feat(sandbox-pilot): add ScreenChangeDetector heuristic pre-filter"
```

---

## Task 4: Action Translator (actions.py)

**Files:**
- Create: `tools/sandbox-pilot/sandbox_pilot/actions.py`
- Create: `tools/sandbox-pilot/tests/test_actions.py`

- [ ] **Step 1: Write failing tests**

Create `tools/sandbox-pilot/tests/test_actions.py`:

```python
"""Tests for action translation — Claude response -> QEMU commands."""

from unittest.mock import MagicMock

import pytest

from sandbox_pilot.actions import execute_action, parse_action


class TestParseAction:
    def test_parse_click(self):
        raw = {"action": "CLICK", "x": 450, "y": 320, "reasoning": "Enable Content"}
        action = parse_action(raw)
        assert action["action"] == "CLICK"
        assert action["x"] == 450
        assert action["y"] == 320

    def test_parse_type(self):
        raw = {"action": "TYPE", "text": "infected", "reasoning": "Password field"}
        action = parse_action(raw)
        assert action["action"] == "TYPE"
        assert action["text"] == "infected"

    def test_parse_key(self):
        raw = {"action": "KEY", "key": "enter", "reasoning": "Dismiss dialog"}
        action = parse_action(raw)
        assert action["action"] == "KEY"
        assert action["key"] == "enter"

    def test_parse_wait(self):
        raw = {"action": "WAIT", "reasoning": "Loading"}
        action = parse_action(raw)
        assert action["action"] == "WAIT"

    def test_parse_done(self):
        raw = {"action": "DONE", "reasoning": "Running normally"}
        action = parse_action(raw)
        assert action["action"] == "DONE"

    def test_parse_unknown_action_returns_wait(self):
        raw = {"action": "EXPLODE", "reasoning": "???"}
        action = parse_action(raw)
        assert action["action"] == "WAIT"

    def test_parse_missing_action_returns_wait(self):
        raw = {"reasoning": "no action field"}
        action = parse_action(raw)
        assert action["action"] == "WAIT"

    def test_parse_click_missing_coords_returns_wait(self):
        raw = {"action": "CLICK", "reasoning": "no coords"}
        action = parse_action(raw)
        assert action["action"] == "WAIT"

    def test_parse_type_over_100_chars_rejected(self):
        raw = {"action": "TYPE", "text": "A" * 101, "reasoning": "long input"}
        action = parse_action(raw)
        assert action["action"] == "WAIT"
        assert "too long" in action["reasoning"].lower()

    def test_parse_type_exactly_100_chars_allowed(self):
        raw = {"action": "TYPE", "text": "A" * 100, "reasoning": "max length"}
        action = parse_action(raw)
        assert action["action"] == "TYPE"
        assert action["text"] == "A" * 100


class TestPromptInjectionDetection:
    """Visual prompt injection detection — log warnings, don't block."""

    def test_suspicious_type_with_pipe_flagged(self):
        raw = {"action": "TYPE", "text": "cmd | echo pwned", "reasoning": "text on screen"}
        action = parse_action(raw)
        assert action["action"] == "TYPE"  # not blocked
        assert action.get("suspicious") is True

    def test_suspicious_type_with_semicolon_chain_flagged(self):
        raw = {"action": "TYPE", "text": "dir; del /f /q C:\\", "reasoning": "instructions"}
        action = parse_action(raw)
        assert action["action"] == "TYPE"
        assert action.get("suspicious") is True

    def test_normal_type_not_flagged(self):
        raw = {"action": "TYPE", "text": "infected", "reasoning": "Password prompt"}
        action = parse_action(raw)
        assert action["action"] == "TYPE"
        assert action.get("suspicious") is not True

    def test_suspicious_reasoning_flagged(self):
        raw = {"action": "KEY", "key": "enter", "reasoning": "instructions on screen told me to"}
        action = parse_action(raw)
        assert action["action"] == "KEY"
        assert action.get("suspicious") is True


class TestExecuteAction:
    def test_execute_click(self):
        monitor = MagicMock()
        action = {"action": "CLICK", "x": 450, "y": 320, "reasoning": "test"}
        result = execute_action(monitor, action)
        monitor.mouse_click.assert_called_once_with(450, 320)
        assert result is True

    def test_execute_type(self):
        monitor = MagicMock()
        action = {"action": "TYPE", "text": "hello", "reasoning": "test"}
        result = execute_action(monitor, action)
        monitor.type_string.assert_called_once_with("hello")
        assert result is True

    def test_execute_key(self):
        monitor = MagicMock()
        action = {"action": "KEY", "key": "enter", "reasoning": "test"}
        result = execute_action(monitor, action)
        monitor.press_key.assert_called_once_with("enter")
        assert result is True

    def test_execute_wait_returns_false(self):
        monitor = MagicMock()
        action = {"action": "WAIT", "reasoning": "test"}
        result = execute_action(monitor, action)
        assert result is False
        monitor.mouse_click.assert_not_called()
        monitor.type_string.assert_not_called()
        monitor.press_key.assert_not_called()

    def test_execute_done_returns_false(self):
        monitor = MagicMock()
        action = {"action": "DONE", "reasoning": "test"}
        result = execute_action(monitor, action)
        assert result is False
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_actions.py -v
```

Expected: `ModuleNotFoundError: No module named 'sandbox_pilot.actions'`

- [ ] **Step 3: Write actions.py**

Create `tools/sandbox-pilot/sandbox_pilot/actions.py`:

```python
"""Translate Claude vision responses into QEMU monitor commands.

Includes anti-prompt-injection mitigations:
- TYPE actions over 100 characters are rejected (blocks "type this shell command")
- Suspicious patterns in TYPE text or reasoning are flagged (not blocked) as
  potential visual prompt injection — useful threat intelligence
"""

import logging
import re

from sandbox_pilot.monitor import QEMUMonitor

logger = logging.getLogger(__name__)

_VALID_ACTIONS = {"CLICK", "TYPE", "KEY", "WAIT", "DONE"}

# Max characters allowed in a single TYPE action. Legitimate dialog inputs
# (passwords, filenames, form fields) are well under this. Blocks injection
# attacks that try to get the agent to type shell commands.
MAX_TYPE_LENGTH = 100

# Patterns that suggest visual prompt injection — flag but don't block.
# These fire a WARNING log for analyst review.
_SUSPICIOUS_TEXT_PATTERNS = re.compile(
    r"[|;&]"          # pipe, semicolon chain, ampersand chain
    r"|>\s*/dev/"      # redirect to device
    r"|powershell\s+-" # powershell with flags
    r"|cmd\s*/c"       # cmd /c
    r"|wget\s+"        # wget download
    r"|curl\s+",       # curl download
    re.IGNORECASE,
)

_SUSPICIOUS_REASONING_PATTERNS = re.compile(
    r"instructions?\s+on\s+screen"
    r"|text\s+(on\s+screen\s+)?(told|asked|says|instructs)"
    r"|ignore\s+previous",
    re.IGNORECASE,
)


def _check_suspicious(action: dict) -> dict:
    """Flag potential prompt injection. Adds 'suspicious': True if detected."""
    text = action.get("text", "")
    reasoning = action.get("reasoning", "")

    if text and _SUSPICIOUS_TEXT_PATTERNS.search(text):
        logger.warning(
            "PROMPT INJECTION? Suspicious TYPE text: %r (reasoning: %s)",
            text, reasoning,
        )
        action["suspicious"] = True
        return action

    if _SUSPICIOUS_REASONING_PATTERNS.search(reasoning):
        logger.warning(
            "PROMPT INJECTION? Suspicious reasoning: %r (action: %s)",
            reasoning, action.get("action"),
        )
        action["suspicious"] = True
        return action

    return action


def parse_action(raw: dict) -> dict:
    """Validate and normalize a raw action dict from Claude.

    Returns a clean action dict. Invalid or unrecognized actions are
    downgraded to WAIT so the agent never crashes on bad AI output.
    TYPE actions over MAX_TYPE_LENGTH characters are rejected.
    Suspicious patterns are flagged but not blocked.
    """
    action = raw.get("action", "").upper()

    if action not in _VALID_ACTIONS:
        logger.warning("Unknown action %r — treating as WAIT", raw.get("action"))
        return {"action": "WAIT", "reasoning": raw.get("reasoning", "unknown action")}

    if action == "CLICK":
        if "x" not in raw or "y" not in raw:
            logger.warning("CLICK missing coordinates — treating as WAIT")
            return {"action": "WAIT", "reasoning": "CLICK missing coordinates"}
        result = {
            "action": "CLICK",
            "x": int(raw["x"]),
            "y": int(raw["y"]),
            "reasoning": raw.get("reasoning", ""),
        }
        return _check_suspicious(result)

    if action == "TYPE":
        text = raw.get("text", "")
        if len(text) > MAX_TYPE_LENGTH:
            logger.warning(
                "TYPE text too long (%d chars, max %d) — rejecting as suspicious: %r",
                len(text), MAX_TYPE_LENGTH, text[:50],
            )
            return {
                "action": "WAIT",
                "reasoning": f"TYPE too long ({len(text)} chars) — rejected",
                "suspicious": True,
            }
        result = {
            "action": "TYPE",
            "text": text,
            "reasoning": raw.get("reasoning", ""),
        }
        return _check_suspicious(result)

    if action == "KEY":
        result = {
            "action": "KEY",
            "key": raw.get("key", "enter"),
            "reasoning": raw.get("reasoning", ""),
        }
        return _check_suspicious(result)

    # WAIT or DONE
    return {"action": action, "reasoning": raw.get("reasoning", "")}


def execute_action(monitor: QEMUMonitor, action: dict) -> bool:
    """Execute a parsed action via the QEMU monitor.

    Returns True if an input action was taken (CLICK/TYPE/KEY),
    False for WAIT/DONE (no input sent).
    """
    act = action["action"]

    if action.get("suspicious"):
        logger.warning("Executing SUSPICIOUS action: %s — flagged for review", action)

    if act == "CLICK":
        logger.info("CLICK(%d, %d) — %s", action["x"], action["y"], action["reasoning"])
        monitor.mouse_click(action["x"], action["y"])
        return True

    if act == "TYPE":
        logger.info("TYPE(%r) — %s", action["text"], action["reasoning"])
        monitor.type_string(action["text"])
        return True

    if act == "KEY":
        logger.info("KEY(%s) — %s", action["key"], action["reasoning"])
        monitor.press_key(action["key"])
        return True

    if act == "DONE":
        logger.info("DONE — %s", action["reasoning"])
        return False

    # WAIT
    logger.debug("WAIT — %s", action["reasoning"])
    return False
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_actions.py -v
```

Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add tools/sandbox-pilot/sandbox_pilot/actions.py tools/sandbox-pilot/tests/test_actions.py
git commit -m "feat(sandbox-pilot): add action parser and executor"
```

---

## Task 5: VisionAnalyzer (vision.py)

**Files:**
- Create: `tools/sandbox-pilot/sandbox_pilot/vision.py`
- Create: `tools/sandbox-pilot/tests/test_vision.py`

- [ ] **Step 1: Write failing tests**

Create `tools/sandbox-pilot/tests/test_vision.py`:

```python
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
        """Create a VisionAnalyzer with a mocked Anthropic client."""
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
        analyzer, mock_client = self._make_analyzer(response)
        result = analyzer.analyze(b"fake_png", [], resolution="1920x1080")
        assert result["action"] == "CLICK"
        assert result["x"] == 450

    def test_analyze_sends_image_in_message(self):
        response = json.dumps({"action": "WAIT", "reasoning": "Loading"})
        analyzer, mock_client = self._make_analyzer(response)
        analyzer.analyze(b"fake_png", [], resolution="1920x1080")
        call_kwargs = mock_client.messages.create.call_args
        messages = call_kwargs.kwargs["messages"]
        # Last message should contain an image block
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
        # History messages + current screenshot message
        assert len(messages) == 3
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_vision.py -v
```

Expected: `ModuleNotFoundError: No module named 'sandbox_pilot.vision'`

- [ ] **Step 3: Write vision.py**

Create `tools/sandbox-pilot/sandbox_pilot/vision.py`:

```python
"""Claude vision interface for sandbox-pilot.

Sends VM screenshots to Claude's vision API and parses structured
action responses (CLICK, TYPE, KEY, WAIT, DONE).
"""

import base64
import json
import logging

import anthropic

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are a malware analysis assistant operating inside an isolated sandbox \
environment (CAPEv2 on an air-gapped detonation VLAN). The VM has:
- No internet access
- No route to production systems or management networks
- A disposable disk that is reverted to a clean snapshot after every analysis

This is authorized defensive security research. The goal is to observe malware \
behavior so security teams can build detections and protect real users.

You are observing a Windows VM where a malware sample has been submitted for \
analysis. Your job is to help the sample fully execute by interacting with \
any dialogs, prompts, or windows that appear and seem to be blocking execution.

SCREEN RESOLUTION: {resolution}

AVAILABLE ACTIONS (respond with exactly one per observation):

  WAIT        — The screen shows normal activity, loading, or the sample
                appears to be running. No intervention needed.

  CLICK(x, y) — Left-click at the given pixel coordinates.
                Use for buttons, checkboxes, links.

  TYPE(text)  — Type the given text string.
                Use for password fields, text inputs, file paths.

  KEY(key)    — Press a special key: enter, tab, escape, space, f1-f12,
                up, down, left, right, delete, backspace.
                Use for dismissing dialogs, navigating menus.

  DONE        — The sample appears to be executing normally and no further
                intervention is likely needed. The observation loop will stop.

GUIDELINES:
- Click "Enable Content", "Enable Editing", "Enable Macros" when prompted
- Accept or Allow security warnings and UAC prompts
- Click through installer wizards (Next -> Next -> Install -> Finish)
- If a password prompt appears and you have a hint, type the password
- Do NOT close the malware process itself
- Do NOT click "Don't Run", "Block", "Cancel", or "Disable" on security prompts
- If the screen hasn't changed after your last action, try a different approach
- Coordinates must be within the screen resolution bounds
- Estimate button/element center coordinates from the screenshot

Respond with ONLY a JSON object, no other text:
{{"action": "CLICK", "x": 450, "y": 320, "reasoning": "Brief explanation"}}

For WAIT, KEY, DONE — omit x/y. For TYPE — include "text" instead of x/y.\
"""


class VisionAnalyzer:
    """Sends screenshots to Claude and returns structured actions."""

    def __init__(self, model: str = "claude-sonnet-4-20250514"):
        self._client = anthropic.Anthropic()  # uses ANTHROPIC_API_KEY env var
        self._model = model

    def analyze(
        self,
        screenshot_png: bytes,
        history: list[dict],
        resolution: str = "1920x1080",
        hint: str | None = None,
    ) -> dict:
        """Send a screenshot to Claude and return a parsed action dict.

        Args:
            screenshot_png: PNG image bytes of the current VM screen.
            history: Previous message exchanges (user/assistant pairs).
            resolution: Screen resolution string for the system prompt.
            hint: Optional context about the sample being detonated.

        Returns:
            Parsed action dict with "action", optional "x"/"y"/"text"/"key",
            and "reasoning" fields. Invalid responses return WAIT.
        """
        system = SYSTEM_PROMPT.format(resolution=resolution)
        if hint:
            system += f"\n\nSAMPLE CONTEXT: {hint}"

        # Build the current screenshot message
        b64_image = base64.standard_b64encode(screenshot_png).decode("ascii")
        current_message = {
            "role": "user",
            "content": [
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": "image/png",
                        "data": b64_image,
                    },
                },
                {
                    "type": "text",
                    "text": "What do you see? What action should be taken?",
                },
            ],
        }

        messages = list(history) + [current_message]

        try:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=512,
                system=system,
                messages=messages,
            )
            raw_text = response.content[0].text
            logger.debug("Claude response: %s", raw_text)
            return self._parse_response(raw_text)

        except anthropic.APIError as exc:
            logger.error("Claude API error: %s", exc)
            return {"action": "WAIT", "reasoning": f"API error: {exc}"}

    def _parse_response(self, text: str) -> dict:
        """Parse Claude's JSON response into an action dict."""
        # Strip markdown code fences if present
        cleaned = text.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            # Remove first and last lines (fences)
            cleaned = "\n".join(lines[1:-1] if len(lines) > 2 else lines[1:])

        try:
            parsed = json.loads(cleaned)
            if not isinstance(parsed, dict) or "action" not in parsed:
                raise ValueError("Missing 'action' key")
            return parsed
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning("Failed to parse Claude response: %s — %s", exc, text[:200])
            return {"action": "WAIT", "reasoning": f"Parse error: {text[:100]}"}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_vision.py -v
```

Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add tools/sandbox-pilot/sandbox_pilot/vision.py tools/sandbox-pilot/tests/test_vision.py
git commit -m "feat(sandbox-pilot): add VisionAnalyzer with Claude API and system prompt"
```

---

## Task 6: CLI Entry Point and Main Loop (cli.py)

**Files:**
- Create: `tools/sandbox-pilot/sandbox_pilot/cli.py`
- Create: `tools/sandbox-pilot/tests/test_cli.py`

- [ ] **Step 1: Write failing tests**

Create `tools/sandbox-pilot/tests/test_cli.py`:

```python
"""Tests for the CLI main loop — integration test with all mocks."""

import json
from unittest.mock import MagicMock, patch, call

import pytest

from sandbox_pilot.cli import run_loop, ActionRecord


class TestRunLoop:
    """Test the core observe-decide-act loop."""

    def _make_mocks(self, vision_responses: list[dict]):
        """Create mocked monitor, vision, and heuristics."""
        monitor = MagicMock()
        # screendump writes a fake PPM (just needs to exist for Pillow mock)
        monitor.screendump = MagicMock()

        vision = MagicMock()
        vision.analyze = MagicMock(side_effect=vision_responses)

        heuristics = MagicMock()
        # Default: always analyze
        heuristics.should_analyze = MagicMock(return_value=True)

        return monitor, vision, heuristics

    @patch("sandbox_pilot.cli._take_screenshot", return_value=b"fake_png")
    def test_done_stops_loop(self, mock_screenshot):
        responses = [
            {"action": "DONE", "reasoning": "Sample running"},
        ]
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
        # No API calls made — all skipped by heuristics
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_cli.py -v
```

Expected: `ModuleNotFoundError: No module named 'sandbox_pilot.cli'`

- [ ] **Step 3: Write cli.py**

Create `tools/sandbox-pilot/sandbox_pilot/cli.py`:

```python
"""CLI entry point and main loop for sandbox-pilot.

Usage:
    sandbox-pilot --socket /path/to/qemu-monitor.sock
    sandbox-pilot --socket /path/to/qemu-monitor.sock --hint "Word doc with macros"
"""

import argparse
import io
import logging
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from PIL import Image

from sandbox_pilot.actions import execute_action, parse_action
from sandbox_pilot.heuristics import ScreenChangeDetector
from sandbox_pilot.monitor import QEMUMonitor
from sandbox_pilot.vision import VisionAnalyzer

logger = logging.getLogger("sandbox_pilot")


@dataclass
class ActionRecord:
    """One iteration's result, for the final summary."""

    elapsed: float
    action: str
    reasoning: str
    x: int | None = None
    y: int | None = None
    text: str | None = None
    key: str | None = None

    def __str__(self) -> str:
        mins = int(self.elapsed) // 60
        secs = int(self.elapsed) % 60
        ts = f"[{mins:02d}:{secs:02d}]"

        if self.action == "CLICK" and self.x is not None:
            detail = f"CLICK({self.x}, {self.y})"
        elif self.action == "TYPE" and self.text is not None:
            detail = f"TYPE({self.text!r})"
        elif self.action == "KEY" and self.key is not None:
            detail = f"KEY({self.key})"
        else:
            detail = self.action

        return f"  {ts} {detail} \u2014 {self.reasoning}"


def _take_screenshot(monitor: QEMUMonitor, tmp_dir: Path) -> bytes:
    """Take a screendump and convert PPM -> PNG bytes."""
    ppm_path = str(tmp_dir / "screen.ppm")
    monitor.screendump(ppm_path)
    # Small delay for QEMU to write the file
    time.sleep(0.3)
    img = Image.open(ppm_path)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


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
    """Core observe-decide-act loop.

    Returns a list of ActionRecords for the summary.
    """
    records: list[ActionRecord] = []
    history: list[dict] = []
    start_time = time.monotonic()
    tmp_dir = Path(tempfile.mkdtemp(prefix="sandbox-pilot-"))

    for iteration in range(1, max_iterations + 1):
        elapsed = time.monotonic() - start_time
        if elapsed >= timeout:
            logger.info("Timeout reached (%.0fs)", timeout)
            break

        logger.debug("Iteration %d / %d (%.1fs elapsed)", iteration, max_iterations, elapsed)

        # 1. Screenshot
        try:
            png_bytes = _take_screenshot(monitor, tmp_dir)
        except Exception as exc:
            logger.warning("Screenshot failed: %s — skipping iteration", exc)
            records.append(ActionRecord(elapsed=elapsed, action="WAIT", reasoning=f"Screenshot error: {exc}"))
            time.sleep(interval)
            continue

        # 2. Heuristic filter
        if not heuristics.should_analyze(png_bytes):
            logger.debug("Heuristic: skip API call")
            records.append(ActionRecord(elapsed=elapsed, action="WAIT", reasoning="Heuristic skip"))
            time.sleep(interval)
            continue

        # 3. Claude vision analysis
        raw_action = vision.analyze(png_bytes, history, resolution=resolution, hint=hint)
        action = parse_action(raw_action)

        # 4. Record
        record = ActionRecord(
            elapsed=elapsed,
            action=action["action"],
            reasoning=action.get("reasoning", ""),
            x=action.get("x"),
            y=action.get("y"),
            text=action.get("text"),
            key=action.get("key"),
        )
        records.append(record)

        # 5. Execute
        took_action = execute_action(monitor, action)

        # 6. Update conversation history (keep last 10 exchanges)
        import base64

        history.append({
            "role": "user",
            "content": [
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": "image/png",
                        "data": base64.standard_b64encode(png_bytes).decode("ascii"),
                    },
                },
                {"type": "text", "text": "What do you see? What action should be taken?"},
            ],
        })
        import json

        history.append({
            "role": "assistant",
            "content": json.dumps(action),
        })
        # Trim to last 10 exchanges (20 messages)
        if len(history) > 20:
            history = history[-20:]

        # 7. Reset heuristics after an action so we detect the result
        if took_action:
            heuristics.reset()

        # 8. Check for DONE
        if action["action"] == "DONE":
            logger.info("DONE signal received — stopping")
            break

        time.sleep(interval)

    return records


def _print_summary(records: list[ActionRecord]) -> None:
    """Print a summary of all actions taken."""
    action_count = sum(1 for r in records if r.action in ("CLICK", "TYPE", "KEY"))
    api_count = sum(1 for r in records if r.reasoning != "Heuristic skip")
    print(f"\nsandbox-pilot finished: {len(records)} iterations, {action_count} actions taken, {api_count} API calls")
    for record in records:
        if record.reasoning != "Heuristic skip":
            print(str(record))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AI-assisted malware detonation agent for QEMU sandboxes"
    )
    parser.add_argument(
        "--socket", required=True, help="Path to QEMU monitor Unix socket"
    )
    parser.add_argument(
        "--hint", default=None, help="Context about the sample (e.g., 'Word doc with macros')"
    )
    parser.add_argument(
        "--interval", type=int, default=5, help="Seconds between observations (default: 5)"
    )
    parser.add_argument(
        "--max-iterations", type=int, default=60, help="Max observation cycles (default: 60)"
    )
    parser.add_argument(
        "--timeout", type=int, default=300, help="Total timeout in seconds (default: 300)"
    )
    parser.add_argument(
        "--resolution", default="1920x1080", help="VM screen resolution (default: 1920x1080)"
    )
    parser.add_argument(
        "--model", default="claude-sonnet-4-20250514", help="Claude model for vision analysis"
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Enable debug logging"
    )
    args = parser.parse_args()

    # Logging setup
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    print(f"sandbox-pilot v0.1.0")
    print(f"  Socket:     {args.socket}")
    print(f"  Model:      {args.model}")
    print(f"  Resolution: {args.resolution}")
    print(f"  Interval:   {args.interval}s")
    print(f"  Max iter:   {args.max_iterations}")
    print(f"  Timeout:    {args.timeout}s")
    if args.hint:
        print(f"  Hint:       {args.hint}")
    print()

    # Connect to QEMU monitor
    monitor = QEMUMonitor(args.socket)
    vision = VisionAnalyzer(model=args.model)
    heuristics = ScreenChangeDetector()

    try:
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
        print("\nInterrupted by user")
    finally:
        monitor.close()


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_cli.py -v
```

Expected: All tests pass.

- [ ] **Step 5: Run the full test suite**

```bash
pytest tests/ -v
```

Expected: All tests across all modules pass.

- [ ] **Step 6: Commit**

```bash
git add tools/sandbox-pilot/sandbox_pilot/cli.py tools/sandbox-pilot/tests/test_cli.py
git commit -m "feat(sandbox-pilot): add CLI entry point and main observe-decide-act loop"
```

---

## Task 7: Final Polish

**Files:**
- Verify: all modules work together
- Run: full test suite

- [ ] **Step 1: Run the full test suite one final time**

```bash
cd tools/sandbox-pilot
pytest tests/ -v --tb=short
```

Expected: All tests pass.

- [ ] **Step 2: Verify CLI entry point works**

```bash
sandbox-pilot --help
```

Expected: Help text with all arguments.

- [ ] **Step 3: Verify package imports**

```bash
python -c "
from sandbox_pilot.monitor import QEMUMonitor, QKEY
from sandbox_pilot.heuristics import ScreenChangeDetector
from sandbox_pilot.vision import VisionAnalyzer, SYSTEM_PROMPT
from sandbox_pilot.actions import execute_action, parse_action
from sandbox_pilot.cli import run_loop, ActionRecord, main
print('All imports OK')
"
```

Expected: `All imports OK`

- [ ] **Step 4: Final commit with all tests passing**

```bash
git add -A tools/sandbox-pilot/
git commit -m "feat(sandbox-pilot): complete MVP — AI-assisted malware detonation agent"
```
