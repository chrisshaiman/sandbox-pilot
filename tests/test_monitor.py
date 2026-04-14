"""
Tests for sandbox_pilot.monitor.QEMUMonitor.

Uses a FakeMonitor — a minimal Unix socket server running in a background
thread — to simulate QEMU monitor responses without a real VM.  The server
sends a QEMU-style banner on connect and records every command line received.
"""

import socket
import sys
import threading
import time
from pathlib import Path

import pytest

# QEMUMonitor uses Unix sockets — skip the entire module on platforms without them.
pytestmark = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"),
    reason="Unix sockets not available on this platform",
)

from sandbox_pilot.monitor import QKEY, QEMUMonitor

# ---------------------------------------------------------------------------
# FakeMonitor helper
# ---------------------------------------------------------------------------

BANNER = b"QEMU 8.2.0 monitor - type 'help' for more information\r\n(qemu) "


class FakeMonitor:
    """
    Minimal Unix socket server that mimics the QEMU text monitor.

    - Binds to a Unix socket at *socket_path*.
    - Accepts exactly one connection (the QEMUMonitor client).
    - Sends BANNER immediately on connect.
    - For every newline-terminated line received, appends it (stripped) to
      ``commands`` and sends a "(qemu) " prompt back so the client
      unblocks.
    - Runs in a daemon thread so it does not prevent test teardown.
    """

    def __init__(self, socket_path: str) -> None:
        self.socket_path = socket_path
        self.commands: list[str] = []
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(socket_path)
        self._server.listen(1)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        try:
            conn, _ = self._server.accept()
        except OSError:
            return  # Server was closed before a connection arrived
        with conn:
            conn.sendall(BANNER)
            buf = b""
            while True:
                try:
                    chunk = conn.recv(4096)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    cmd = line.decode("utf-8", errors="replace").strip()
                    if cmd:
                        self.commands.append(cmd)
                    # Echo the QEMU prompt so QEMUMonitor's read_until_prompt
                    # returns promptly.
                    try:
                        conn.sendall(b"(qemu) ")
                    except OSError:
                        return

    def stop(self) -> None:
        try:
            self._server.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def fake_server(tmp_path: Path):
    """Yield a running FakeMonitor; stop it after the test."""
    sock_path = str(tmp_path / "qemu.sock")
    server = FakeMonitor(sock_path)
    yield server
    server.stop()


@pytest.fixture()
def mon(fake_server: FakeMonitor):
    """Yield a connected QEMUMonitor; close it after the test."""
    monitor = QEMUMonitor(fake_server.socket_path)
    yield monitor
    time.sleep(0.2)   # let fake server finish processing buffered commands
    monitor.close()


# ---------------------------------------------------------------------------
# Tests — connection
# ---------------------------------------------------------------------------

def test_connect_and_close(fake_server: FakeMonitor, tmp_path: Path) -> None:
    """QEMUMonitor connects without error and closes cleanly."""
    monitor = QEMUMonitor(fake_server.socket_path)
    time.sleep(0.2)
    monitor.close()


def test_connect_bad_path_raises(tmp_path: Path) -> None:
    """Connecting to a non-existent socket raises ConnectionError."""
    bad_path = str(tmp_path / "no_such.sock")
    with pytest.raises(ConnectionError):
        # Short timeout so the test doesn't hang
        QEMUMonitor(bad_path, connect_timeout=0.5)


# ---------------------------------------------------------------------------
# Tests — sendkey
# ---------------------------------------------------------------------------

def test_sendkey_letter(mon: QEMUMonitor, fake_server: FakeMonitor) -> None:
    """sendkey('a') transmits 'sendkey a'."""
    mon.sendkey("a")
    time.sleep(0.2)
    assert "sendkey a" in fake_server.commands


def test_sendkey_ret(mon: QEMUMonitor, fake_server: FakeMonitor) -> None:
    """sendkey('ret') transmits 'sendkey ret'."""
    mon.sendkey("ret")
    time.sleep(0.2)
    assert "sendkey ret" in fake_server.commands


# ---------------------------------------------------------------------------
# Tests — type_string
# ---------------------------------------------------------------------------

def test_type_string_mixed_case(mon: QEMUMonitor, fake_server: FakeMonitor) -> None:
    """type_string('Hi') sends shift-h then i."""
    mon.type_string("Hi")
    time.sleep(0.2)
    assert "sendkey shift-h" in fake_server.commands
    assert "sendkey i" in fake_server.commands
    # Order check: shift-h must precede i
    assert fake_server.commands.index("sendkey shift-h") < fake_server.commands.index("sendkey i")


def test_type_string_at_sign(mon: QEMUMonitor, fake_server: FakeMonitor) -> None:
    """type_string('@') sends 'sendkey shift-2'."""
    mon.type_string("@")
    time.sleep(0.2)
    assert "sendkey shift-2" in fake_server.commands


# ---------------------------------------------------------------------------
# Tests — press_key
# ---------------------------------------------------------------------------

def test_press_key_enter(mon: QEMUMonitor, fake_server: FakeMonitor) -> None:
    """press_key('enter') sends 'sendkey ret'."""
    mon.press_key("enter")
    time.sleep(0.2)
    assert "sendkey ret" in fake_server.commands


def test_press_key_tab(mon: QEMUMonitor, fake_server: FakeMonitor) -> None:
    """press_key('tab') sends 'sendkey tab'."""
    mon.press_key("tab")
    time.sleep(0.2)
    assert "sendkey tab" in fake_server.commands


def test_press_key_escape(mon: QEMUMonitor, fake_server: FakeMonitor) -> None:
    """press_key('escape') sends 'sendkey esc'."""
    mon.press_key("escape")
    time.sleep(0.2)
    assert "sendkey esc" in fake_server.commands


# ---------------------------------------------------------------------------
# Tests — mouse
# ---------------------------------------------------------------------------

def test_mouse_move(mon: QEMUMonitor, fake_server: FakeMonitor) -> None:
    """mouse_move(100, 200) sends 'mouse_move 100 200'."""
    mon.mouse_move(100, 200)
    time.sleep(0.2)
    assert "mouse_move 100 200" in fake_server.commands


def test_mouse_click(mon: QEMUMonitor, fake_server: FakeMonitor) -> None:
    """mouse_click(450, 320) sends move, button-down, button-up in order."""
    mon.mouse_click(450, 320)
    time.sleep(0.5)   # three commands — give fake server time to process all
    assert "mouse_move 450 320" in fake_server.commands
    assert "mouse_button 1" in fake_server.commands
    assert "mouse_button 0" in fake_server.commands
    # Order: move → button 1 → button 0
    idx_move = fake_server.commands.index("mouse_move 450 320")
    idx_down = fake_server.commands.index("mouse_button 1")
    idx_up   = fake_server.commands.index("mouse_button 0")
    assert idx_move < idx_down < idx_up


# ---------------------------------------------------------------------------
# Tests — screendump
# ---------------------------------------------------------------------------

def test_screendump(mon: QEMUMonitor, fake_server: FakeMonitor, tmp_path: Path) -> None:
    """screendump sends 'screendump /some/path'."""
    out_path = str(tmp_path / "screen.ppm")
    mon.screendump(out_path)
    time.sleep(0.2)
    assert f"screendump {out_path}" in fake_server.commands


# ---------------------------------------------------------------------------
# Tests — QKEY completeness
# ---------------------------------------------------------------------------

def test_qkey_uppercase_a_to_z() -> None:
    """All 26 uppercase letters map to 'shift-{lower}'."""
    for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        expected = f"shift-{ch.lower()}"
        assert QKEY.get(ch) == expected, f"QKEY[{ch!r}] should be {expected!r}"


def test_qkey_space() -> None:
    assert QKEY[" "] == "spc"


def test_qkey_at_sign() -> None:
    assert QKEY["@"] == "shift-2"


def test_qkey_open_brace() -> None:
    assert QKEY["{"] == "shift-bracket_left"


def test_qkey_pipe() -> None:
    assert QKEY["|"] == "shift-backslash"


# ---------------------------------------------------------------------------
# Security: newline injection prevention
# ---------------------------------------------------------------------------


def test_send_command_strips_newlines(mon: QEMUMonitor, fake_server: FakeMonitor) -> None:
    """Embedded newlines in commands must be stripped to prevent command injection."""
    mon.send_command("sendkey a\nquit")
    time.sleep(0.3)
    # Newline stripped — "quit" merged into single command, not executed separately
    assert "sendkey aquit" in fake_server.commands
    assert len(fake_server.commands) == 1  # only ONE command sent, not two


def test_send_command_strips_carriage_return(mon: QEMUMonitor, fake_server: FakeMonitor) -> None:
    """Carriage returns must also be stripped."""
    mon.send_command("sendkey b\r\nquit")
    time.sleep(0.3)
    assert "sendkey bquit" in fake_server.commands
    assert len(fake_server.commands) == 1
