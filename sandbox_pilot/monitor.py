"""
QEMUMonitor — connects to a QEMU machine monitor via Unix socket.

Provides keyboard/mouse input and screenshot capability over the QEMU
monitor protocol. Uses a persistent socket connection (no reconnect per
command). Intended for sandbox automation: detonating malware samples and
capturing execution in a controlled QEMU VM.
"""

import logging
import socket
import time

# Delay between keystrokes (seconds). Tuned for reliable VM input reception.
KEY_DELAY = 0.08

# Delay between mouse-button events during a click (seconds).
MOUSE_DELAY = 0.05

# ---------------------------------------------------------------------------
# QKEY: character → QEMU key name mapping
#
# QEMU sendkey uses its own key name vocabulary.  This dict covers printable
# ASCII characters that need special handling.  Plain lowercase letters and
# digits are passed through unchanged (they match QEMU key names directly).
# ---------------------------------------------------------------------------
QKEY: dict[str, str] = {
    # Whitespace / control-ish
    " ":  "spc",
    "\t": "tab",
    "\n": "ret",

    # Punctuation — unshifted
    "/":  "slash",
    "\\":  "backslash",
    "-":  "minus",
    "=":  "equal",
    ".":  "dot",
    ",":  "comma",
    "'":  "apostrophe",
    ";":  "semicolon",
    "[":  "bracket_left",
    "]":  "bracket_right",
    "`":  "grave_accent",

    # Punctuation — shifted (require Shift modifier)
    "_":  "shift-minus",
    "+":  "shift-equal",
    "@":  "shift-2",
    "!":  "shift-1",
    "#":  "shift-3",
    "$":  "shift-4",
    "%":  "shift-5",
    "^":  "shift-6",
    "&":  "shift-7",
    "*":  "shift-8",
    "(":  "shift-9",
    ")":  "shift-0",
    "{":  "shift-bracket_left",
    "}":  "shift-bracket_right",
    "|":  "shift-backslash",
    '"':  "shift-apostrophe",
    ":":  "shift-semicolon",
    "<":  "shift-comma",
    ">":  "shift-dot",
    "?":  "shift-slash",
    "~":  "shift-grave_accent",
}

# Add uppercase A-Z → shift-{lowercase}
for _c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
    QKEY[_c] = f"shift-{_c.lower()}"

# Friendly name → QEMU key name (used by press_key)
_PRESS_KEY_MAP: dict[str, str] = {
    "enter":  "ret",
    "return": "ret",
    "escape": "esc",
    "esc":    "esc",
    "tab":    "tab",
    "space":  "spc",
    "ret":    "ret",
    "spc":    "spc",
}


class QEMUMonitor:
    """
    Thin wrapper around the QEMU text monitor protocol (Unix socket).

    The monitor speaks a line-oriented protocol: you send a command
    terminated by newline; QEMU replies with one or more lines.  The
    connection is established once and reused for all commands.

    Parameters
    ----------
    socket_path:
        Filesystem path of the QEMU monitor Unix socket (e.g. created by
        ``-monitor unix:/tmp/qemu.sock,server,nowait``).
    connect_timeout:
        Total seconds to keep retrying before raising ConnectionError.
        Useful at VM startup when the socket may not yet exist.
    """

    def __init__(self, socket_path: str, connect_timeout: float = 10.0) -> None:
        self._path = socket_path
        self._sock: socket.socket | None = None
        self._connect(connect_timeout)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _connect(self, timeout: float) -> None:
        """Attempt to connect until *timeout* seconds have elapsed."""
        deadline = time.monotonic() + timeout
        last_exc: Exception = Exception("unknown")

        while time.monotonic() < deadline:
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.connect(self._path)
                self._sock = sock
                # Read and discard the QEMU banner (one or more lines ending
                # with the prompt "(qemu) ").  We just drain until we see the
                # prompt string so subsequent reads are aligned.
                self._read_until_prompt()
                return
            except (FileNotFoundError, ConnectionRefusedError, OSError) as exc:
                last_exc = exc
                time.sleep(0.25)

        raise ConnectionError(
            f"Could not connect to QEMU monitor at {self._path!r} "
            f"within {timeout}s: {last_exc}"
        )

    def _read_until_prompt(self) -> str:
        """
        Read bytes from the socket until we see the QEMU prompt '(qemu) '.

        Returns the accumulated text (useful for debugging; not normally
        needed by callers).
        """
        buf = b""
        if self._sock is None:
            raise RuntimeError("Monitor socket is closed")
        self._sock.settimeout(5.0)
        try:
            while True:
                chunk = self._sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if b"(qemu) " in buf:
                    break
        except socket.timeout:
            pass
        finally:
            # Restore blocking mode for subsequent use
            self._sock.settimeout(None)
        return buf.decode("utf-8", errors="replace")

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def send_command(self, cmd: str) -> str:
        """
        Send *cmd* to the QEMU monitor and return the response text.

        A newline is appended automatically.  Sleeps KEY_DELAY seconds after
        sending to give QEMU time to process before the next command.

        Security: newline and carriage-return characters are stripped from
        *cmd* to prevent command injection.  A single monitor command must
        be exactly one line — embedded newlines could inject additional
        monitor commands (e.g. ``quit``, ``migrate``).
        """
        if self._sock is None:
            raise RuntimeError("Monitor socket is closed")
        sanitized = cmd.replace("\n", "").replace("\r", "")
        if sanitized != cmd:
            logging.getLogger(__name__).warning(
                "Stripped newline/CR from monitor command: %r → %r", cmd, sanitized
            )
        self._sock.sendall((sanitized + "\n").encode("utf-8"))
        time.sleep(KEY_DELAY)
        return self._read_until_prompt()

    def sendkey(self, key: str) -> None:
        """Send a single QEMU key-name (e.g. 'shift-h', 'ret', 'spc')."""
        self.send_command(f"sendkey {key}")

    def type_string(self, text: str) -> None:
        """
        Type *text* into the VM character by character.

        Each character is looked up in QKEY; plain lowercase letters and
        digits are sent as-is since they match QEMU key names directly.
        Unrecognised characters are silently skipped.
        """
        for ch in text:
            key = QKEY.get(ch)
            if key is None:
                # Plain lowercase letter or digit — QEMU accepts them directly
                if ch.isalnum() and ch == ch.lower():
                    key = ch
                else:
                    # Unknown character; skip rather than send garbage
                    continue
            self.sendkey(key)

    def press_key(self, key: str) -> None:
        """
        Press a key using a friendly name.

        Recognised friendly names: enter, return, escape/esc, tab, space.
        Any other value is forwarded to sendkey unchanged (allows passing
        raw QEMU key names like 'f1', 'ctrl-alt-del', etc.).
        """
        qkey = _PRESS_KEY_MAP.get(key.lower(), key)
        self.sendkey(qkey)

    def mouse_move(self, x: int, y: int) -> None:
        """Move the mouse cursor to absolute coordinates (*x*, *y*)."""
        self.send_command(f"mouse_move {x} {y}")

    def mouse_click(self, x: int, y: int, button: int = 1) -> None:
        """
        Click mouse *button* (default 1 = left) at position (*x*, *y*).

        Sequence: move → button-down → small delay → button-up.
        """
        self.mouse_move(x, y)
        time.sleep(MOUSE_DELAY)
        self.send_command(f"mouse_button {button}")
        time.sleep(MOUSE_DELAY)
        self.send_command("mouse_button 0")

    def screendump(self, path: str) -> None:
        """Save a screenshot of the VM display to *path* on the host."""
        self.send_command(f"screendump {path}")

    def __enter__(self) -> "QEMUMonitor":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the monitor connection."""
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
