"""
Action translator for sandbox-pilot.

Parses Claude vision API response dicts into structured action records and
dispatches those actions to a QEMUMonitor instance.

Anti-prompt-injection mitigations
----------------------------------
Claude operates inside a closed loop where the only input it sees is a VM
screenshot.  A malicious payload rendered on screen could try to hijack the
agent by embedding instructions such as "now type: rm -rf /" or
"instructions on screen told me to press Enter".  Two layers of defence are
implemented here:

1. _check_suspicious() scans the action's text payload *and* Claude's own
   reasoning field for known injection signatures.  If a match is found,
   suspicious=True is added to the action dict.

2. execute_action() logs a WARNING before acting on any suspicious action so
   operators can detect and investigate injection attempts in log output.
   (A future hardening pass could refuse to execute suspicious actions
   entirely; for now we log-and-continue so the sandbox doesn't stall.)
"""

import logging
import re

from sandbox_pilot.monitor import QEMUMonitor

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Valid action names that Claude may return.
_VALID_ACTIONS = {"CLICK", "TYPE", "KEY", "WAIT", "DONE"}

# Maximum number of characters allowed in a TYPE action's text field.
# Exceeding this is treated as a likely injection or model hallucination.
MAX_TYPE_LENGTH = 100

# Patterns matched against text payloads (TYPE text, KEY key name).
# Any match sets suspicious=True.
_SUSPICIOUS_TEXT_PATTERNS: list[re.Pattern] = [
    re.compile(r"[|;&]",              re.IGNORECASE),
    re.compile(r"[>]{1,2}\s*/",       re.IGNORECASE),  # output redirection
    re.compile(r"powershell\s+-",     re.IGNORECASE),
    re.compile(r"cmd\s*/c",           re.IGNORECASE),
    re.compile(r"wget\s+",            re.IGNORECASE),
    re.compile(r"curl\s+",            re.IGNORECASE),
    re.compile(r"certutil\s+",        re.IGNORECASE),  # Windows download/decode
    re.compile(r"bitsadmin\s+",       re.IGNORECASE),  # Windows download
    re.compile(r"net\s+(?:user|localgroup)\s+", re.IGNORECASE),  # account manipulation
    re.compile(r"reg\s+(?:add|delete)\s+",      re.IGNORECASE),  # registry manipulation
    re.compile(r"schtasks\s+",        re.IGNORECASE),  # persistence
    re.compile(r"wscript\s+",         re.IGNORECASE),
    re.compile(r"cscript\s+",         re.IGNORECASE),
]

# Patterns matched against Claude's reasoning string.
# These catch prompt-injection attempts that leak into the model's explanation.
_SUSPICIOUS_REASONING_PATTERNS: list[re.Pattern] = [
    re.compile(r"instructions?\s+on\s+screen",                        re.IGNORECASE),
    re.compile(r"text\s+(?:on\s+screen\s+)?(?:told|asked|says|instructs)", re.IGNORECASE),
    re.compile(r"(?:the\s+)?screen\s+says\s+to",                     re.IGNORECASE),
    re.compile(r"following\s+(?:the\s+)?on-?screen\s+instructions?",  re.IGNORECASE),
    re.compile(r"as\s+directed\s+by\s+(?:the\s+)?text",              re.IGNORECASE),
    re.compile(r"ignore\s+previous",                                  re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _check_suspicious(action: dict) -> dict:
    """
    Inspect *action* for prompt-injection signals.

    Checks:
    - The 'text' field (TYPE actions) against _SUSPICIOUS_TEXT_PATTERNS.
    - The 'key' field (KEY actions) against _SUSPICIOUS_TEXT_PATTERNS.
    - The 'reasoning' field against _SUSPICIOUS_REASONING_PATTERNS.

    Returns the action dict with suspicious=True added if any pattern matches.
    The dict is modified in-place and also returned for convenience.
    """
    # Check text/key payload fields
    for field in ("text", "key"):
        value = action.get(field, "")
        if isinstance(value, str):
            for pattern in _SUSPICIOUS_TEXT_PATTERNS:
                if pattern.search(value):
                    action["suspicious"] = True
                    logger.debug(
                        "Suspicious text pattern matched in field %r: %r", field, value
                    )
                    break

    # Check reasoning field for prompt-injection signals
    reasoning = action.get("reasoning", "")
    if isinstance(reasoning, str):
        for pattern in _SUSPICIOUS_REASONING_PATTERNS:
            if pattern.search(reasoning):
                action["suspicious"] = True
                logger.debug(
                    "Suspicious reasoning pattern matched: %r", reasoning
                )
                break

    return action


def _safe_wait(reasoning: str = "") -> dict:
    """Return a WAIT action dict, carrying *reasoning* through."""
    return {"action": "WAIT", "reasoning": reasoning}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_action(raw: dict) -> dict:
    """
    Parse a raw dict from Claude's vision API response into a validated action.

    Expected raw shape (examples)::

        {"action": "CLICK",  "x": 640, "y": 480, "reasoning": "..."}
        {"action": "TYPE",   "text": "malware.exe", "reasoning": "..."}
        {"action": "KEY",    "key": "enter", "reasoning": "..."}
        {"action": "WAIT",   "reasoning": "..."}
        {"action": "DONE",   "reasoning": "..."}

    Validation rules
    ----------------
    - Unknown or missing action → WAIT.
    - CLICK missing x or y → WAIT.
    - TYPE text longer than MAX_TYPE_LENGTH → WAIT with suspicious=True and
      a reasoning string that mentions "too long".
    - All valid actions pass through _check_suspicious() before being returned.

    Parameters
    ----------
    raw:
        Dict as returned by the Claude API (after JSON parsing).

    Returns
    -------
    dict
        Normalised action dict with at least ``{"action": "<NAME>"}``.
        May include ``suspicious=True`` and a ``reasoning`` string.
    """
    action_name = raw.get("action")
    if not isinstance(action_name, str) or action_name.upper() not in _VALID_ACTIONS:
        return _safe_wait(reasoning=f"unknown or missing action: {action_name!r}")

    action_name = action_name.upper()
    reasoning = raw.get("reasoning", "")

    # --- CLICK ---
    if action_name == "CLICK":
        x = raw.get("x")
        y = raw.get("y")
        if x is None or y is None:
            return _safe_wait(reasoning="CLICK missing x or y coordinate")
        result = {"action": "CLICK", "x": x, "y": y, "reasoning": reasoning}
        return _check_suspicious(result)

    # --- TYPE ---
    if action_name == "TYPE":
        text = raw.get("text", "")
        if len(str(text)) > MAX_TYPE_LENGTH:
            return {
                "action": "WAIT",
                "suspicious": True,
                "reasoning": f"TYPE text too long ({len(str(text))} chars > {MAX_TYPE_LENGTH})",
            }
        result = {"action": "TYPE", "text": text, "reasoning": reasoning}
        return _check_suspicious(result)

    # --- KEY ---
    if action_name == "KEY":
        key = raw.get("key", "")
        result = {"action": "KEY", "key": key, "reasoning": reasoning}
        return _check_suspicious(result)

    # --- WAIT ---
    if action_name == "WAIT":
        result = {"action": "WAIT", "reasoning": reasoning}
        return _check_suspicious(result)

    # --- DONE ---
    # DONE carries no payload; still run suspicious check on reasoning.
    result = {"action": "DONE", "reasoning": reasoning}
    return _check_suspicious(result)


def execute_action(monitor: QEMUMonitor, action: dict) -> bool:
    """
    Execute a parsed action against *monitor*.

    Parameters
    ----------
    monitor:
        Connected QEMUMonitor instance.
    action:
        Dict previously returned by parse_action().

    Returns
    -------
    bool
        True if a VM input command was sent (CLICK, TYPE, KEY).
        False for WAIT and DONE (no input sent).

    Side effects
    ------------
    - Logs a WARNING before executing any action where ``action.get("suspicious")``
      is truthy so operators can detect potential prompt-injection attempts.
    """
    if action.get("suspicious"):
        logger.warning(
            "Suspicious action detected — executing anyway: %r", action
        )

    name = action.get("action")

    if name == "CLICK":
        monitor.mouse_click(action["x"], action["y"])
        return True

    if name == "TYPE":
        monitor.type_string(action["text"])
        return True

    if name == "KEY":
        monitor.press_key(action["key"])
        return True

    # WAIT and DONE: nothing to send to the VM.
    return False
