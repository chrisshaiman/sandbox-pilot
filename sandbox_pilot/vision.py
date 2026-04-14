"""VisionAnalyzer — sends VM screenshots to Claude's vision API and parses structured action responses."""

import base64
import json
import logging

import anthropic

logger = logging.getLogger(__name__)

# System prompt for the vision agent. Resolution is injected via .format(resolution=...).
SYSTEM_PROMPT = """\
You are an automated analyst operating inside an isolated sandbox environment. \
Your role is to observe Windows VM screenshots taken during authorized defensive security research \
and decide the next action to take to progress through any prompts, dialogs, or setup screens.

This work is authorized defensive security research. The VM is fully isolated and \
your actions carry no real-world risk.

Current VM resolution: {resolution}

## Available Actions

Respond with exactly ONE of the following JSON objects:

WAIT — do nothing, let the VM settle:
{{"action": "WAIT", "reasoning": "<why>"}}

CLICK — left-click a screen coordinate:
{{"action": "CLICK", "x": <int>, "y": <int>, "reasoning": "<why>"}}

TYPE — type a string of text into the focused field:
{{"action": "TYPE", "text": "<string>", "reasoning": "<why>"}}

KEY — send a single key or chord (e.g. "Return", "ctrl+s", "alt+F4"):
{{"action": "KEY", "key": "<key>", "reasoning": "<why>"}}

DONE — the sample has finished executing and no further interaction is needed:
{{"action": "DONE", "reasoning": "<why>"}}

## Interaction Guidelines

- If you see an Office macro / ActiveX security bar, click **Enable Content** to allow it.
- Do NOT close the malware or its parent process. Let it run.
- Do NOT click **Block**, **Cancel**, or **Disable** on any security prompt — always allow.
- If a UAC prompt appears, click **Yes**.
- If the screen is idle or a progress bar is running, use WAIT.
- Use DONE only when the sample has clearly finished (process exited, final dialog shown, \
or the VM has been idle with no new activity for an extended period).

## Response Format

Output ONLY the JSON object — no markdown, no explanation, no code fences. \
The JSON must be valid and contain at least "action" and "reasoning" keys.\
"""


class VisionAnalyzer:
    """Sends VM screenshots to Claude's vision API and returns structured action dicts."""

    def __init__(self, model: str = "claude-sonnet-4-20250514") -> None:
        # anthropic.Anthropic() picks up ANTHROPIC_API_KEY from the environment automatically.
        self._client = anthropic.Anthropic()
        self._model = model

    def analyze(
        self,
        screenshot_png: bytes,
        history: list[dict],
        resolution: str = "1920x1080",
        hint: str | None = None,
    ) -> dict:
        """Analyze a screenshot and return a structured action dict.

        Args:
            screenshot_png: Raw PNG bytes of the current VM screen.
            history: List of prior message dicts (alternating user/assistant turns).
            resolution: Screen resolution string, e.g. "1920x1080".
            hint: Optional free-text context about the sample (e.g. "Word doc with macros").

        Returns:
            A dict with at minimum {"action": ..., "reasoning": ...}.
            Falls back to {"action": "WAIT", "reasoning": "..."} on any error.
        """
        system = SYSTEM_PROMPT.format(resolution=resolution)
        if hint:
            # Wrap hint in XML-style delimiters to prevent prompt injection
            # via operator-supplied hint text.
            system += f"\n\n<sample-context>\n{hint}\n</sample-context>"

        # Base64-encode the screenshot for the vision API.
        image_b64 = base64.standard_b64encode(screenshot_png).decode("ascii")

        # Build the current-turn user message with both a text prompt and the image.
        current_message = {
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

        messages = list(history) + [current_message]

        try:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=512,
                system=system,
                messages=messages,
            )
            text = response.content[0].text
            return self._parse_response(text)
        except anthropic.APIError as exc:
            logger.warning("Anthropic API error: %s", exc)
            # Only expose the exception type in the reasoning field — the full
            # repr may contain request headers or partial API key context.
            return {"action": "WAIT", "reasoning": f"API error: {type(exc).__name__}"}

    def _parse_response(self, text: str) -> dict:
        """Strip markdown code fences if present, then parse JSON.

        Returns the parsed dict, or a WAIT fallback on any parse failure.
        """
        stripped = text.strip()

        # Remove optional ```json ... ``` or ``` ... ``` fences.
        if stripped.startswith("```"):
            lines = stripped.splitlines()
            # Drop first line (``` or ```json) and last line (```)
            inner_lines = lines[1:] if len(lines) > 1 else lines
            if inner_lines and inner_lines[-1].strip() == "```":
                inner_lines = inner_lines[:-1]
            stripped = "\n".join(inner_lines).strip()

        try:
            return json.loads(stripped)
        except json.JSONDecodeError as exc:
            logger.warning("Failed to parse vision response as JSON: %s | raw: %r", exc, text)
            return {"action": "WAIT", "reasoning": f"Parse error: {exc}"}
