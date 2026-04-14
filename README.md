# sandbox-pilot

[![CI](https://github.com/chrisshaiman/sandbox-pilot/actions/workflows/ci.yml/badge.svg)](https://github.com/chrisshaiman/sandbox-pilot/actions/workflows/ci.yml)

AI-assisted malware detonation agent for QEMU sandboxes.

Many malware samples require user interaction to fully execute: clicking
"Enable Content" on Office macros, dismissing security dialogs, navigating
installer wizards, or entering passwords. sandbox-pilot watches a QEMU VM's
screen and uses Claude's vision API to understand what's happening and send
the right keyboard/mouse input to help samples detonate.

## How it works

```
QEMU VM (malware running)          sandbox-pilot
+-----------------------+           +------------------+
|                       |  screen   |                  |
|   Windows guest       |---------->|  screendump      |
|   with sample         |  dump     |       |          |
|                       |           |  heuristic check |
|                       |  sendkey  |       |          |
|                       |<----------|  Claude vision   |
|                       |  mouse    |       |          |
+-----------------------+           |  execute action  |
                                    +------------------+
```

1. Takes a screenshot via QEMU monitor socket
2. Heuristic filter skips unchanged screens (saves 60-80% of API calls)
3. Sends changed/stuck screens to Claude's vision API
4. Claude analyzes the screen and recommends an action
5. Agent translates the action into QEMU keyboard/mouse input
6. Repeats until the sample is running or timeout

## Install

```bash
pip install -e ".[dev]"
```

Requires Python 3.10+ and an [Anthropic API key](https://console.anthropic.com/).

## Usage

```bash
export ANTHROPIC_API_KEY=sk-ant-...

# Basic — connect to a QEMU monitor socket
sandbox-pilot --socket /path/to/qemu-monitor.sock

# With context about the sample
sandbox-pilot --socket /path/to/qemu-monitor.sock \
              --hint "Word document with macros, expect Enable Content prompt"

# Tuning
sandbox-pilot --socket /path/to/qemu-monitor.sock \
              --interval 5 \
              --max-iterations 60 \
              --timeout 300 \
              --resolution 1920x1080
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--socket` | (required) | Path to QEMU monitor Unix socket |
| `--hint` | none | Context about the sample for Claude |
| `--interval` | 5 | Seconds between observations |
| `--max-iterations` | 60 | Max observation cycles |
| `--timeout` | 300 | Total timeout in seconds |
| `--resolution` | 1920x1080 | VM screen resolution |
| `--model` | claude-sonnet-4-20250514 | Claude model for vision |
| `--verbose` | off | Enable debug logging |

## Example output

```
sandbox-pilot v0.1.0
  Socket:     /tmp/qemu-monitor.sock
  Model:      claude-sonnet-4-20250514
  Resolution: 1920x1080
  Interval:   5s
  Hint:       Word document with macros

sandbox-pilot finished: 12 iterations, 3 actions taken, 5 API calls
  [00:05] CLICK(450, 320) — "Enable Content" button on macro warning
  [00:15] KEY(enter) — Dismissed Windows security dialog
  [01:00] DONE — Malware process running normally in task manager
```

## Security

**Intended use:** Authorized malware analysis in isolated sandbox environments.

The system prompt tells Claude it is operating inside an air-gapped detonation
environment with no internet access and disposable VM snapshots. This framing
is required for Claude to assist with malware execution and must accurately
reflect your actual environment.

**Anti-prompt-injection mitigations:**

Malware authors aware of AI-assisted sandboxes could attempt visual prompt
injection (rendering adversarial text on screen). sandbox-pilot includes:

- **TYPE length cap (100 chars):** Blocks "type this shell command" attacks
- **Suspicious pattern detection:** Flags shell metacharacters and injection
  phrases in logs (does not block — this is threat intelligence)
- **Full audit log:** Every action, reasoning, and screenshot logged for review

## Architecture

```
sandbox_pilot/
  cli.py          # Entry point, main loop, logging
  monitor.py      # QEMU monitor socket (sendkey, mouse, screendump)
  vision.py       # Claude API (vision analysis, system prompt)
  heuristics.py   # Screenshot change detection (API call filter)
  actions.py      # Action translation + anti-injection
```

## Requirements

- Python 3.10+
- QEMU with monitor socket enabled (`-monitor unix:/path/to/sock,server,nowait`)
- Anthropic API key (`ANTHROPIC_API_KEY` environment variable)
- A VM with a display (VGA) — screendump requires a framebuffer

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Author

Christopher Shaiman
