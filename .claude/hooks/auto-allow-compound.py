#!/usr/bin/env python3
"""
PreToolUse hook: auto-approve a compound Bash command when every sub-command
is individually allowed by the project's permissions.allow list.

Triggered on Bash tool calls. Splits the command on top-level |, ||, &&, and
; operators (quote-aware). For each sub-command it looks up the command
prefix against every Bash(...) entry in the project's permissions.allow.

Emits {"permissionDecision": "allow"} only when every sub-command matches an
allow pattern AND no sub-command matches a deny pattern.

Deliberately conservative — on any parse ambiguity (unclosed quotes, command
substitution, heredocs) it exits silently and lets the normal permission
flow prompt the user.
"""

import json
import re
import shlex
import sys
from pathlib import Path

# Project settings files, in merge order (later overrides earlier).
SETTINGS_FILES = [
    Path(".claude/settings.json"),
    Path(".claude/settings.local.json"),
]

# Patterns that, if present anywhere in the command, disable auto-allow
# because the embedded command cannot be reliably decomposed.
UNSAFE_PATTERNS = (
    "$(",   # command substitution
    "`",    # backtick substitution
    "<(",   # process substitution
    ">(",   # process substitution
    "<<",   # heredoc
)


def load_rules():
    allow, deny = [], []
    for p in SETTINGS_FILES:
        if not p.exists():
            continue
        try:
            data = json.loads(p.read_text())
        except json.JSONDecodeError:
            continue
        perms = data.get("permissions") or {}
        allow += perms.get("allow") or []
        deny += perms.get("deny") or []
    return allow, deny


def extract_bash_prefix(pattern):
    """Parse a Bash(...) permission rule into (prefix, allow_any_args)."""
    m = re.match(r"^Bash\((.*)\)$", pattern)
    if not m:
        return None
    inner = m.group(1)
    if inner.endswith(":*"):
        return inner[:-2].strip(), True
    if inner.endswith(" *"):
        return inner[:-2].strip(), True
    return inner.strip(), False


def subcmd_matches(subcmd_tokens, patterns):
    """Return True if tokens match any Bash(...) pattern in the list."""
    for pat in patterns:
        ext = extract_bash_prefix(pat)
        if ext is None:
            continue
        prefix, any_args = ext
        prefix_tokens = prefix.split()
        if not prefix_tokens or len(prefix_tokens) > len(subcmd_tokens):
            continue
        if subcmd_tokens[: len(prefix_tokens)] != prefix_tokens:
            continue
        if any_args or len(subcmd_tokens) == len(prefix_tokens):
            return True
    return False


def split_compound(cmd):
    """Split on top-level |, ||, &&, ;. Quote-aware; respects \\ escapes."""
    parts = []
    buf = []
    i = 0
    in_single = False
    in_double = False
    n = len(cmd)
    while i < n:
        c = cmd[i]
        if c == "\\" and i + 1 < n:
            buf.append(c)
            buf.append(cmd[i + 1])
            i += 2
            continue
        if c == "'" and not in_double:
            in_single = not in_single
            buf.append(c)
            i += 1
            continue
        if c == '"' and not in_single:
            in_double = not in_double
            buf.append(c)
            i += 1
            continue
        if not in_single and not in_double:
            if c == "|" and i + 1 < n and cmd[i + 1] == "|":
                parts.append("".join(buf).strip())
                buf = []
                i += 2
                continue
            if c == "&" and i + 1 < n and cmd[i + 1] == "&":
                parts.append("".join(buf).strip())
                buf = []
                i += 2
                continue
            if c == "|":
                parts.append("".join(buf).strip())
                buf = []
                i += 1
                continue
            if c == ";":
                parts.append("".join(buf).strip())
                buf = []
                i += 1
                continue
        buf.append(c)
        i += 1
    if buf:
        parts.append("".join(buf).strip())
    return [p for p in parts if p]


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return
    if payload.get("tool_name") != "Bash":
        return
    cmd = (payload.get("tool_input") or {}).get("command", "")
    if not cmd.strip():
        return

    # Bail on any construct whose embedded commands we cannot decompose.
    if any(pat in cmd for pat in UNSAFE_PATTERNS):
        return

    subs = split_compound(cmd)
    if len(subs) <= 1:
        # Single command — the harness's existing allowlist already covers it.
        return

    allow, deny = load_rules()

    for sub in subs:
        try:
            tokens = shlex.split(sub)
        except ValueError:
            # Unparseable sub-command — let normal flow decide.
            return
        if not tokens:
            return
        if subcmd_matches(tokens, deny):
            return
        if not subcmd_matches(tokens, allow):
            return

    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason": (
                f"compound command: all {len(subs)} sub-commands match allow patterns"
            ),
        }
    }
    print(json.dumps(out))


if __name__ == "__main__":
    main()
