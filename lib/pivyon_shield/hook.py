"""Claude Code PreToolUse hook: vet packages before Bash installs them or an
edit adds them to a manifest. Reads the hook JSON on stdin, prints a decision.

It fails open on every internal problem: no output means "no opinion".
"""

from __future__ import annotations

import json
import os
import sys
from typing import List, Optional

from . import config, manifests
from .commands import Context, Request, dedupe, packages_in_command
from .policy import RANK, Verdict, evaluate_all

MAX_PACKAGES = 25  # beyond this (e.g. a 200-line requirements file) check the first N


def requests_for(payload: dict, cfg=None) -> List[Request]:
    tool = payload.get("tool_name") or ""
    tin = payload.get("tool_input") or {}
    cwd = payload.get("cwd") or os.getcwd()
    ctx = Context(cwd, cfg=cfg)
    if tool == "Bash":
        return packages_in_command(tin.get("command") or "", ctx)
    if tool in ("Write", "Edit", "MultiEdit"):
        path = tin.get("file_path") or ""
        if not manifests.parser_for(path):
            return []
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                before = fh.read()
        except OSError:
            before = ""
        after = manifests.apply_edit(tool, tin, before)
        if after is None:
            return []
        ctx = Context(os.path.dirname(path) or cwd, cfg=cfg)
        out = []
        for (eco, name), ver in manifests.added_or_changed(path, before, after).items():
            custom = (eco == "npm" and (ctx.npm_custom_registry or ctx.npm_scope_private(name))) or (
                eco == "PyPI" and ctx.pypi_custom_index)
            if eco == "Go" and ctx.go_private(name):
                continue
            out.append(Request(eco, name, ver, os.path.basename(path), custom, False))
        return dedupe(out)
    return []


def _bullet(v: Verdict, levels) -> List[str]:
    return ["- %s: %s" % (v.label, f.message) for f in v.findings if f.level in levels]


def decide(verdicts: List[Verdict], mode: str) -> Optional[dict]:
    if not verdicts:
        return None
    worst = min((v.level for v in verdicts), key=lambda lvl: RANK[lvl])
    blocking = [b for v in verdicts for b in _bullet(v, ("block",))]
    confirming = [b for v in verdicts for b in _bullet(v, ("confirm",))]
    warnings = [b for v in verdicts for b in _bullet(v, ("warn",))]
    fixes = ["- %s: upgrade to %s" % (v.request.name, v.fix_version) for v in verdicts if v.fix_version]

    out: dict = {"hookEventName": "PreToolUse"}
    if mode == "enforce" and worst == "block":
        out["permissionDecision"] = "deny"
        out["permissionDecisionReason"] = "\n".join(
            ["pivyon-shield blocked this install:"] + blocking + confirming
            + ["", "Do not retry with guessed spellings. Look up the correct package name in the "
               "library's official documentation, or tell the user why it was blocked. A person can "
               "allow a package in .pivyon-shield.json (\"allow\": [\"npm:name\"])."]
        )
        return {"hookSpecificOutput": out}
    if mode == "enforce" and worst == "confirm":
        out["permissionDecision"] = "ask"
        out["permissionDecisionReason"] = "\n".join(["pivyon-shield wants a human to check:"] + confirming)
        context = confirming + warnings
        if fixes:
            context += ["Safer versions:"] + fixes
        out["additionalContext"] = "pivyon-shield findings:\n" + "\n".join(context)
        return {"hookSpecificOutput": out}
    notes = blocking + confirming + warnings
    if mode != "enforce":
        notes = [n.replace("- ", "- [would %s] " % ("block" if n in blocking else "ask"), 1)
                 if n in blocking or n in confirming else n for n in notes]
    if fixes:
        notes += ["Safer versions:"] + fixes
    if not notes:
        return None  # clean, or offline: stay silent rather than nag on every install
    out["additionalContext"] = "pivyon-shield findings (install allowed):\n" + "\n".join(notes)
    return {"hookSpecificOutput": out}


def main(stdin=None, stdout=None) -> int:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    try:
        payload = json.load(stdin)
    except ValueError:
        return 0
    try:
        cwd = payload.get("cwd") or os.getcwd()
        cfg = config.load(cwd)
        if cfg.mode == "off":
            return 0
        reqs = requests_for(payload, cfg)[:MAX_PACKAGES]
        if not reqs:
            return 0
        result = decide(evaluate_all(reqs, cfg), cfg.mode)
    except Exception as exc:  # never break the user's tool call
        if os.environ.get("PIVYON_SHIELD_DEBUG"):
            raise
        sys.stderr.write("pivyon-shield: internal error (%s); allowing.\n" % exc)
        return 0
    if result:
        json.dump(result, stdout)
        stdout.write("\n")
    return 0
