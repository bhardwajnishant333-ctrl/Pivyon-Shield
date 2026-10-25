"""Due diligence on candidate packages *before* choosing one, and a dry run
of what the hook would decide for a shell command."""

from __future__ import annotations

import datetime as _dt
import json
from typing import List

from . import config, typosquat
from .commands import Context, Request, packages_in_command
from .policy import Verdict, evaluate_all

ALIASES = {"npm": "npm", "node": "npm", "js": "npm", "pypi": "PyPI", "pip": "PyPI", "python": "PyPI", "py": "PyPI",
           "crates": "crates.io", "crates.io": "crates.io", "cargo": "crates.io", "rust": "crates.io",
           "go": "Go", "golang": "Go", "rubygems": "RubyGems", "gem": "RubyGems", "ruby": "RubyGems",
           "packagist": "Packagist", "composer": "Packagist", "php": "Packagist"}


def parse_target(spec: str, default_eco: str) -> Request:
    eco = default_eco
    if ":" in spec and not spec.startswith("@"):
        head, _, rest = spec.partition(":")
        if head.lower() in ALIASES:
            eco, spec = ALIASES[head.lower()], rest
    name, ver = spec, None
    if eco == "PyPI" and "==" in spec:
        name, ver = spec.split("==", 1)
    elif "@" in spec[1:]:
        idx = spec.rindex("@")
        name, ver = spec[:idx], spec[idx + 1:]
    return Request(eco, name, ver or None, "vet")


def _date(d) -> str:
    return d.strftime("%Y-%m-%d") if d else "?"


def _ago(d) -> str:
    if not d:
        return "?"
    days = (_dt.datetime.now(_dt.timezone.utc) - d).days
    if days < 1:
        return "today"
    if days < 60:
        return "%dd ago" % days
    if days < 730:
        return "%dmo ago" % (days // 30)
    return "%.1fy ago" % (days / 365)


VERDICT_TEXT = {"block": "DO NOT USE", "confirm": "CHECK FIRST", "warn": "OK, with notes",
                "ok": "OK", "unverified": "UNVERIFIED"}


def to_markdown(verdicts: List[Verdict]) -> str:
    lines = ["| Package | Verdict | Latest | First release | Last release | Releases | Popularity | License | Known vulns |",
             "|---|---|---|---|---|---|---|---|---|"]
    for v in verdicts:
        i = v.info
        rank = typosquat.popularity_rank(v.request.ecosystem, v.request.name)
        pop = ("top %d" % rank) if rank else "-"
        if i and i.weekly_downloads is not None:
            pop += " / %s wk dl" % format(i.weekly_downloads, ",")
        elif i and i.total_downloads:
            pop += " / %s total dl" % format(i.total_downloads, ",")
        lines.append("| %s `%s` | **%s** | %s | %s | %s | %s | %s | %s | %s |" % (
            v.request.ecosystem, v.request.name, VERDICT_TEXT[v.level],
            (i.latest if i else None) or "?", _date(i.created) if i else "?", _ago(i.last_release) if i else "?",
            (i.version_count if i else 0) or "?", pop, ((i.license if i else None) or "?")[:30],
            len(v.vulns) if v.vulns else 0))
    lines.append("")
    for v in verdicts:
        if v.findings:
            lines.append("**%s**" % v.label)
            for f in v.findings:
                lines.append("- %s: %s" % (f.level, f.message))
            if v.info and v.info.repository:
                lines.append("- repository: %s" % v.info.repository)
            lines.append("")
    return "\n".join(lines)


def to_json(verdicts: List[Verdict]) -> str:
    out = []
    for v in verdicts:
        i = v.info
        out.append({
            "ecosystem": v.request.ecosystem, "name": v.request.name, "requested": v.request.version,
            "verdict": v.level,
            "findings": [{"level": f.level, "message": f.message} for f in v.findings],
            "exists": i.exists if i else None,
            "latest": i.latest if i else None,
            "resolved_version": i.resolved_version if i else None,
            "created": _date(i.created) if i and i.created else None,
            "last_release": _date(i.last_release) if i and i.last_release else None,
            "releases": i.version_count if i else None,
            "weekly_downloads": i.weekly_downloads if i else None,
            "license": i.license if i else None,
            "repository": i.repository if i else None,
            "popularity_rank": typosquat.popularity_rank(v.request.ecosystem, v.request.name),
            "vulnerabilities": [{"id": x.id, "alias": x.cve, "severity": x.severity, "fixed": x.fixed} for x in v.vulns],
            "fix_version": v.fix_version,
        })
    return json.dumps(out, indent=2)


def main(argv: List[str], mode: str) -> int:
    import argparse
    import os

    ap = argparse.ArgumentParser(prog="pivyon-shield " + mode)
    if mode == "vet":
        ap.add_argument("packages", nargs="+", help="npm:express, pypi:requests==2.0.0, crates:serde, ...")
        ap.add_argument("-e", "--ecosystem", default="npm", help="default ecosystem for bare names")
    else:
        ap.add_argument("command", help="the shell command to dry-run, quoted")
    ap.add_argument("--format", choices=("md", "json"), default="md")
    args = ap.parse_args(argv)
    cfg = config.load(os.getcwd())
    if mode == "vet":
        default = ALIASES.get(args.ecosystem.lower(), args.ecosystem)
        reqs = [parse_target(p, default) for p in args.packages]
    else:
        reqs = packages_in_command(args.command, Context(os.getcwd()))
        if not reqs:
            print("No registry packages found in that command.")
            return 0
    verdicts = evaluate_all(reqs, cfg)
    print(to_json(verdicts) if args.format == "json" else to_markdown(verdicts))
    return 1 if any(v.level == "block" for v in verdicts) else 0
