"""Whole-project audit: every locked dependency against OSV.dev in one batch."""

from __future__ import annotations

import json
import os
from collections import defaultdict
from typing import Dict, List, Tuple

from . import lockfiles, osv
from .net import NetError


def run(root: str) -> dict:
    deps = lockfiles.collect(root)
    errors = [d for d in deps if d.ecosystem == "error"]
    deps = [d for d in deps if d.ecosystem != "error"]
    unique: Dict[Tuple[str, str, str], List[lockfiles.Dep]] = defaultdict(list)
    for d in deps:
        unique[(d.ecosystem, d.name, d.version)].append(d)

    report: dict = {
        "root": os.path.abspath(root),
        "lockfiles": sorted({os.path.relpath(d.file, root) if os.path.isdir(root) else d.file for d in deps}),
        "parse_errors": [{"file": e.name, "error": e.version} for e in errors],
        "dependencies": len(unique),
        "findings": [],
        "error": None,
    }
    if not unique:
        return report
    try:
        hits = osv.query_batch(list(unique.keys()))
    except NetError as exc:
        report["error"] = "OSV.dev unreachable: %s" % exc
        return report

    for key, vulns in hits.items():
        if not vulns:
            continue
        eco, name, version = key
        rows = unique[key]
        direct = any(r.direct for r in rows) if any(r.direct is not None for r in rows) else None
        real = [v for v in vulns if not v.malicious]
        report["findings"].append({
            "ecosystem": eco,
            "name": name,
            "version": version,
            "direct": direct,
            "dev": all(r.dev for r in rows) if all(r.dev is not None for r in rows) else None,
            "files": sorted({os.path.relpath(r.file, root) if os.path.isdir(root) else r.file for r in rows}),
            "malicious": any(v.malicious for v in vulns),
            "severity": "critical" if any(v.malicious for v in vulns) else osv.worst(real),
            "fix": osv.fix_for(version, real),
            "vulns": [
                {"id": v.id, "alias": v.cve, "severity": v.severity, "score": v.score,
                 "summary": v.summary, "fixed": sorted(set(v.fixed)), "malicious": v.malicious, "url": v.url}
                for v in sorted(vulns, key=lambda v: -osv.SEVERITY_ORDER[v.severity])
            ],
        })
    report["findings"].sort(key=lambda f: (not f["malicious"], -osv.SEVERITY_ORDER[f["severity"]],
                                           not f["direct"], f["name"]))
    counts: Dict[str, int] = defaultdict(int)
    for f in report["findings"]:
        counts["malicious" if f["malicious"] else f["severity"]] += 1
    report["summary"] = dict(counts)
    return report


def to_markdown(report: dict) -> str:
    lines = ["# pivyon-shield audit", ""]
    lines.append("Scanned %d unique dependencies from %d lockfile(s) under `%s`." % (
        report["dependencies"], len(report["lockfiles"]), report["root"]))
    for f in report["lockfiles"]:
        lines.append("- `%s`" % f)
    for e in report["parse_errors"]:
        lines.append("- could not parse `%s`: %s" % (e["file"], e["error"]))
    lines.append("")
    if report.get("error"):
        lines.append("**Audit incomplete:** %s" % report["error"])
        return "\n".join(lines)
    if not report["dependencies"]:
        lines.append("No lockfiles found. Generate one (`npm install`, `uv lock`, `cargo generate-lockfile`, ...) and re-run.")
        return "\n".join(lines)
    findings = report["findings"]
    if not findings:
        lines.append("**No known vulnerabilities or malicious packages.** (Source: OSV.dev)")
        return "\n".join(lines)
    s = report.get("summary", {})
    order = ["malicious", "critical", "high", "medium", "low", "unknown"]
    lines.append("**%d affected package version(s):** %s" % (
        len(findings), ", ".join("%d %s" % (s[k], k) for k in order if s.get(k))))
    lines.append("")
    lines.append("| Package | Version | Severity | Direct | Fix | Advisories |")
    lines.append("|---|---|---|---|---|---|")
    for f in findings:
        sev = "**MALICIOUS**" if f["malicious"] else f["severity"]
        direct = {True: "yes", False: "transitive", None: "?"}[f["direct"]]
        advis = ", ".join(v["alias"] or v["id"] for v in f["vulns"][:4]) + (
            " +%d" % (len(f["vulns"]) - 4) if len(f["vulns"]) > 4 else "")
        lines.append("| %s `%s` | %s | %s | %s | %s | %s |" % (
            f["ecosystem"], f["name"], f["version"], sev, direct, f["fix"] or "none listed", advis))
    lines.append("")
    lines.append("Details: https://osv.dev/list — ids above link as https://osv.dev/vulnerability/<id>.")
    return "\n".join(lines)


def main(argv: List[str]) -> int:
    import argparse

    ap = argparse.ArgumentParser(prog="pivyon-shield audit")
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("--format", choices=("md", "json"), default="md")
    ap.add_argument("--fail-on", choices=("malicious", "critical", "high", "medium", "low", "never"), default="never",
                    help="exit 1 when a finding at or above this level exists (for CI)")
    args = ap.parse_args(argv)
    report = run(args.path)
    print(json.dumps(report, indent=2) if args.format == "json" else to_markdown(report))
    if report.get("error"):
        return 2
    if args.fail_on != "never":
        threshold = 5 if args.fail_on == "malicious" else osv.SEVERITY_ORDER[args.fail_on]
        for f in report["findings"]:
            rank = 5 if f["malicious"] else osv.SEVERITY_ORDER[f["severity"]]
            if rank >= threshold:
                return 1
    return 0
