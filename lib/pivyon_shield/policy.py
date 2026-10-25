"""Turn registry + OSV facts about a requested package into a verdict.

Levels, most severe first:
  block       - never install: does not exist, known malware, removed by the registry
  confirm     - a human should look first: lookalike name, brand-new package,
                release younger than the cooldown, serious known vulnerability
  warn        - install is fine but Claude should know: other vulns, deprecated,
                install scripts, very low adoption
  ok          - nothing found
  unverified  - registry unreachable; nothing could be checked
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import List, Optional

from . import osv, registries, typosquat
from .commands import Request
from .config import Config
from .net import NetError

LEVELS = ("block", "confirm", "warn", "unverified", "ok")
RANK = {lvl: i for i, lvl in enumerate(LEVELS)}

REGISTRY_NAMES = {
    "npm": "npm", "PyPI": "PyPI", "crates.io": "crates.io", "Go": "the Go module proxy",
    "RubyGems": "RubyGems", "Packagist": "Packagist",
}


@dataclass
class Finding:
    level: str
    message: str


@dataclass
class Verdict:
    request: Request
    findings: List[Finding] = field(default_factory=list)
    info: Optional[registries.PackageInfo] = None
    vulns: List[osv.Vuln] = field(default_factory=list)
    fix_version: Optional[str] = None

    @property
    def level(self) -> str:
        if not self.findings:
            return "ok"
        return min((f.level for f in self.findings), key=lambda lvl: RANK[lvl])

    def add(self, level: str, message: str) -> None:
        self.findings.append(Finding(level, message))

    @property
    def label(self) -> str:
        r = self.request
        ver = r.version or (self.info.resolved_version if self.info else None)
        return "%s %s%s" % (r.ecosystem, r.name, ("@" + ver) if ver else "")


def _days(x: float) -> str:
    if x < 1:
        return "%d hours" % max(1, round(x * 24))
    return "%d days" % round(x)


def evaluate(req: Request, cfg: Config) -> Verdict:
    v = Verdict(req)
    eco, name = req.ecosystem, req.name
    reg = REGISTRY_NAMES.get(eco, eco)

    if cfg.denied(eco, name):
        v.add("block", "%s is on this project's pivyon-shield deny list." % name)
        return v
    if cfg.allowed(eco, name):
        return v

    popular = typosquat.is_popular(eco, name)
    look = typosquat.lookalike(eco, name)
    info = registries.lookup(eco, name, req.version, popular=popular,
                             fresh_window_hours=max(cfg.cooldown_hours, 1.0))
    v.info = info

    if info.exists is None:
        if look:
            v.add("confirm", "'%s' looks like the popular package '%s' (%s), and %s could not be "
                             "reached to verify it." % (name, look[0], look[1], reg))
        else:
            v.add("unverified", "%s was unreachable, so '%s' could not be verified." % (reg, name))
        return v

    if info.exists is False:
        hint = (" Did you mean '%s'?" % look[0]) if look else ""
        if req.custom_index:
            v.add("warn", "'%s' is not on public %s. That is fine if it lives on your private index, "
                          "but if the private index is ever missing it, an attacker can claim the public "
                          "name (dependency confusion).%s" % (name, reg, hint))
        else:
            v.add("block", "'%s' does not exist on %s. The name is most likely hallucinated, and "
                           "attackers register exactly these names to ship malware (slopsquatting).%s "
                           "Find the real package name in the library's official docs before retrying."
                           % (name, reg, hint))
        return v

    if info.security_holding:
        v.add("block", "npm's security team removed '%s' for malicious code; only a placeholder remains." % name)
        return v
    if info.quarantined:
        v.add("block", "PyPI has quarantined '%s' (suspected malware)." % name)
        return v

    version = info.resolved_version
    try:
        if version:
            vulns = osv.query(eco, info.name, version)
        else:  # unknown version: only "the whole package is malware" is meaningful
            vulns = [x for x in osv.query(eco, info.name) if x.malicious]
    except NetError:
        vulns = osv.from_pypi(info.registry_vulns) if eco == "PyPI" else []
        if eco != "PyPI":
            v.add("unverified", "OSV.dev was unreachable, so known-malware and vulnerability checks were skipped.")
    malicious = [x for x in vulns if x.malicious]
    if malicious:
        v.add("block", "'%s' is flagged as MALICIOUS by the OpenSSF malicious-packages feed (%s): %s"
              % (name, malicious[0].id, malicious[0].summary or "see " + malicious[0].url))
        return v

    age = info.age_days()
    adoption = ""
    if info.weekly_downloads is not None:
        adoption = ", %s downloads last week" % format(info.weekly_downloads, ",")
    if look and not popular:
        v.add("confirm", "'%s' looks like the popular package '%s' (%s). First published %s ago%s. "
                         "Make sure this is the package you meant." % (
                             name, look[0], look[1], _days(age) if age is not None else "at an unknown time", adoption))
    if not popular and age is not None and age < cfg.new_package_days:
        v.add("confirm", "'%s' was first published only %s ago (%d release%s%s). Brand-new packages are "
                         "the usual vehicle for slopsquatting and malware." % (
                             name, _days(age), info.version_count, "" if info.version_count == 1 else "s", adoption))
    rage = info.resolved_age_hours()
    if cfg.cooldown_hours > 0 and rage is not None and rage < cfg.cooldown_hours and not (
        not popular and age is not None and age < cfg.new_package_days
    ):
        v.add("confirm", "%s %s was published %s ago, inside the %g-hour cooldown. Hijacked releases of "
                         "popular packages are typically live for hours before removal. Prefer pinning the "
                         "previous release." % (name, version, _days(rage / 24), cfg.cooldown_hours))

    real = [x for x in vulns if not x.malicious]
    if real:
        v.vulns = real
        fix = osv.fix_for(version or "0", real) if version else None
        v.fix_version = fix
        worst = osv.worst(real)
        ids = ", ".join(x.label for x in sorted(real, key=lambda x: -osv.SEVERITY_ORDER[x.severity])[:5])
        more = "" if len(real) <= 5 else " and %d more" % (len(real) - 5)
        msg = "%s %s has %d known vulnerabilit%s (worst: %s): %s%s.%s" % (
            name, version, len(real), "y" if len(real) == 1 else "ies", worst, ids, more,
            (" Fixed in %s." % fix) if fix else " No fixed release is listed.")
        threshold = osv.SEVERITY_ORDER.get(cfg.block_vulnerable, 99)
        level = "confirm" if cfg.block_vulnerable != "never" and osv.SEVERITY_ORDER[worst] >= threshold else "warn"
        v.add(level, msg)

    if info.requested_version_missing:
        v.add("warn", "%s has no release '%s'; the latest is %s." % (name, req.version, info.latest))
    if info.deprecated:
        v.add("warn", "%s %s is deprecated: %s" % (name, version, info.deprecated[:200]))
    if info.yanked:
        v.add("warn", "%s %s was yanked by its maintainers." % (name, version))
    if info.install_scripts and not popular:
        v.add("warn", "%s runs install scripts (preinstall/install/postinstall) on install." % name)
    if (not popular and info.weekly_downloads is not None and info.weekly_downloads < 50
            and (age is None or age < 365)):
        v.add("warn", "%s has very little adoption (%d downloads last week)." % (name, info.weekly_downloads))
    return v


def evaluate_all(reqs: List[Request], cfg: Config, workers: int = 8) -> List[Verdict]:
    if not reqs:
        return []
    with ThreadPoolExecutor(max_workers=min(workers, len(reqs))) as pool:
        return list(pool.map(lambda r: _safe(r, cfg), reqs))


def _safe(req: Request, cfg: Config) -> Verdict:
    try:
        return evaluate(req, cfg)
    except Exception as exc:  # a guard must never crash the tool call
        v = Verdict(req)
        v.add("unverified", "pivyon-shield hit an internal error checking this package: %s" % exc)
        return v
