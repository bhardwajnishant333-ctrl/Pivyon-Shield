"""OSV.dev client (free, no key) plus a CVSS v3 base-score calculator.

OSV aggregates GitHub Advisories, PyPA, RustSec, Go, RubySec and the OpenSSF
malicious-packages feed (ids starting with ``MAL-``).
"""

from __future__ import annotations

import math
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from . import versions as _v
from .net import NetError, NotFound, request_json

OSV_API = "https://api.osv.dev/v1"
QUERY_TTL = 3600
VULN_TTL = 24 * 3600

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


@dataclass
class Vuln:
    id: str
    summary: str = ""
    aliases: List[str] = field(default_factory=list)
    severity: str = "unknown"
    score: Optional[float] = None
    fixed: List[str] = field(default_factory=list)
    malicious: bool = False
    url: str = ""

    @property
    def cve(self) -> Optional[str]:
        for a in self.aliases:
            if a.startswith("CVE-"):
                return a
        return None

    @property
    def label(self) -> str:
        return self.cve or self.id


# ----------------------------------------------------------- CVSS v3.x base

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x: float) -> float:
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> Optional[float]:
    if not vector or not vector.startswith("CVSS:3"):
        return None
    m = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    try:
        scope_changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _W["C"][m["C"]]) * (1 - _W["I"][m["I"]]) * (1 - _W["A"][m["A"]])
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        exploit = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploit), 10))
    return _roundup(min(impact + exploit, 10))


def label_for_score(score: Optional[float]) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


_DB_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


def parse_vuln(doc: dict, ecosystem: Optional[str] = None, name: Optional[str] = None) -> Vuln:
    vid = doc.get("id", "")
    v = Vuln(
        id=vid,
        summary=(doc.get("summary") or (doc.get("details") or "").strip().split("\n")[0])[:200],
        aliases=list(doc.get("aliases") or []),
        malicious=vid.startswith("MAL-"),
        url="https://osv.dev/vulnerability/" + vid,
    )
    for sev in doc.get("severity") or []:
        if sev.get("type") == "CVSS_V3":
            v.score = cvss3_score(sev.get("score", ""))
            break
    label = label_for_score(v.score)
    if label == "unknown":
        db = (doc.get("database_specific") or {}).get("severity")
        label = _DB_SEVERITY.get(str(db).upper(), "unknown")
    if label == "unknown":
        for aff in doc.get("affected") or []:
            es = (aff.get("ecosystem_specific") or {}).get("severity")
            if es:
                label = _DB_SEVERITY.get(str(es).upper(), "unknown")
                break
    if v.malicious:
        label = "critical"
    v.severity = label
    for aff in doc.get("affected") or []:
        pkg = aff.get("package") or {}
        if name and pkg.get("name") and _same_name(pkg.get("name"), name, ecosystem) is False:
            continue
        for rng in aff.get("ranges") or []:
            if rng.get("type") == "GIT":
                continue  # commit hashes, not installable versions
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    v.fixed.append(ev["fixed"])
    return v


def _same_name(a: str, b: str, ecosystem: Optional[str]) -> bool:
    if ecosystem == "PyPI":
        norm = lambda s: re.sub(r"[-_.]+", "-", s).lower()  # noqa: E731
        return norm(a) == norm(b)
    return a == b


def dedupe(vulns: Iterable[Vuln]) -> List[Vuln]:
    """Merge records that describe the same flaw (GHSA, PYSEC and CVE ids alias
    each other), keeping the richest severity and the union of fixes."""
    merged: List[Vuln] = []
    index: Dict[str, Vuln] = {}
    for v in vulns:
        keys = [v.id] + v.aliases
        hit = next((index[k] for k in keys if k in index), None)
        if hit is None:
            merged.append(v)
            hit = v
        else:
            if SEVERITY_ORDER[v.severity] > SEVERITY_ORDER[hit.severity]:
                hit.severity, hit.score = v.severity, v.score
            hit.fixed = sorted(set(hit.fixed) | set(v.fixed))
            hit.aliases = sorted(set(hit.aliases) | set(keys) - {hit.id})
            hit.malicious = hit.malicious or v.malicious
            if not hit.summary:
                hit.summary = v.summary
        for k in keys:
            index[k] = hit
    return merged


def query(ecosystem: str, name: str, version: Optional[str] = None) -> List[Vuln]:
    """All advisories for a package (optionally only those affecting a version)."""
    payload: Dict = {"package": {"name": name, "ecosystem": ecosystem}}
    if version:
        payload["version"] = version.lstrip("v") if ecosystem != "Go" else version
    vulns: List[Vuln] = []
    token = None
    for _ in range(10):
        body = dict(payload)
        if token:
            body["page_token"] = token
        doc = request_json(OSV_API + "/query", data=body, ttl=QUERY_TTL)
        for item in doc.get("vulns") or []:
            vulns.append(parse_vuln(item, ecosystem, name))
        token = doc.get("next_page_token")
        if not token:
            break
    return dedupe(vulns)


def get_vuln(vid: str) -> dict:
    return request_json(OSV_API + "/vulns/" + vid, ttl=VULN_TTL)


def query_batch(items: List[Tuple[str, str, str]], workers: int = 8) -> Dict[Tuple[str, str, str], List[Vuln]]:
    """Look up many (ecosystem, name, version) triples. Raises NetError."""
    results: Dict[Tuple[str, str, str], List[str]] = {}
    for start in range(0, len(items), 1000):
        chunk = items[start:start + 1000]
        queries = [
            {"package": {"ecosystem": e, "name": n}, "version": (ver.lstrip("v") if e != "Go" else ver)}
            for e, n, ver in chunk
        ]
        doc = request_json(OSV_API + "/querybatch", data={"queries": queries}, ttl=QUERY_TTL)
        for item, res in zip(chunk, doc.get("results") or []):
            ids = [v.get("id") for v in (res or {}).get("vulns") or [] if v.get("id")]
            if (res or {}).get("next_page_token"):
                # Rare: a package with more than a page of hits. Fall back.
                try:
                    ids = [v.id for v in query(*item)]
                except NetError:
                    pass
            results[item] = ids

    needed = sorted({vid for ids in results.values() for vid in ids})
    docs: Dict[str, dict] = {}

    def fetch(vid: str):
        try:
            return vid, get_vuln(vid)
        except (NetError, NotFound):
            return vid, {"id": vid}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for vid, doc in pool.map(fetch, needed):
            docs[vid] = doc
    return {
        item: dedupe(parse_vuln(docs.get(vid, {"id": vid}), item[0], item[1]) for vid in ids)
        for item, ids in results.items()
    }


def from_pypi(entries: Iterable[dict]) -> List[Vuln]:
    """PyPI's JSON API embeds OSV data; use it when OSV itself is unreachable."""
    out = []
    for e in entries:
        if e.get("withdrawn"):
            continue
        out.append(
            Vuln(
                id=e.get("id", ""),
                summary=(e.get("summary") or (e.get("details") or "").split("\n")[0])[:200],
                aliases=list(e.get("aliases") or []),
                fixed=list(e.get("fixed_in") or []),
                url=e.get("link") or "",
            )
        )
    return dedupe(out)


def worst(vulns: Iterable[Vuln]) -> str:
    best = "unknown"
    for v in vulns:
        if SEVERITY_ORDER[v.severity] > SEVERITY_ORDER[best]:
            best = v.severity
    return best


def fix_for(current: str, vulns: Iterable[Vuln]) -> Optional[str]:
    """Smallest version that fixes every listed advisory that has a fix."""
    best: Optional[str] = None
    for v in vulns:
        f = _v.nearest_fix(current, v.fixed)
        if f and (best is None or _v.compare(f, best) > 0):
            best = f
    return best
