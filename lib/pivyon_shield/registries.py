"""Read-only lookups against the public registries. No accounts, no keys.

Each lookup returns a PackageInfo. ``exists`` is True/False when the registry
answered and None when it could not be reached (callers then fail open).
"""

from __future__ import annotations

import datetime as _dt
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Optional

from . import versions as _v
from .net import NetError, NotFound, request_json

ECOSYSTEMS = ("npm", "PyPI", "crates.io", "Go", "RubyGems", "Packagist")

REGISTRY_TTL = 3600


@dataclass
class PackageInfo:
    ecosystem: str
    name: str
    exists: Optional[bool] = None
    error: Optional[str] = None
    latest: Optional[str] = None
    created: Optional[_dt.datetime] = None
    last_release: Optional[_dt.datetime] = None
    version_count: int = 0
    # The version that would actually be installed and when it was published.
    resolved_version: Optional[str] = None
    resolved_published: Optional[_dt.datetime] = None
    requested_version_missing: bool = False
    deprecated: Optional[str] = None
    yanked: bool = False
    install_scripts: bool = False
    security_holding: bool = False
    quarantined: bool = False
    weekly_downloads: Optional[int] = None
    total_downloads: Optional[int] = None
    license: Optional[str] = None
    repository: Optional[str] = None
    description: Optional[str] = None
    maintainers: Optional[int] = None
    # Vulnerabilities reported by the registry itself (PyPI ships OSV data).
    registry_vulns: List[dict] = field(default_factory=list)

    def age_days(self, now: Optional[_dt.datetime] = None) -> Optional[float]:
        if not self.created:
            return None
        now = now or _dt.datetime.now(_dt.timezone.utc)
        return (now - self.created).total_seconds() / 86400

    def resolved_age_hours(self, now: Optional[_dt.datetime] = None) -> Optional[float]:
        if not self.resolved_published:
            return None
        now = now or _dt.datetime.now(_dt.timezone.utc)
        return (now - self.resolved_published).total_seconds() / 3600


def parse_time(value) -> Optional[_dt.datetime]:
    if not value or not isinstance(value, str):
        return None
    v = value.strip().replace("Z", "+00:00")
    # Trim fractional seconds beyond microseconds (PyPI, crates send 6+ digits).
    v = re.sub(r"(\.\d{6})\d+", r"\1", v)
    try:
        t = _dt.datetime.fromisoformat(v)
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=_dt.timezone.utc)
    return t


# --------------------------------------------------------------------- npm

NPM_REGISTRY = "https://registry.npmjs.org/"


def _npm_url(name: str) -> str:
    return NPM_REGISTRY + urllib.parse.quote(name, safe="@")


def _npm_shrink(doc: dict) -> dict:
    keep = ("name", "description", "dist-tags", "time", "maintainers", "license", "repository", "modified")
    out = {k: doc[k] for k in keep if k in doc}
    out["versions"] = {}
    for ver, meta in (doc.get("versions") or {}).items():
        meta = meta or {}
        scripts = meta.get("scripts") or {}
        out["versions"][ver] = {
            "deprecated": meta.get("deprecated"),
            "hasInstallScript": meta.get("hasInstallScript"),
            "scripts": {k: True for k in ("preinstall", "install", "postinstall") if k in scripts},
            "license": meta.get("license"),
        }
    return out


def _pypi_shrink(doc: dict) -> dict:
    info = doc.get("info") or {}
    keep = ("name", "version", "summary", "license", "license_expression", "project_urls")
    return {
        "info": {k: info.get(k) for k in keep},
        "releases": {
            ver: [{"upload_time_iso_8601": f.get("upload_time_iso_8601"), "yanked": f.get("yanked")} for f in files or []]
            for ver, files in (doc.get("releases") or {}).items()
        },
        "vulnerabilities": doc.get("vulnerabilities") or [],
    }


def npm(
    name: str,
    version: Optional[str] = None,
    *,
    popular: bool = False,
    fresh_window_hours: float = 72,
) -> PackageInfo:
    info = PackageInfo("npm", name)
    try:
        doc = None
        if popular:
            # Abbreviated metadata is a fraction of the size for big packages
            # but has no publish times. If nothing changed inside the fresh
            # window, nothing installed from it can be fresh either.
            doc = request_json(
                _npm_url(name),
                headers={"Accept": "application/vnd.npm.install-v1+json"},
                ttl=REGISTRY_TTL,
                shrink=_npm_shrink,
            )
            modified = parse_time(doc.get("modified"))
            now = _dt.datetime.now(_dt.timezone.utc)
            if not modified or (now - modified).total_seconds() < fresh_window_hours * 3600:
                doc = None
        if doc is None:
            doc = request_json(_npm_url(name), ttl=REGISTRY_TTL, shrink=_npm_shrink)
    except NotFound:
        info.exists = False
        return info
    except NetError as exc:
        info.error = str(exc)
        return info

    info.exists = True
    tags = doc.get("dist-tags") or {}
    vers = doc.get("versions") or {}
    times = doc.get("time") or {}
    info.latest = tags.get("latest")
    info.version_count = len(vers)
    info.created = parse_time(times.get("created"))
    info.description = doc.get("description")
    info.maintainers = len(doc.get("maintainers") or []) or None
    lic = doc.get("license")
    info.license = lic.get("type") if isinstance(lic, dict) else lic
    repo = doc.get("repository")
    info.repository = repo.get("url") if isinstance(repo, dict) else repo

    if (info.latest or "").endswith("-security") or (
        (doc.get("description") or "").strip().lower() == "security holding package"
    ):
        info.security_holding = True

    resolved = None
    if version and version in vers:
        resolved = version
    elif version and version in tags:
        resolved = tags[version]
    elif version and _v.is_exact(version):
        info.requested_version_missing = True
    if not resolved:
        resolved = info.latest
    info.resolved_version = resolved
    if resolved:
        info.resolved_published = parse_time(times.get(resolved))
        meta = vers.get(resolved) or {}
        info.deprecated = meta.get("deprecated") or None
        scripts = meta.get("scripts") or {}
        info.install_scripts = bool(
            meta.get("hasInstallScript")
            or any(k in scripts for k in ("preinstall", "install", "postinstall"))
        )
        if not info.license:
            lic = meta.get("license")
            info.license = lic.get("type") if isinstance(lic, dict) else lic
    release_times = [parse_time(t) for k, t in times.items() if k not in ("created", "modified")]
    release_times = [t for t in release_times if t]
    if release_times:
        info.last_release = max(release_times)

    if not popular:
        try:
            dl = request_json(
                "https://api.npmjs.org/downloads/point/last-week/"
                + urllib.parse.quote(name, safe="@"),
                ttl=6 * 3600,
            )
            info.weekly_downloads = int(dl.get("downloads") or 0)
        except (NotFound, NetError, ValueError, TypeError):
            pass
    return info


# -------------------------------------------------------------------- PyPI


def pypi_normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def pypi(name: str, version: Optional[str] = None, *, popular: bool = False) -> PackageInfo:
    norm = pypi_normalize(name)
    info = PackageInfo("PyPI", norm)
    try:
        doc = request_json("https://pypi.org/pypi/%s/json" % urllib.parse.quote(norm), ttl=REGISTRY_TTL,
                           shrink=_pypi_shrink)
    except NotFound:
        info.exists = False
        # A quarantined project (PEP 792) 404s on the JSON API but still has
        # a simple page that says so. Distinguish it from "never existed".
        try:
            simple = request_json(
                "https://pypi.org/simple/%s/" % urllib.parse.quote(norm),
                headers={"Accept": "application/vnd.pypi.simple.v1+json"},
                ttl=REGISTRY_TTL,
            )
            status = (simple.get("project-status") or {}).get("status")
            if status == "quarantined":
                info.quarantined = True
                info.exists = True
        except (NotFound, NetError):
            pass
        return info
    except NetError as exc:
        info.error = str(exc)
        return info

    info.exists = True
    meta = doc.get("info") or {}
    releases = doc.get("releases") or {}
    info.latest = meta.get("version")
    info.version_count = len([r for r in releases.values() if r])
    info.description = meta.get("summary")
    info.license = (meta.get("license_expression") or meta.get("license") or "").strip()[:80] or None
    urls = meta.get("project_urls") or {}
    for key in ("Source", "Source Code", "Repository", "Code", "GitHub", "Homepage"):
        if urls.get(key):
            info.repository = urls[key]
            break

    def first_upload(files) -> Optional[_dt.datetime]:
        ts = [parse_time(f.get("upload_time_iso_8601")) for f in files or []]
        ts = [t for t in ts if t]
        return min(ts) if ts else None

    all_times = [first_upload(f) for f in releases.values()]
    all_times = [t for t in all_times if t]
    if all_times:
        info.created = min(all_times)
        info.last_release = max(all_times)

    resolved = info.latest
    if version:
        if version in releases:
            resolved = version
        else:
            info.requested_version_missing = True
    info.resolved_version = resolved
    files = releases.get(resolved) or []
    info.resolved_published = first_upload(files)
    info.yanked = bool(files) and all(f.get("yanked") for f in files)
    if resolved == info.latest:
        info.registry_vulns = doc.get("vulnerabilities") or []
    elif resolved:
        try:
            vdoc = request_json(
                "https://pypi.org/pypi/%s/%s/json" % (urllib.parse.quote(norm), urllib.parse.quote(resolved)),
                ttl=REGISTRY_TTL,
            )
            info.registry_vulns = vdoc.get("vulnerabilities") or []
        except (NotFound, NetError):
            pass
    return info


# --------------------------------------------------------------- crates.io


def crates(name: str, version: Optional[str] = None, *, popular: bool = False) -> PackageInfo:
    info = PackageInfo("crates.io", name)
    try:
        doc = request_json("https://crates.io/api/v1/crates/%s" % urllib.parse.quote(name), ttl=REGISTRY_TTL)
    except NotFound:
        info.exists = False
        return info
    except NetError as exc:
        info.error = str(exc)
        return info
    info.exists = True
    crate = doc.get("crate") or {}
    vers = doc.get("versions") or []
    info.latest = crate.get("max_stable_version") or crate.get("max_version")
    info.created = parse_time(crate.get("created_at"))
    info.last_release = parse_time(crate.get("updated_at"))
    info.version_count = len(vers)
    info.total_downloads = crate.get("downloads")
    info.description = crate.get("description")
    info.repository = crate.get("repository")
    by_num = {v.get("num"): v for v in vers}
    resolved = info.latest
    if version:
        if version in by_num:
            resolved = version
        elif _v.is_exact(version):
            info.requested_version_missing = True
    info.resolved_version = resolved
    meta = by_num.get(resolved) or {}
    info.resolved_published = parse_time(meta.get("created_at"))
    info.yanked = bool(meta.get("yanked"))
    info.license = meta.get("license")
    return info


# ---------------------------------------------------------------------- Go


def _go_escape(path: str) -> str:
    return re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), path)


def go(path: str, version: Optional[str] = None, *, popular: bool = False) -> PackageInfo:
    """``go get`` takes package paths; the module is the longest prefix the
    proxy knows. Walk up until one resolves."""
    info = PackageInfo("Go", path)
    parts = path.split("/")
    min_parts = 3 if parts[0] in ("github.com", "gitlab.com", "bitbucket.org") else 1
    any_answer = False
    for n in range(len(parts), min_parts - 1, -1):
        mod = "/".join(parts[:n])
        try:
            doc = request_json("https://proxy.golang.org/%s/@latest" % _go_escape(mod), ttl=REGISTRY_TTL)
        except NotFound:
            any_answer = True
            continue
        except NetError as exc:
            info.error = str(exc)
            return info
        info.exists = True
        info.name = mod
        info.latest = doc.get("Version")
        info.resolved_version = info.latest
        info.resolved_published = parse_time(doc.get("Time"))
        info.last_release = info.resolved_published
        origin = doc.get("Origin") or {}
        info.repository = origin.get("URL")
        if version and version not in ("latest", "upgrade", "patch") and version != info.latest:
            try:
                vdoc = request_json(
                    "https://proxy.golang.org/%s/@v/%s.info" % (_go_escape(mod), _go_escape(version)),
                    ttl=REGISTRY_TTL,
                )
                info.resolved_version = vdoc.get("Version") or version
                info.resolved_published = parse_time(vdoc.get("Time"))
            except NotFound:
                info.requested_version_missing = True
            except NetError:
                pass
        return info
    if any_answer:
        info.exists = False
    return info


# ---------------------------------------------------------------- RubyGems


def rubygems(name: str, version: Optional[str] = None, *, popular: bool = False) -> PackageInfo:
    info = PackageInfo("RubyGems", name)
    try:
        doc = request_json("https://rubygems.org/api/v1/gems/%s.json" % urllib.parse.quote(name), ttl=REGISTRY_TTL)
    except NotFound:
        info.exists = False
        return info
    except NetError as exc:
        info.error = str(exc)
        return info
    info.exists = True
    info.latest = doc.get("version")
    info.total_downloads = doc.get("downloads")
    info.description = doc.get("info")
    info.repository = doc.get("source_code_uri") or doc.get("homepage_uri")
    lic = doc.get("licenses") or []
    info.license = ", ".join(lic) if lic else None
    info.last_release = parse_time(doc.get("version_created_at"))
    resolved = info.latest
    try:
        vers = request_json(
            "https://rubygems.org/api/v1/versions/%s.json" % urllib.parse.quote(name), ttl=REGISTRY_TTL
        )
        info.version_count = len(vers)
        created = [parse_time(v.get("created_at")) for v in vers]
        created = [c for c in created if c]
        if created:
            info.created = min(created)
        by_num = {v.get("number"): v for v in vers}
        if version:
            if version in by_num:
                resolved = version
            elif _v.is_exact(version):
                info.requested_version_missing = True
        info.resolved_published = parse_time((by_num.get(resolved) or {}).get("created_at"))
    except (NotFound, NetError):
        pass
    info.resolved_version = resolved
    return info


# --------------------------------------------------------------- Packagist


def packagist(name: str, version: Optional[str] = None, *, popular: bool = False) -> PackageInfo:
    info = PackageInfo("Packagist", name.lower())
    try:
        doc = request_json("https://repo.packagist.org/p2/%s.json" % name.lower(), ttl=REGISTRY_TTL)
    except NotFound:
        info.exists = False
        return info
    except NetError as exc:
        info.error = str(exc)
        return info
    info.exists = True
    vers = (doc.get("packages") or {}).get(name.lower()) or []
    info.version_count = len(vers)
    if vers:
        info.latest = vers[0].get("version")
        times = [parse_time(v.get("time")) for v in vers]
        times = [t for t in times if t]
        if times:
            info.created, info.last_release = min(times), max(times)
        by_num = {v.get("version"): v for v in vers}
        resolved = version if version in by_num else info.latest
        info.resolved_version = resolved
        info.resolved_published = parse_time((by_num.get(resolved) or {}).get("time"))
    return info


LOOKUPS = {
    "npm": npm,
    "PyPI": pypi,
    "crates.io": crates,
    "Go": go,
    "RubyGems": rubygems,
    "Packagist": packagist,
}


def lookup(
    ecosystem: str,
    name: str,
    version: Optional[str] = None,
    *,
    popular: bool = False,
    fresh_window_hours: float = 72,
) -> PackageInfo:
    if ecosystem == "npm":
        return npm(name, version, popular=popular, fresh_window_hours=fresh_window_hours)
    return LOOKUPS[ecosystem](name, version, popular=popular)
