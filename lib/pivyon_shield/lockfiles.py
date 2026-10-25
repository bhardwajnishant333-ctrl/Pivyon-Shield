"""Exact resolved dependencies from lockfiles, for whole-project audits.

npm (package-lock / shrinkwrap), Yarn v1 + Berry, pnpm, Bun (bun.lock),
pip requirements (== pins), Poetry, uv, PDM, Pipfile.lock, Cargo, Go (go.mod),
Bundler (Gemfile.lock) and Composer.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Iterator, List, Optional

from .manifests import _toml_load, requirements_lines

SKIP_DIRS = {"node_modules", ".git", ".hg", ".venv", "venv", "env", ".tox", "vendor", "target", "dist",
             "build", ".next", ".nuxt", "__pycache__", ".cache", ".pnpm-store", "site-packages", ".yarn"}


@dataclass
class Dep:
    ecosystem: str
    name: str
    version: str
    file: str
    direct: Optional[bool] = None
    dev: Optional[bool] = None


def _read(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _npm_lock(path: str) -> List[Dep]:
    doc = json.loads(_read(path))
    out: List[Dep] = []
    pkgs = doc.get("packages")
    if isinstance(pkgs, dict):
        root = pkgs.get("") or {}
        direct = set()
        for sec in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            direct.update((root.get(sec) or {}).keys())
        for key, meta in pkgs.items():
            if not key or "node_modules/" not in key or not isinstance(meta, dict):
                continue
            if meta.get("link") or not meta.get("version"):
                continue
            resolved = meta.get("resolved") or ""
            if resolved and not resolved.startswith("http"):
                continue  # file: / git deps
            name = meta.get("name") or key.rsplit("node_modules/", 1)[1]
            top = key.count("node_modules/") == 1
            out.append(Dep("npm", name, meta["version"], path, top and name in direct, bool(meta.get("dev"))))
        return out

    def walk(deps: dict, depth: int):
        for name, meta in (deps or {}).items():
            if isinstance(meta, dict) and meta.get("version") and re.match(r"^\d", meta["version"]):
                out.append(Dep("npm", name, meta["version"], path, depth == 0, bool(meta.get("dev"))))
                walk(meta.get("dependencies") or {}, depth + 1)

    walk(doc.get("dependencies") or {}, 0)
    return out


def _yarn_lock(path: str) -> List[Dep]:
    out: List[Dep] = []
    name = None
    for line in _read(path).splitlines():
        if line and not line.startswith((" ", "#")):
            first = line.rstrip(":").split(",")[0].strip().strip('"')
            m = re.match(r"^((?:@[^@/]+/)?[^@]+)@(.*)$", first)
            name = None
            if m and not re.search(r"@(file|link|workspace|portal|patch|git|github):", first):
                name = m.group(1)
        else:
            m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line)
            if m and name:
                out.append(Dep("npm", name, m.group(1), path))
                name = None
    return out


def _pnpm_lock(path: str) -> List[Dep]:
    out: List[Dep] = []
    section = None
    for line in _read(path).splitlines():
        if re.match(r"^\S", line):
            section = line.rstrip(":").strip()
            continue
        if section not in ("packages", "snapshots"):
            continue
        m = re.match(r"^  '?/?((?:@[^@/]+/)?[^@/(]+)[@/](\d[^(:'\s]*)", line)
        if m:
            out.append(Dep("npm", m.group(1), m.group(2), path))
    return out


def _bun_lock(path: str) -> List[Dep]:
    text = _read(path)
    text = re.sub(r",(\s*[}\]])", r"\1", text)  # JSONC trailing commas
    doc = json.loads(text)
    out: List[Dep] = []
    for entry in (doc.get("packages") or {}).values():
        if isinstance(entry, list) and entry and isinstance(entry[0], str):
            m = re.match(r"^((?:@[^@/]+/)?[^@]+)@(\d[^\s]*)$", entry[0])
            if m:
                out.append(Dep("npm", m.group(1), m.group(2), path))
    return out


def _requirements(path: str) -> List[Dep]:
    return [Dep("PyPI", n, v, path, True) for n, v, _ in requirements_lines(_read(path)) if n and v]


def _toml_packages(path: str, ecosystem: str) -> List[Dep]:
    text = _read(path)
    doc = _toml_load(text)
    out: List[Dep] = []
    if doc is not None:
        for p in doc.get("package") or []:
            src = p.get("source")
            if ecosystem == "crates.io" and not (isinstance(src, str) and src.startswith("registry+")):
                continue
            if ecosystem == "PyPI" and isinstance(src, dict) and any(k in src for k in ("editable", "virtual", "path", "directory", "git")):
                continue
            if p.get("name") and p.get("version"):
                out.append(Dep(ecosystem, p["name"], str(p["version"]), path))
        return out
    # No tomllib (Python < 3.11): read the flat keys of each [[package]] table.
    for block in re.split(r"^\[\[package\]\]\s*$", text, flags=re.M)[1:]:
        block = re.split(r"^\[", block, maxsplit=1, flags=re.M)[0]
        keys = dict(re.findall(r'^(\w+)\s*=\s*(.+?)\s*$', block, re.M))
        name = keys.get("name", "").strip('"')
        version = keys.get("version", "").strip('"')
        src = keys.get("source", "")
        if ecosystem == "crates.io" and not src.startswith('"registry+'):
            continue
        if ecosystem == "PyPI" and re.search(r"\b(editable|virtual|path|directory|git)\s*=", src):
            continue
        if name and version:
            out.append(Dep(ecosystem, name, version, path))
    return out


def _pipfile_lock(path: str) -> List[Dep]:
    doc = json.loads(_read(path))
    out: List[Dep] = []
    for sec in ("default", "develop"):
        for name, meta in (doc.get(sec) or {}).items():
            ver = (meta or {}).get("version", "")
            if ver.startswith("=="):
                out.append(Dep("PyPI", name, ver[2:], path, None, sec == "develop"))
    return out


def _gomod(path: str) -> List[Dep]:
    out: List[Dep] = []
    in_block = False
    for line in _read(path).splitlines():
        s = line.strip()
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block and s == ")":
            in_block = False
            continue
        m = re.match(r"^(?:require\s+)?(\S+)\s+(v\S+)(\s*//\s*indirect)?", s)
        if m and (in_block or s.startswith("require ")):
            out.append(Dep("Go", m.group(1), m.group(2), path, not m.group(3)))
    return out


def _gemfile_lock(path: str) -> List[Dep]:
    out: List[Dep] = []
    in_specs = False
    section = None
    for line in _read(path).splitlines():
        if re.match(r"^\S", line):
            section = line.strip()
            in_specs = False
            continue
        if line.strip() == "specs:":
            in_specs = section == "GEM"
            continue
        m = re.match(r"^    ([\w.-]+) \(([\w.]+)(?:-[\w-]+)?\)$", line)
        if in_specs and m:
            out.append(Dep("RubyGems", m.group(1), m.group(2), path))
    return out


def _composer_lock(path: str) -> List[Dep]:
    doc = json.loads(_read(path))
    out: List[Dep] = []
    for sec, dev in (("packages", False), ("packages-dev", True)):
        for p in doc.get(sec) or []:
            ver = str(p.get("version", "")).lstrip("v")
            if p.get("name") and re.match(r"^\d", ver):
                out.append(Dep("Packagist", p["name"], ver, path, None, dev))
    return out


PARSERS = {
    "package-lock.json": _npm_lock,
    "npm-shrinkwrap.json": _npm_lock,
    "yarn.lock": _yarn_lock,
    "pnpm-lock.yaml": _pnpm_lock,
    "bun.lock": _bun_lock,
    "poetry.lock": lambda p: _toml_packages(p, "PyPI"),
    "uv.lock": lambda p: _toml_packages(p, "PyPI"),
    "pdm.lock": lambda p: _toml_packages(p, "PyPI"),
    "pipfile.lock": _pipfile_lock,
    "cargo.lock": lambda p: _toml_packages(p, "crates.io"),
    "go.mod": _gomod,
    "gemfile.lock": _gemfile_lock,
    "composer.lock": _composer_lock,
}


def parser_for(path: str):
    base = os.path.basename(path).lower()
    if base in PARSERS:
        return PARSERS[base]
    if re.match(r"^.*requirements.*\.txt$", base):
        return _requirements
    return None


def find(root: str, max_depth: int = 5) -> Iterator[str]:
    if os.path.isfile(root):
        if parser_for(root):
            yield root
        return
    root = os.path.abspath(root)
    base_depth = root.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith("."))
        if dirpath.count(os.sep) - base_depth >= max_depth:
            dirnames[:] = []
        for f in sorted(filenames):
            if parser_for(f):
                yield os.path.join(dirpath, f)


def collect(root: str) -> List[Dep]:
    deps: List[Dep] = []
    for path in find(root):
        try:
            deps.extend(parser_for(path)(path))
        except Exception as exc:  # one broken lockfile must not sink the audit
            deps.append(Dep("error", path, str(exc)[:200], path))
    return deps
