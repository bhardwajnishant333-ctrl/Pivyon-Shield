"""Dependencies declared in manifest files, so edits to them can be vetted.

An agent rarely types ``npm install foo``; it edits package.json and runs a
bare ``npm install``. Diffing the manifest before and after the edit is what
catches that path.
"""

from __future__ import annotations

import json
import os
import re
from typing import Dict, Iterable, List, Optional, Tuple

try:  # Python 3.11+
    import tomllib as _toml
except ImportError:  # pragma: no cover - older Pythons use the regex fallback
    _toml = None

Deps = Dict[Tuple[str, str], Optional[str]]  # (ecosystem, name) -> exact version or None


def requirements_lines(text: str) -> Iterable[Tuple[Optional[str], Optional[str], Optional[str]]]:
    """Yield (name, exact_version, nested_requirements_file) per line."""
    from .commands import pypi_spec

    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^(-r|--requirement)\s*=?\s*(\S+)", line)
        if m:
            yield None, None, m.group(2)
            continue
        if line.startswith("-"):
            continue
        parsed = pypi_spec(line)
        if parsed:
            yield parsed[0], parsed[1], None


def _exact(ver: Optional[str]) -> Optional[str]:
    if not isinstance(ver, str):
        return None
    v = ver.strip().lstrip("=").strip()
    return v if re.match(r"^v?\d+(\.\d+)*([-.+][\w.+-]+)?$", v) else None


def _npm_deps(text: str) -> Deps:
    from .commands import npm_spec

    doc = json.loads(text)
    out: Deps = {}
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, spec in (doc.get(section) or {}).items():
            if not isinstance(spec, str):
                continue
            if spec.startswith("npm:"):
                parsed = npm_spec(spec[4:])
                if parsed:
                    out[("npm", parsed[0])] = _exact(parsed[1])
                continue
            if npm_spec(name + "@" + spec) is None and npm_spec(name) is None:
                continue
            if re.match(r"^(file:|link:|workspace:|portal:|git|github:|http|\.|/|~)", spec) or (
                "/" in spec and not spec.startswith("@")
            ):
                continue
            out[("npm", name)] = _exact(spec)
    return out


def _requirements_deps(text: str) -> Deps:
    from .registries import pypi_normalize

    return {("PyPI", pypi_normalize(n)): v for n, v, _ in requirements_lines(text) if n}


def _toml_load(text: str) -> Optional[dict]:
    if _toml is None:
        return None
    return _toml.loads(text)


def _pyproject_deps(text: str) -> Deps:
    from .commands import pypi_spec
    from .registries import pypi_normalize

    out: Deps = {}
    doc = _toml_load(text)
    specs: List[str] = []
    if doc is None:
        # Fallback: quoted strings inside dependencies = [...] arrays.
        for block in re.findall(r"dependencies\s*=\s*\[(.*?)\]", text, re.S):
            specs.extend(re.findall(r"[\"']([^\"']+)[\"']", block))
    else:
        proj = doc.get("project") or {}
        specs.extend(proj.get("dependencies") or [])
        for group in (proj.get("optional-dependencies") or {}).values():
            specs.extend(group or [])
        for group in (doc.get("dependency-groups") or {}).values():
            specs.extend(s for s in group or [] if isinstance(s, str))
        poetry = (doc.get("tool") or {}).get("poetry") or {}
        tables = [poetry.get("dependencies") or {}, poetry.get("dev-dependencies") or {}]
        for g in (poetry.get("group") or {}).values():
            tables.append((g or {}).get("dependencies") or {})
        for table in tables:
            for name, spec in table.items():
                if name.lower() == "python":
                    continue
                if isinstance(spec, dict):
                    if any(k in spec for k in ("path", "git", "url", "source")):
                        continue
                    spec = spec.get("version", "")
                ver = _exact(spec) if isinstance(spec, str) and not re.match(r"^[\^~<>*]", spec) else None
                out[("PyPI", pypi_normalize(name))] = ver
    for s in specs:
        if not isinstance(s, str):
            continue
        p = pypi_spec(s)
        if p:
            out[("PyPI", pypi_normalize(p[0]))] = p[1]
    return out


def _cargo_deps(text: str) -> Deps:
    out: Deps = {}
    doc = _toml_load(text)
    if doc is None:
        return out
    tables = []
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        tables.append(doc.get(key) or {})
    for target in (doc.get("target") or {}).values():
        for key in ("dependencies", "dev-dependencies", "build-dependencies"):
            tables.append((target or {}).get(key) or {})
    tables.append((doc.get("workspace") or {}).get("dependencies") or {})
    for table in tables:
        for name, spec in table.items():
            ver = None
            if isinstance(spec, dict):
                if any(k in spec for k in ("path", "git", "registry", "workspace")):
                    continue
                name = spec.get("package", name)
                spec = spec.get("version")
            if isinstance(spec, str) and spec.startswith("="):
                ver = _exact(spec)
            out[("crates.io", name)] = ver
    return out


def _gemfile_deps(text: str) -> Deps:
    out: Deps = {}
    for line in text.splitlines():
        m = re.match(r"""^\s*gem\s+['"]([\w.-]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?(.*)$""", line)
        if not m:
            continue
        if re.search(r"\b(path|git|github|source)\s*:", m.group(3) or "") or re.search(r":(path|git|github)\s*=>", line):
            continue
        out[("RubyGems", m.group(1))] = _exact(m.group(2))
    return out


def _gomod_deps(text: str) -> Deps:
    out: Deps = {}
    in_block = False
    for line in text.splitlines():
        s = line.split("//", 1)[0].strip()
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block and s == ")":
            in_block = False
            continue
        m = re.match(r"^(?:require\s+)?([\w.\-/~]+\.[\w.\-/~]+)\s+(v[\w.\-+]+)$", s)
        if m and (in_block or s.startswith("require")):
            out[("Go", m.group(1))] = m.group(2)
    return out


def _composer_deps(text: str) -> Deps:
    doc = json.loads(text)
    out: Deps = {}
    for section in ("require", "require-dev"):
        for name, spec in (doc.get(section) or {}).items():
            if "/" not in name or name.startswith(("php", "ext-", "lib-")):
                continue
            out[("Packagist", name.lower())] = _exact(spec)
    return out


def parser_for(path: str):
    base = os.path.basename(path).lower()
    if base == "package.json":
        return _npm_deps
    if re.match(r"^.*requirements.*\.(txt|in)$", base) or base in ("constraints.txt",):
        return _requirements_deps
    if base == "pyproject.toml":
        return _pyproject_deps
    if base == "cargo.toml":
        return _cargo_deps
    if base in ("gemfile", "gems.rb"):
        return _gemfile_deps
    if base == "go.mod":
        return _gomod_deps
    if base == "composer.json":
        return _composer_deps
    return None


def declared(path: str, text: str) -> Optional[Deps]:
    parser = parser_for(path)
    if not parser:
        return None
    try:
        return parser(text)
    except (ValueError, TypeError, AttributeError, KeyError):
        return None  # mid-edit / invalid file: fail open
    except Exception:  # tomllib.TOMLDecodeError and friends
        return None


def added_or_changed(path: str, before: str, after: str) -> Deps:
    """Dependencies present in ``after`` that were absent or different before."""
    new = declared(path, after)
    if not new:
        return {}
    old = declared(path, before) or {}
    return {k: v for k, v in new.items() if k not in old or (v and old.get(k) != v)}


def apply_edit(tool: str, tool_input: dict, current: str) -> Optional[str]:
    """The file content after a Write / Edit / MultiEdit tool call."""
    if tool == "Write":
        return tool_input.get("content")
    if tool == "Edit":
        edits = [tool_input]
    elif tool == "MultiEdit":
        edits = tool_input.get("edits") or []
    else:
        return None
    text = current
    for e in edits:
        old, new = e.get("old_string", ""), e.get("new_string", "")
        if old == "":
            text = new + text if not text else text
            continue
        if old not in text:
            return None
        text = text.replace(old, new) if e.get("replace_all") else text.replace(old, new, 1)
    return text
