"""Find the registry packages a shell command would fetch.

Covers npm / pnpm / yarn / bun / npx / bunx / pnpm dlx / yarn dlx / create-*,
pip / pip3 / python -m pip / uv / uvx / pipx / poetry / pdm / rye,
cargo add / install / binstall, go get / install / run, gem install,
bundle add and composer require.
"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

from . import manifests


@dataclass
class Request:
    ecosystem: str
    name: str
    version: Optional[str] = None
    origin: str = ""          # the command or file the request came from
    custom_index: bool = False  # a private / alternate index is in play
    executes: bool = False    # npx-style: the package runs immediately

    @property
    def key(self) -> Tuple[str, str, Optional[str]]:
        return (self.ecosystem, self.name, self.version)


SEPARATORS = {"&&", "||", ";", "|", "&", "(", ")", ";;", "|&", "\n"}
WRAPPERS = {"sudo", "time", "nohup", "exec", "command", "builtin", "nice", "doas", "then", "do", "else", "!"}


def _strip_heredocs(cmd: str) -> str:
    """Drop heredoc bodies: their text is data, not commands."""
    out_lines: List[str] = []
    pending: List[str] = []
    for line in cmd.split("\n"):
        if pending:
            if line.strip() == pending[0]:
                pending.pop(0)
            continue
        out_lines.append(line)
        for m in re.finditer(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1", line):
            pending.append(m.group(2))
    return "\n".join(out_lines)


def split_commands(cmd: str) -> List[List[str]]:
    """Split a shell line into simple commands (lists of words)."""
    cmd = _strip_heredocs(cmd)
    cmd = cmd.replace("\\\n", " ")
    # Command substitutions run too: lift them out as separate commands.
    cmd = re.sub(r"\$\(|`", " ; ", cmd)
    commands: List[List[str]] = []
    for line in cmd.split("\n"):
        lex = shlex.shlex(line, posix=True, punctuation_chars=";&|()")
        lex.whitespace_split = True
        lex.commenters = "#"
        current: List[str] = []
        try:
            for tok in lex:
                if tok in SEPARATORS or set(tok) <= set(";&|()"):
                    if current:
                        commands.append(current)
                    current = []
                else:
                    current.append(tok)
        except ValueError:
            # Unbalanced quotes: fall back to naive splitting.
            current = line.split()
        if current:
            commands.append(current)
    return commands


def _unwrap(words: List[str]) -> List[str]:
    i = 0
    while i < len(words):
        w = words[i]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", w):
            i += 1
        elif w in WRAPPERS:
            i += 1
            if w == "sudo":
                while i < len(words) and words[i].startswith("-"):
                    i += 2 if words[i] in ("-u", "-g", "-C", "-D") else 1
        elif w == "env":
            i += 1
            while i < len(words) and (words[i].startswith("-") or "=" in words[i]):
                i += 1
        else:
            break
    words = words[i:]
    if words:
        words = [os.path.basename(words[0])] + words[1:]
    return words


def _positionals(args: List[str], takes_value: Set[str]) -> Tuple[List[str], Dict[str, List[str]]]:
    pos: List[str] = []
    opts: Dict[str, List[str]] = {}
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            pos.extend(args[i + 1:])
            break
        if a.startswith("-") and len(a) > 1:
            if "=" in a and a.startswith("--"):
                k, val = a.split("=", 1)
                opts.setdefault(k, []).append(val)
            elif a in takes_value and i + 1 < len(args):
                opts.setdefault(a, []).append(args[i + 1])
                i += 1
            else:
                opts.setdefault(a, []).append("")
        else:
            pos.append(a)
        i += 1
    return pos, opts


# --------------------------------------------------------------------- npm

NPM_VALUE_FLAGS = {
    "--registry", "--prefix", "-w", "--workspace", "--tag", "--save-prefix", "--omit",
    "--include", "--install-strategy", "--cache", "--userconfig", "--filter", "-F",
    "-C", "--dir", "--cwd", "--target", "--os", "--cpu", "--libc", "--network-concurrency",
    "-p", "--package", "-c", "--call", "--loglevel", "--global-dir", "--modules-folder",
}
NPM_INSTALL_VERBS = {"install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta",
                     "isntal", "isntall", "add", "a"}


def npm_spec(spec: str) -> Optional[Tuple[str, Optional[str]]]:
    """``name``, ``name@1.2.3``, ``@scope/name@^1`` or ``alias@npm:real@1``."""
    if not spec or spec.startswith((".", "/", "~", "$")) or "://" in spec:
        return None
    if re.match(r"^(git\+|git:|github:|gitlab:|bitbucket:|gist:|file:|link:|workspace:|portal:|patch:|jsr:)", spec):
        return None
    if spec.endswith((".tgz", ".tar.gz", ".tar")):
        return None
    m = re.match(r"^((?:@[^/@\s]+/)?[^@/\s]+)(?:@(.*))?$", spec)
    if not m:
        return None  # user/repo GitHub shorthand and friends
    name, ver = m.group(1), m.group(2)
    if ver and ver.startswith("npm:"):
        return npm_spec(ver[4:])
    if ver is not None and (ver.startswith(("git", "file:", "http", "link:", "workspace:")) or "/" in ver):
        return None
    if not re.match(r"^(@[a-z0-9][\w.~-]*/)?[a-z0-9_.~-][\w.~-]*$", name, re.I):
        return None
    return name, (ver or None)


def _create_package(arg: str) -> Optional[str]:
    """``npm create vite`` installs ``create-vite``; ``@scope`` -> ``@scope/create``."""
    m = npm_spec(arg)
    if not m:
        return None
    name, _ = m
    if name.startswith("@"):
        scope, _, rest = name.partition("/")
        return scope + "/create" + ("-" + rest if rest else "")
    return "create-" + name


def _npm_family(words: List[str], ctx: "Context") -> List[Request]:
    tool, args = words[0], words[1:]
    reqs: List[Request] = []
    origin = " ".join(words)
    pos, opts = _positionals(args, NPM_VALUE_FLAGS)
    custom = "--registry" in opts or ctx.npm_custom_registry
    executes = False
    specs: List[str] = []

    if tool in ("npx", "pnpx", "bunx"):
        pkg_flags = opts.get("-p", []) + opts.get("--package", [])
        if pkg_flags:
            specs = pkg_flags
        elif pos:
            specs = [pos[0]]
        executes = True
    elif not pos:
        return []
    else:
        verb, rest = pos[0], pos[1:]
        if tool == "yarn" and verb == "global" and rest:
            verb, rest = rest[0], rest[1:]
        if tool == "pnpm" and verb == "-g":
            verb, rest = rest[0] if rest else "", rest[1:]
        if verb in NPM_INSTALL_VERBS and (tool != "yarn" or verb == "add"):
            specs = rest
        elif verb in ("exec", "x") and tool in ("npm", "bun"):
            pkg_flags = opts.get("-p", []) + opts.get("--package", [])
            specs = pkg_flags or rest[:1]
            executes = True
        elif verb == "dlx" and tool in ("pnpm", "yarn"):
            pkg_flags = opts.get("-p", []) + opts.get("--package", [])
            specs = pkg_flags or rest[:1]
            executes = True
        elif verb in ("create", "init") and rest and tool in ("npm", "pnpm", "yarn", "bun"):
            if verb == "init" and tool == "npm" and rest[0].startswith("-"):
                return []
            name = _create_package(rest[0])
            if name:
                reqs.append(Request("npm", name, None, origin, custom, True))
            return reqs
        else:
            return []

    for spec in specs:
        parsed = npm_spec(spec)
        if not parsed:
            continue
        name, ver = parsed
        reqs.append(Request("npm", name, ver, origin, custom or ctx.npm_scope_private(name), executes))
    return reqs


# -------------------------------------------------------------------- PyPI

PIP_VALUE_FLAGS = {
    "-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url",
    "--extra-index-url", "-f", "--find-links", "-t", "--target", "--prefix", "--root",
    "--platform", "--python-version", "--implementation", "--abi", "--only-binary",
    "--no-binary", "--src", "--upgrade-strategy", "--progress-bar", "--cache-dir", "--log",
    "--trusted-host", "--proxy", "--timeout", "--retries", "--exists-action", "--cert",
    "--client-cert", "--report", "-C", "--config-settings", "--global-option", "--python",
    "-p", "--with", "--from", "--group", "-G", "--source", "--index", "--default-index",
    "--extra", "--optional", "--package", "--directory", "--project", "--python-preference",
    "-w", "--with-requirements", "--dev-group", "--keyring-provider", "--resolution",
    "--prerelease", "--exclude-newer", "--refresh-package", "--reinstall-package",
    "--upgrade-package", "-P", "--suffix", "--pip-args", "--spec", "--include-deps",
}

_PEP508 = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")


def pypi_spec(spec: str) -> Optional[Tuple[str, Optional[str]]]:
    spec = spec.strip().strip("'\"")
    if not spec or spec.startswith((".", "/", "~", "$", "-")) or "://" in spec:
        return None
    if re.search(r"\.(whl|zip|tar\.gz|tgz|tar\.bz2)$", spec) or spec.startswith(("git+", "hg+", "svn+", "bzr+")):
        return None
    if os.sep in spec.split("[")[0] or "/" in spec.split("[")[0]:
        return None
    spec = spec.split(";", 1)[0].strip()
    m = _PEP508.match(spec)
    if not m:
        return None
    name, rest = m.group(1), m.group(3).strip()
    if rest.startswith("@"):
        rest = rest[1:].strip()
        if "://" in rest or rest.startswith(("git", "file")):
            return None  # PEP 508 direct reference
        # poetry/uv style name@1.2.3 / name@^1 / name@latest
        rest = ("==" + rest) if re.match(r"^\d[\w.\-]*$", rest) else ""
    version = None
    em = re.match(r"^===?\s*([\w.\-+!]+)\s*$", rest)
    if em and "*" not in em.group(1):
        version = em.group(1)
    return name, version


def _requirements_file(path: str, cwd: str, depth: int = 0) -> List[Tuple[str, Optional[str]]]:
    full = path if os.path.isabs(path) else os.path.join(cwd, path)
    try:
        with open(full, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return []
    out: List[Tuple[str, Optional[str]]] = []
    for name, ver, nested in manifests.requirements_lines(text):
        if nested and depth < 3:
            out.extend(_requirements_file(nested, os.path.dirname(full), depth + 1))
        elif name:
            out.append((name, ver))
    return out


def _pypi_family(words: List[str], ctx: "Context") -> List[Request]:
    tool, args = words[0], words[1:]
    origin = " ".join(words)
    # python -m pip ..., py -3 -m pip ..., python -m uv ...
    if re.match(r"^(python[0-9.]*|py)$", tool):
        if "-m" not in args:
            return []
        idx = args.index("-m")
        mod = args[idx + 1] if idx + 1 < len(args) else ""
        if mod not in ("pip", "pipx", "uv", "poetry", "pdm"):
            return []
        tool, args = mod, args[idx + 2:]
    if re.match(r"^pip[0-9.]*$", tool):
        tool = "pip"

    pos, opts = _positionals(args, PIP_VALUE_FLAGS)
    custom = any(k in opts for k in ("-i", "--index-url", "--index", "--default-index", "--source")) or ctx.pypi_custom_index
    extra_index = "--extra-index-url" in opts
    executes = False
    specs: List[str] = []
    req_files: List[str] = opts.get("-r", []) + opts.get("--requirement", []) + opts.get("--with-requirements", [])

    if tool == "pip":
        if not pos or pos[0] not in ("install", "download", "wheel"):
            return []
        specs = pos[1:]
    elif tool == "uv":
        if pos[:2] == ["pip", "install"]:
            specs = pos[2:]
        elif pos[:1] == ["add"]:
            specs = pos[1:]
        elif pos[:2] in (["tool", "install"], ["tool", "run"]):
            specs = (opts.get("--from") or pos[2:3]) + opts.get("--with", [])
            executes = pos[1] == "run"
        elif pos[:1] == ["run"]:
            specs = opts.get("--with", [])
        else:
            return []
    elif tool == "uvx":
        specs = (opts.get("--from") or pos[:1]) + opts.get("--with", [])
        executes = True
    elif tool == "pipx":
        if pos[:1] == ["install"]:
            specs = pos[1:]
        elif pos[:1] == ["run"]:
            specs = opts.get("--spec") or pos[1:2]
            executes = True
        elif pos[:1] == ["inject"]:
            specs = pos[2:]
        else:
            return []
    elif tool in ("poetry", "pdm", "rye"):
        if pos[:1] != ["add"]:
            return []
        specs = pos[1:]
    else:
        return []

    pairs: List[Tuple[str, Optional[str]]] = []
    for s in specs:
        p = pypi_spec(s)
        if p:
            pairs.append(p)
    for f in req_files:
        pairs.extend(_requirements_file(f, ctx.cwd))
    return [Request("PyPI", n, v, origin, custom or extra_index, executes) for n, v in pairs]


# --------------------------------------------------------------- crates.io

CARGO_VALUE_FLAGS = {
    "-F", "--features", "--rename", "-p", "--package", "--path", "--git", "--branch", "--tag",
    "--rev", "--registry", "--manifest-path", "--target", "--version", "--vers", "--root",
    "--bin", "--example", "--index", "--profile", "-j", "--jobs", "--target-dir", "--config",
    "-Z", "--color", "--lockfile-path",
}


def _cargo(words: List[str], ctx: "Context") -> List[Request]:
    args = words[1:]
    origin = " ".join(words)
    pos, opts = _positionals(args, CARGO_VALUE_FLAGS)
    if not pos or pos[0] not in ("add", "install", "binstall"):
        return []
    if any(k in opts for k in ("--git", "--path")):
        return []
    custom = any(k in opts for k in ("--registry", "--index"))
    version = (opts.get("--version") or opts.get("--vers") or [None])[0]
    out = []
    for spec in pos[1:]:
        m = re.match(r"^([A-Za-z0-9_-]+)(?:@(.+))?$", spec)
        if not m:
            continue
        ver = m.group(2) or version
        if ver:
            ver = ver.lstrip("=")
        out.append(Request("crates.io", m.group(1), ver, origin, custom, pos[0] != "add"))
    return out


# ---------------------------------------------------------------------- Go


def _go(words: List[str], ctx: "Context") -> List[Request]:
    args = words[1:]
    origin = " ".join(words)
    pos, opts = _positionals(args, {"-modfile", "-C", "-o", "-tags", "-ldflags", "-gcflags", "-mod"})
    if not pos or pos[0] not in ("get", "install", "run"):
        return []
    out = []
    for spec in pos[1:]:
        if spec.startswith((".", "/")) or spec.endswith(".go"):
            continue
        path, _, ver = spec.partition("@")
        if ver == "none":
            continue  # go get pkg@none removes a dependency
        first = path.split("/")[0]
        if "." not in first or "..." in path:
            continue  # standard library or pattern
        if pos[0] == "run" and not ver:
            continue  # go run pkg without @version builds the local module
        if ctx.go_private(path):
            continue
        out.append(Request("Go", path, ver or None, origin, False, pos[0] != "get"))
    return out


# -------------------------------------------------------- RubyGems / PHP


def _gem(words: List[str], ctx: "Context") -> List[Request]:
    tool, args = words[0], words[1:]
    origin = " ".join(words)
    flags = {"-v", "--version", "-s", "--source", "-i", "--install-dir", "-n", "--bindir",
             "--platform", "-g", "--file", "--group", "--git", "--github", "--path", "--branch",
             "--ref", "-r", "--require", "--glob"}
    pos, opts = _positionals(args, flags)
    if tool == "gem" and pos[:1] == ["install"]:
        names = pos[1:]
    elif tool == "bundle" and pos[:1] == ["add"]:
        names = pos[1:]
    else:
        return []
    if any(k in opts for k in ("--git", "--github", "--path")):
        return []
    custom = any(k in opts for k in ("-s", "--source"))
    version = (opts.get("-v") or opts.get("--version") or [None])[0]
    if version and not re.match(r"^\d[\w.]*$", version):
        version = None
    out = []
    for n in names:
        if n.endswith(".gem") or "/" in n:
            continue
        name, _, ver = n.partition(":")
        if re.match(r"^[A-Za-z0-9][\w.-]*$", name):
            out.append(Request("RubyGems", name, ver or version, origin, custom, tool == "gem"))
    return out


def _composer(words: List[str], ctx: "Context") -> List[Request]:
    args = words[1:]
    origin = " ".join(words)
    pos, _ = _positionals(args, {"--working-dir", "-d"})
    if not pos or pos[0] not in ("require", "global", "create-project"):
        return []
    if pos[0] == "global":
        pos = pos[1:]
        if pos[:1] != ["require"]:
            return []
    specs = pos[1:2] if pos[0] == "create-project" else pos[1:]
    out = []
    for spec in specs:
        name, _, ver = spec.replace("=", ":").partition(":")
        if re.match(r"^[a-z0-9][\w.-]*/[a-z0-9][\w.-]*$", name, re.I) and not name.startswith(("php", "ext-", "lib-")):
            out.append(Request("Packagist", name.lower(), ver or None, origin, False, False))
    return out


# -------------------------------------------------------------- dispatch

HANDLERS: Dict[str, Callable[[List[str], "Context"], List[Request]]] = {}
for _t in ("npm", "pnpm", "yarn", "bun", "npx", "pnpx", "bunx"):
    HANDLERS[_t] = _npm_family
for _t in ("pip", "pip3", "uv", "uvx", "pipx", "poetry", "pdm", "rye", "python", "python3", "py"):
    HANDLERS[_t] = _pypi_family
HANDLERS["cargo"] = _cargo
HANDLERS["go"] = _go
HANDLERS["gem"] = _gem
HANDLERS["bundle"] = _gem
HANDLERS["composer"] = _composer


class Context:
    """Which registries are private, from the user's .pivyon-shield.json.

    Package managers' own config files and index-URL variables are never
    read: they routinely hold auth tokens.
    """

    def __init__(self, cwd: str, env: Optional[dict] = None, cfg=None):
        from . import config

        self.cwd = cwd or os.getcwd()
        env = os.environ if env is None else env
        cfg = cfg if cfg is not None else config.load(self.cwd, env)
        self.npm_scopes: Set[str] = set(cfg.private_npm_scopes)
        self.npm_custom_registry = cfg.private_npm_registry
        self.pypi_custom_index = cfg.private_pypi_index
        self.go_private_patterns = [
            p.strip() for p in (env.get("GOPRIVATE", "") + "," + env.get("GONOPROXY", "")).split(",") if p.strip()
        ]

    def npm_scope_private(self, name: str) -> bool:
        return name.startswith("@") and name.split("/")[0] in self.npm_scopes

    def go_private(self, path: str) -> bool:
        import fnmatch

        for pat in self.go_private_patterns:
            n = len(pat.split("/"))
            prefix = "/".join(path.split("/")[:n])
            if fnmatch.fnmatch(prefix, pat):
                return True
        return False


def packages_in_command(cmd: str, ctx: Context) -> List[Request]:
    reqs: List[Request] = []
    for words in split_commands(cmd):
        words = _unwrap(words)
        if not words:
            continue
        handler = HANDLERS.get(words[0])
        if handler is None and re.match(r"^(pip|python)[0-9.]+$", words[0]):
            handler = _pypi_family
        if handler:
            try:
                reqs.extend(handler(words, ctx))
            except (IndexError, ValueError):
                continue
    return dedupe(reqs)


def dedupe(reqs: Iterable[Request]) -> List[Request]:
    seen = set()
    out = []
    for r in reqs:
        if r.key in seen:
            continue
        seen.add(r.key)
        out.append(r)
    return out
