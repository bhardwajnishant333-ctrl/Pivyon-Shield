"""Lookalike detection against the most-downloaded packages of each ecosystem.

Data files in ``data/`` list popular names, most popular first. A name that is
itself popular is never flagged; a rare name one keystroke away from a popular
one (``reqeusts``, ``expresss``, ``python-dateutils``) is.
"""

from __future__ import annotations

import os
import re
from functools import lru_cache
from typing import FrozenSet, List, Optional, Tuple

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data")
FILES = {"npm": "npm.txt", "PyPI": "pypi.txt", "crates.io": "crates.txt", "RubyGems": "rubygems.txt"}
TARGETS = 3000  # how many of the most popular names to compare against

AFFIXES_PRE = ("node-", "python-", "py-", "py", "js-", "lib", "go-", "rust-", "ruby-", "the-", "real-", "official-")
AFFIXES_SUF = ("-js", "js", ".js", "-node", "-py", "py", "-python", "-lib", "lib", "-rs", "-rb", "-cli",
               "-dev", "-official", "2", "3", "-sdk", "-api", "-core", "-utils", "-tools", "-helper", "-helpers")


def normalize(ecosystem: str, name: str) -> str:
    n = name.lower()
    if ecosystem == "PyPI":
        n = re.sub(r"[-_.]+", "-", n)
    if ecosystem == "crates.io":
        n = n.replace("_", "-")
    return n


@lru_cache(maxsize=None)
def _load(ecosystem: str) -> Tuple[List[str], FrozenSet[str]]:
    fname = FILES.get(ecosystem)
    if not fname:
        return [], frozenset()
    names: List[str] = []
    try:
        with open(os.path.join(DATA_DIR, fname), encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    names.append(normalize(ecosystem, line))
    except OSError:
        return [], frozenset()
    return names, frozenset(names)


def popularity_rank(ecosystem: str, name: str) -> Optional[int]:
    names, known = _load(ecosystem)
    n = normalize(ecosystem, name)
    if n not in known:
        return None
    return names.index(n) + 1


def is_popular(ecosystem: str, name: str) -> bool:
    return normalize(ecosystem, name) in _load(ecosystem)[1]


def _osa(a: str, b: str, limit: int = 2) -> int:
    """Optimal string alignment distance (Damerau-Levenshtein with adjacent swaps)."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: List[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
        if min(prev) > limit:
            return limit + 1
    return prev[-1]


def _squash(s: str) -> str:
    return re.sub(r"[-_.]", "", s)


def lookalike(ecosystem: str, name: str) -> Optional[Tuple[str, str]]:
    """Return (popular_name, how) if ``name`` imitates a popular package."""
    names, known = _load(ecosystem)
    if not names:
        return None
    n = normalize(ecosystem, name)
    if n in known:
        return None
    scope = ""
    bare = n
    if ecosystem == "npm" and n.startswith("@") and "/" in n:
        scope, bare = n.split("/", 1)
    for target in names[:TARGETS]:
        t_bare = target.split("/", 1)[1] if target.startswith("@") and "/" in target else target
        if scope and target.startswith("@"):
            # @types/nodee vs @types/node: compare within the same scope only.
            if target.split("/", 1)[0] != scope:
                continue
            cand, tgt = bare, t_bare
        elif scope or target.startswith("@"):
            continue
        else:
            cand, tgt = n, target
        if len(tgt) < 4:
            continue
        if _squash(cand) == _squash(tgt) and cand != tgt:
            return target, "same name with different separators"
        if len(tgt) >= 5 and _osa(cand, tgt, 1) == 1:
            if cand.isdigit() or re.sub(r"\d", "", cand) == re.sub(r"\d", "", tgt):
                continue  # version-ish variants (vue2/vue3) are usually legit
            return target, "one character away"
    # Affix pass on the top names only: lodash-utils, python-requests, ...
    for target in names[:500]:
        if len(target) < 4 or target.startswith("@"):
            continue
        for p in AFFIXES_PRE:
            if n == p + target:
                return target, "popular name with a '%s' prefix" % p
        for s in AFFIXES_SUF:
            if n == target + s:
                return target, "popular name with a '%s' suffix" % s
    return None
