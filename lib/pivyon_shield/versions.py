"""Ecosystem-agnostic version helpers.

Good enough to order semver, PEP 440 and Go/Ruby style versions for the
questions this plugin asks ("which fixed release is the nearest upgrade?").
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

_SPLIT = re.compile(r"(\d+|[a-zA-Z]+)")
_PRE_TAGS = {"dev": -4, "a": -3, "alpha": -3, "b": -2, "beta": -2, "pre": -2,
             "c": -1, "rc": -1, "preview": -1}


def version_key(version: str) -> Tuple:
    """Sortable key. Pre-releases sort before the release they precede."""
    v = version.strip().lstrip("vV=")
    v = v.split("+", 1)[0]  # build metadata never orders
    parts: List[Tuple[int, int, str]] = []
    for tok in _SPLIT.findall(v):
        if tok.isdigit():
            parts.append((1, int(tok), ""))
        else:
            low = tok.lower()
            if low in ("post", "p", "r", "patch"):
                parts.append((2, 0, low))
            else:
                parts.append((0, _PRE_TAGS.get(low, -5), low))
    # Pad numeric tails so 1.2 == 1.2.0 and 1.2.0 > 1.2.0-rc1.
    while len(parts) < 3 or parts[-1][0] == 0:
        if len(parts) >= 3 and parts[-1][0] == 0:
            break
        parts.append((1, 0, ""))
    parts.append((1, -1, ""))  # terminator: a release outranks its pre-releases
    return tuple(parts)


def compare(a: str, b: str) -> int:
    ka, kb = version_key(a), version_key(b)
    return (ka > kb) - (ka < kb)


EXACT_SEMVER = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-+]+)?$")


def is_exact(version: Optional[str]) -> bool:
    return bool(version) and bool(EXACT_SEMVER.match(version or ""))


def nearest_fix(current: str, fixed: List[str]) -> Optional[str]:
    """Smallest fixed version greater than ``current`` (same major if possible)."""
    above = sorted({f for f in fixed if f and compare(f, current) > 0}, key=version_key)
    if not above:
        return None
    major = version_key(current)[0]
    same_major = [f for f in above if version_key(f)[0] == major]
    return (same_major or above)[0]
