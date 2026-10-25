"""Settings, read from (later wins): defaults, ~/.config/pivyon-shield/config.json,
<project>/.pivyon-shield.json, then PIVYON_SHIELD_* environment variables.

    {
      "mode": "enforce",          // enforce | warn | off
      "cooldown_hours": 24,       // ask before installing a release younger than this
      "new_package_days": 30,     // ask before installing a non-popular package younger than this
      "block_vulnerable": "critical", // ask on known vulns at/above: critical|high|medium|low|never
      "allow": ["npm:my-internal-pkg", "PyPI:our-tool"],
      "deny":  ["npm:event-stream"]
    }
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Config:
    mode: str = "enforce"
    cooldown_hours: float = 24.0
    new_package_days: float = 30.0
    block_vulnerable: str = "critical"
    allow: List[str] = field(default_factory=list)
    deny: List[str] = field(default_factory=list)

    def _match(self, entries: List[str], ecosystem: str, name: str) -> bool:
        low = name.lower()
        for e in entries:
            e = e.strip()
            if ":" in e and not e.startswith("@"):
                eco, _, n = e.partition(":")
                if eco.lower() == ecosystem.lower() and n.lower() == low:
                    return True
            elif e.lower() == low:
                return True
        return False

    def allowed(self, ecosystem: str, name: str) -> bool:
        return self._match(self.allow, ecosystem, name)

    def denied(self, ecosystem: str, name: str) -> bool:
        return self._match(self.deny, ecosystem, name)


def _merge(cfg: Config, data: dict) -> None:
    if not isinstance(data, dict):
        return
    if data.get("mode") in ("enforce", "warn", "off"):
        cfg.mode = data["mode"]
    for key in ("cooldown_hours", "new_package_days"):
        if isinstance(data.get(key), (int, float)):
            setattr(cfg, key, float(data[key]))
    if data.get("block_vulnerable") in ("critical", "high", "medium", "low", "never"):
        cfg.block_vulnerable = data["block_vulnerable"]
    for key in ("allow", "deny"):
        if isinstance(data.get(key), list):
            getattr(cfg, key).extend(str(x) for x in data[key])


def _read(path: str) -> Optional[dict]:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _project_root(cwd: str) -> str:
    d = os.path.abspath(cwd)
    while True:
        if os.path.exists(os.path.join(d, ".pivyon-shield.json")) or os.path.exists(os.path.join(d, ".git")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            return os.path.abspath(cwd)
        d = parent


def load(cwd: str, env: Optional[dict] = None) -> Config:
    env = os.environ if env is None else env
    cfg = Config()
    xdg = env.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    for path in (os.path.join(xdg, "pivyon-shield", "config.json"),
                 os.path.join(_project_root(cwd), ".pivyon-shield.json")):
        data = _read(path)
        if data:
            _merge(cfg, data)
    overrides: dict = {}
    if env.get("PIVYON_SHIELD_MODE"):
        overrides["mode"] = env["PIVYON_SHIELD_MODE"].strip().lower()
    for key in ("cooldown_hours", "new_package_days"):
        raw = env.get("PIVYON_SHIELD_" + key.upper())
        if raw:
            try:
                overrides[key] = float(raw)
            except ValueError:
                pass
    if env.get("PIVYON_SHIELD_BLOCK_VULNERABLE"):
        overrides["block_vulnerable"] = env["PIVYON_SHIELD_BLOCK_VULNERABLE"].strip().lower()
    for key in ("allow", "deny"):
        raw = env.get("PIVYON_SHIELD_" + key.upper())
        if raw:
            overrides[key] = [x for x in raw.split(",") if x.strip()]
    _merge(cfg, overrides)
    return cfg
