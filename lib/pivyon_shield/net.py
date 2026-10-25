"""Tiny HTTP layer: JSON GET/POST with a timeout, a disk cache and no deps.

Every failure is reported as a NetError so callers can fail open: a guard
that blocks work whenever the network hiccups is a guard people uninstall.
"""

from __future__ import annotations

import hashlib
import json
import os
import ssl
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Optional

from . import USER_AGENT

DEFAULT_TIMEOUT = float(os.environ.get("PIVYON_SHIELD_TIMEOUT", "6"))


class NetError(Exception):
    """The request could not be completed (offline, timeout, 5xx, bad JSON)."""


class NotFound(Exception):
    """The server answered 404 or 410: the thing does not exist."""


def _cache_dir() -> Optional[str]:
    if os.environ.get("PIVYON_SHIELD_NO_CACHE"):
        return None
    base = os.environ.get("PIVYON_SHIELD_CACHE_DIR")
    if not base:
        xdg = os.environ.get("XDG_CACHE_HOME") or os.path.join(
            os.path.expanduser("~"), ".cache"
        )
        base = os.path.join(xdg, "pivyon-shield")
    try:
        os.makedirs(base, exist_ok=True)
    except OSError:
        return None
    return base


def _cache_path(key: str) -> Optional[str]:
    base = _cache_dir()
    if not base:
        return None
    return os.path.join(base, hashlib.sha256(key.encode()).hexdigest()[:40] + ".json")


def _cache_get(key: str, ttl: float) -> Any:
    path = _cache_path(key)
    if not path or ttl <= 0:
        return None
    try:
        if time.time() - os.path.getmtime(path) > ttl:
            return None
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _cache_put(key: str, value: Any) -> None:
    path = _cache_path(key)
    if not path:
        return
    tmp = "%s.%d.tmp" % (path, os.getpid())
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(value, fh)
        os.replace(tmp, path)
    except (OSError, TypeError, ValueError):
        try:
            os.unlink(tmp)
        except OSError:
            pass


_NOT_FOUND_MARK = {"__pivyon_shield_not_found__": True}


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    bundle = os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE")
    if bundle and os.path.exists(bundle):
        try:
            ctx.load_verify_locations(bundle)
        except (OSError, ssl.SSLError):
            pass
    return ctx


def request_json(
    url: str,
    *,
    data: Any = None,
    headers: Optional[dict] = None,
    ttl: float = 3600,
    timeout: Optional[float] = None,
    shrink: Optional[Callable[[Any], Any]] = None,
) -> Any:
    """GET (or POST when ``data`` is given) a JSON document.

    Raises NotFound on 404/410 and NetError on anything else that went wrong.
    Both successes and not-found answers are cached for ``ttl`` seconds.
    ``shrink`` trims a large document to the fields callers use before it is
    cached and returned (npm metadata for big packages runs to megabytes).
    """
    body = None if data is None else json.dumps(data).encode()
    key = url + "\n" + (body.decode() if body else "") + json.dumps(headers or {}, sort_keys=True)
    cached = _cache_get(key, ttl)
    if cached is not None:
        if cached == _NOT_FOUND_MARK:
            raise NotFound(url)
        return cached

    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    hdrs.update(headers or {})
    if body is not None:
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=hdrs)
    try:
        with urllib.request.urlopen(
            req, timeout=timeout or DEFAULT_TIMEOUT, context=_ssl_context()
        ) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        if exc.code in (404, 410):
            _cache_put(key, _NOT_FOUND_MARK)
            raise NotFound(url) from None
        raise NetError("%s -> HTTP %s" % (url, exc.code)) from None
    except Exception as exc:  # URLError, timeout, ssl, connection reset...
        raise NetError("%s -> %s" % (url, exc)) from None
    try:
        value = json.loads(raw.decode("utf-8"))
    except ValueError:
        raise NetError("%s -> invalid JSON" % url) from None
    if shrink is not None:
        try:
            value = shrink(value)
        except (AttributeError, TypeError, KeyError):
            pass
    _cache_put(key, value)
    return value
