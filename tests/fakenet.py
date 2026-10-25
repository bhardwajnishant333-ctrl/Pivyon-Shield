"""Offline stand-in for pivyon_shield.net.request_json used by the tests."""

import datetime as dt
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "lib"))

from pivyon_shield import osv, registries  # noqa: E402
from pivyon_shield.net import NetError, NotFound  # noqa: E402

FIXTURES = os.path.join(HERE, "fixtures")


def iso(days_ago=0.0, hours_ago=0.0):
    t = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days_ago, hours=hours_ago)
    return t.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def osv_doc(vid):
    with open(os.path.join(FIXTURES, "osv", vid + ".json")) as fh:
        return json.load(fh)


def npm_doc(name, versions, created_days=3000, latest=None, scripts=None, description="", modified_days=None):
    """versions: {version: days_ago}"""
    latest = latest or list(versions)[-1]
    times = {"created": iso(created_days), "modified": iso(modified_days if modified_days is not None else min(versions.values()))}
    times.update({v: iso(d) for v, d in versions.items()})
    return {
        "name": name,
        "description": description,
        "dist-tags": {"latest": latest},
        "versions": {v: {"name": name, "version": v, "scripts": scripts or {}} for v in versions},
        "time": times,
        "license": "MIT",
    }


class FakeNet:
    def __init__(self):
        self.routes = {}
        self.osv = {}  # (ecosystem, name) -> [(vuln_id, affected_versions or None)]
        self.osv_down = False
        self.calls = []

    def route(self, url, value):
        self.routes[url] = value

    def __call__(self, url, *, data=None, headers=None, ttl=0, timeout=None, shrink=None):
        value = self._answer(url, data)
        return shrink(value) if shrink else value

    def _answer(self, url, data):
        self.calls.append(url)
        if url.startswith(osv.OSV_API):
            if self.osv_down:
                raise NetError("osv down")
            return self._osv(url, data)
        if url in self.routes:
            value = self.routes[url]
            if isinstance(value, Exception):
                raise value
            return value
        if "api.npmjs.org/downloads" in url:
            raise NetError("downloads api not faked")
        raise NotFound(url)

    def _hits(self, eco, name, version):
        out = []
        for vid, versions in self.osv.get((eco, name), []):
            if version is None or versions is None or version in versions:
                out.append(vid)
        return out

    def _osv(self, url, data):
        if url.endswith("/query"):
            pkg = data["package"]
            ids = self._hits(pkg["ecosystem"], pkg["name"], data.get("version"))
            return {"vulns": [osv_doc(i) for i in ids]} if ids else {}
        if url.endswith("/querybatch"):
            results = []
            for q in data["queries"]:
                ids = self._hits(q["package"]["ecosystem"], q["package"]["name"], q.get("version"))
                results.append({"vulns": [{"id": i, "modified": "x"} for i in ids]} if ids else {})
            return {"results": results}
        m = re.search(r"/vulns/(.+)$", url)
        if m:
            return osv_doc(m.group(1))
        raise NotFound(url)


def install(fake):
    """Patch every module that imported request_json by name."""
    registries.request_json = fake
    osv.request_json = fake
    return fake


NPM = registries.NPM_REGISTRY
