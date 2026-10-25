import io
import json
import os
import tempfile
import unittest

import fakenet
from fakenet import NPM, FakeNet, install, npm_doc
from pivyon_shield import config, hook, lockfiles, audit
from pivyon_shield.commands import Request
from pivyon_shield.net import NetError
from pivyon_shield.policy import evaluate


def cfg(**kw):
    c = config.Config()
    for k, v in kw.items():
        setattr(c, k, v)
    return c


def run_hook(payload):
    out = io.StringIO()
    hook.main(io.StringIO(json.dumps(payload)), out)
    text = out.getvalue().strip()
    return json.loads(text)["hookSpecificOutput"] if text else None


class Policy(unittest.TestCase):
    def setUp(self):
        self.net = install(FakeNet())
        os.environ["PIVYON_SHIELD_NO_CACHE"] = "1"

    def level(self, eco, name, version=None, **kw):
        return evaluate(Request(eco, name, version, "test", kw.pop("custom", False)), cfg(**kw))

    def test_nonexistent_is_blocked_with_suggestion(self):
        v = self.level("PyPI", "reqeusts")
        self.assertEqual(v.level, "block")
        self.assertIn("Did you mean 'requests'", v.findings[0].message)

    def test_nonexistent_on_private_index_only_warns(self):
        self.assertEqual(self.level("npm", "corp-internal-thing", custom=True).level, "warn")

    def test_security_holding_package(self):
        self.net.route(NPM + "crossenv", npm_doc("crossenv", {"0.0.1-security": 2000}, description="security holding package"))
        self.assertEqual(self.level("npm", "crossenv").level, "block")

    def test_osv_malware(self):
        self.net.route(NPM + "cxp-jquery", npm_doc("cxp-jquery", {"1.0.0": 400}, created_days=400))
        self.net.osv[("npm", "cxp-jquery")] = [("MAL-2021-1", None)]
        v = self.level("npm", "cxp-jquery")
        self.assertEqual(v.level, "block")
        self.assertIn("MALICIOUS", v.findings[0].message)

    def test_brand_new_package_asks(self):
        self.net.route(NPM + "shiny-new-helper", npm_doc("shiny-new-helper", {"0.0.1": 2}, created_days=2))
        v = self.level("npm", "shiny-new-helper")
        self.assertEqual(v.level, "confirm")
        self.assertIn("first published only 2 days ago", v.findings[0].message)

    def test_lookalike_asks(self):
        self.net.route(NPM + "expresss", npm_doc("expresss", {"0.0.0": 3000}))
        v = self.level("npm", "expresss")
        self.assertEqual(v.level, "confirm")
        self.assertIn("'express'", v.findings[0].message)

    def test_fresh_release_of_popular_package_asks(self):
        abbreviated = {"name": "chalk", "dist-tags": {"latest": "5.6.1"}, "modified": fakenet.iso(hours_ago=2),
                       "versions": {"5.6.0": {}, "5.6.1": {}}}
        self.net.route(NPM + "chalk", npm_doc("chalk", {"5.6.0": 300, "5.6.1": 2 / 24.0}))
        v = self.level("npm", "chalk")
        self.assertEqual(v.level, "confirm")
        self.assertIn("cooldown", v.findings[0].message)
        self.assertEqual(self.level("npm", "chalk", "5.6.0").level, "ok")
        self.assertEqual(self.level("npm", "chalk", cooldown_hours=0).level, "ok")
        del abbreviated

    def test_popular_stable_package_uses_abbreviated_metadata(self):
        self.net.route(NPM + "react", {"name": "react", "dist-tags": {"latest": "19.0.0"},
                                       "modified": fakenet.iso(days_ago=30), "versions": {"19.0.0": {}}})
        self.assertEqual(self.level("npm", "react").level, "ok")

    def test_vulnerable_pinned_version(self):
        self.net.route(NPM + "lodash", npm_doc("lodash", {"4.17.15": 2000, "4.17.21": 1500}))
        self.net.osv[("npm", "lodash")] = [("GHSA-p6mc-m468-83gw", ["4.17.15"]), ("GHSA-35jh-r3h4-6jhm", ["4.17.15"])]
        v = self.level("npm", "lodash", "4.17.15")
        self.assertEqual(v.level, "warn")  # high is below the default "critical" ask threshold
        self.assertEqual(v.fix_version, "4.17.21")
        self.assertEqual(self.level("npm", "lodash", "4.17.15", block_vulnerable="high").level, "confirm")
        self.assertEqual(self.level("npm", "lodash").level, "ok")  # latest is clean

    def test_install_scripts_and_low_adoption(self):
        self.net.route(NPM + "tiny-native-thing", npm_doc("tiny-native-thing", {"1.0.0": 200}, created_days=200,
                                                          scripts={"postinstall": "node x.js"}))
        self.net.route("https://api.npmjs.org/downloads/point/last-week/tiny-native-thing", {"downloads": 3})
        v = self.level("npm", "tiny-native-thing")
        self.assertEqual(v.level, "warn")
        text = " ".join(f.message for f in v.findings)
        self.assertIn("install scripts", text)
        self.assertIn("3 downloads", text)

    def test_offline_fails_open(self):
        self.net.route(NPM + "anything-at-all", NetError("offline"))
        self.assertEqual(self.level("npm", "anything-at-all").level, "unverified")

    def test_allow_and_deny_lists(self):
        self.assertEqual(self.level("PyPI", "reqeusts", allow=["pypi:reqeusts"]).level, "ok")
        self.assertEqual(self.level("npm", "react", deny=["react"]).level, "block")

    def test_pypi_vulns_from_registry_when_osv_is_down(self):
        self.net.osv_down = True
        doc = {"info": {"version": "1.26.4", "name": "urllib3"},
               "releases": {"1.26.4": [{"upload_time_iso_8601": "2021-03-15T00:00:00Z"}]},
               "vulnerabilities": [{"id": "PYSEC-2021-108", "aliases": ["CVE-2021-33503", "GHSA-q2q7-5pp4-w6pg"],
                                    "fixed_in": ["1.26.5"], "details": "ReDoS"},
                                   {"id": "GHSA-q2q7-5pp4-w6pg", "aliases": ["CVE-2021-33503", "PYSEC-2021-108"],
                                    "fixed_in": ["1.26.5"], "details": "ReDoS"}]}
        self.net.route("https://pypi.org/pypi/urllib3/json", doc)
        v = self.level("PyPI", "urllib3", "1.26.4")
        self.assertEqual(len(v.vulns), 1)
        self.assertEqual(v.fix_version, "1.26.5")


class Hook(unittest.TestCase):
    def setUp(self):
        self.net = install(FakeNet())
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["PIVYON_SHIELD_NO_CACHE"] = "1"
        for k in ("PIVYON_SHIELD_MODE", "PIVYON_SHIELD_ALLOW"):
            os.environ.pop(k, None)

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("PIVYON_SHIELD_MODE", None)

    def bash(self, command):
        return run_hook({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": self.tmp.name})

    def test_deny(self):
        out = self.bash("npm install definitely-not-real-zz9")
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("does not exist on npm", out["permissionDecisionReason"])

    def test_ask(self):
        self.net.route(NPM + "fresh-pkg-xyz", npm_doc("fresh-pkg-xyz", {"0.1.0": 1}, created_days=1))
        out = self.bash("pnpm add fresh-pkg-xyz")
        self.assertEqual(out["permissionDecision"], "ask")

    def test_silent_when_clean_or_unrelated(self):
        self.net.route(NPM + "react", {"name": "react", "dist-tags": {"latest": "19.0.0"},
                                       "modified": fakenet.iso(days_ago=30), "versions": {"19.0.0": {}}})
        self.assertIsNone(self.bash("npm install react"))
        self.assertIsNone(self.bash("ls -la && git status"))

    def test_warn_mode_never_blocks(self):
        os.environ["PIVYON_SHIELD_MODE"] = "warn"
        out = self.bash("npm install definitely-not-real-zz9")
        self.assertNotIn("permissionDecision", out)
        self.assertIn("[would block]", out["additionalContext"])

    def test_off_mode(self):
        os.environ["PIVYON_SHIELD_MODE"] = "off"
        self.assertIsNone(self.bash("npm install definitely-not-real-zz9"))

    def test_project_allow_file(self):
        with open(os.path.join(self.tmp.name, ".pivyon-shield.json"), "w") as fh:
            json.dump({"allow": ["npm:definitely-not-real-zz9"]}, fh)
        self.assertIsNone(self.bash("npm install definitely-not-real-zz9"))

    def test_manifest_edit_is_vetted(self):
        path = os.path.join(self.tmp.name, "package.json")
        with open(path, "w") as fh:
            fh.write('{\n  "dependencies": {\n    "react": "^19.0.0"\n  }\n}\n')
        out = run_hook({"tool_name": "Edit", "cwd": self.tmp.name, "tool_input": {
            "file_path": path, "old_string": '"react": "^19.0.0"',
            "new_string": '"react": "^19.0.0",\n    "react-codeshift-helper": "^1.0.0"'}})
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("react-codeshift-helper", out["permissionDecisionReason"])
        self.assertNotIn("npm react:", out["permissionDecisionReason"])

    def test_write_requirements(self):
        path = os.path.join(self.tmp.name, "requirements.txt")
        out = run_hook({"tool_name": "Write", "cwd": self.tmp.name,
                        "tool_input": {"file_path": path, "content": "reqeusts==2.31.0\n"}})
        self.assertEqual(out["permissionDecision"], "deny")

    def test_non_manifest_edit_ignored(self):
        self.assertIsNone(run_hook({"tool_name": "Write", "cwd": self.tmp.name, "tool_input": {
            "file_path": os.path.join(self.tmp.name, "notes.md"), "content": "npm install nothing-real"}}))

    def test_garbage_input_is_ignored(self):
        out = io.StringIO()
        self.assertEqual(hook.main(io.StringIO("not json"), out), 0)
        self.assertEqual(out.getvalue(), "")


class Audit(unittest.TestCase):
    def setUp(self):
        self.net = install(FakeNet())
        os.environ["PIVYON_SHIELD_NO_CACHE"] = "1"
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name

        def w(rel, text):
            p = os.path.join(d, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as fh:
                fh.write(text)

        w("package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
            "": {"dependencies": {"lodash": "^4.17.0"}},
            "node_modules/lodash": {"version": "4.17.15", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz"},
            "node_modules/cxp-jquery": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/x.tgz", "dev": True},
            "node_modules/a/node_modules/ms": {"version": "2.1.3", "resolved": "https://registry.npmjs.org/ms.tgz"},
            "node_modules/linked": {"link": True},
        }}))
        w("py/requirements.txt", "urllib3==1.26.4\nrequests>=2\n")
        w("yarn.lock", '# yarn lockfile v1\n\n"left-pad@^1.0.0", left-pad@^1.3.0:\n  version "1.3.0"\n  resolved "x"\n')
        w("pnpm-lock.yaml", "lockfileVersion: '9.0'\n\npackages:\n\n  '@scope/pkg@1.2.3':\n    resolution: {}\n\n"
                            "  zod@3.22.4:\n    resolution: {}\n\nsnapshots:\n\n  zod@3.22.4: {}\n")
        w("rust/Cargo.lock", 'version = 3\n\n[[package]]\nname = "serde"\nversion = "1.0.200"\n'
                             'source = "registry+https://github.com/rust-lang/crates.io-index"\n\n'
                             '[[package]]\nname = "mine"\nversion = "0.1.0"\n')
        w("go/go.mod", "module x\n\nrequire (\n\tgithub.com/gorilla/mux v1.8.0\n\tgolang.org/x/net v0.1.0 // indirect\n)\n")
        w("rb/Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.3)\n    nokogiri (1.15.0-x86_64-linux)\n\n"
                             "PLATFORMS\n  ruby\n")
        w("node_modules/ignored/package-lock.json", "{}")
        self.net.osv[("npm", "lodash")] = [("GHSA-p6mc-m468-83gw", ["4.17.15"]), ("GHSA-35jh-r3h4-6jhm", ["4.17.15"])]
        self.net.osv[("npm", "cxp-jquery")] = [("MAL-2021-1", None)]
        self.net.osv[("PyPI", "urllib3")] = [("GHSA-q2q7-5pp4-w6pg", ["1.26.4"]), ("PYSEC-2021-108", ["1.26.4"])]

    def tearDown(self):
        self.tmp.cleanup()

    def test_lockfile_coverage(self):
        deps = {(d.ecosystem, d.name, d.version) for d in lockfiles.collect(self.tmp.name)}
        expected = {("npm", "lodash", "4.17.15"), ("npm", "cxp-jquery", "1.0.0"), ("npm", "ms", "2.1.3"),
                    ("PyPI", "urllib3", "1.26.4"), ("npm", "left-pad", "1.3.0"), ("npm", "@scope/pkg", "1.2.3"),
                    ("npm", "zod", "3.22.4"), ("crates.io", "serde", "1.0.200"), ("Go", "github.com/gorilla/mux", "v1.8.0"),
                    ("Go", "golang.org/x/net", "v0.1.0"), ("RubyGems", "rack", "2.2.3"), ("RubyGems", "nokogiri", "1.15.0")}
        self.assertEqual(deps, expected)

    def test_report(self):
        report = audit.run(self.tmp.name)
        names = [f["name"] for f in report["findings"]]
        self.assertEqual(names[0], "cxp-jquery")  # malware first
        self.assertEqual(set(names), {"cxp-jquery", "lodash", "urllib3"})
        lodash = next(f for f in report["findings"] if f["name"] == "lodash")
        self.assertTrue(lodash["direct"])
        self.assertEqual(lodash["fix"], "4.17.21")
        self.assertEqual(lodash["severity"], "high")  # CVSS 7.4 and 7.2
        urllib3 = next(f for f in report["findings"] if f["name"] == "urllib3")
        self.assertEqual(len(urllib3["vulns"]), 1)  # GHSA + PYSEC merged
        self.assertEqual(urllib3["fix"], "1.26.5")
        md = audit.to_markdown(report)
        self.assertIn("**MALICIOUS**", md)
        self.assertIn("4.17.21", md)

    def test_fail_on_exit_codes(self):
        import contextlib

        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(audit.main([self.tmp.name, "--fail-on", "critical"]), 1)
            self.net.osv_down = True
            self.assertEqual(audit.main([self.tmp.name]), 2)


if __name__ == "__main__":
    unittest.main()
