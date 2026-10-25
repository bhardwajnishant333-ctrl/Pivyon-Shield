import os
import tempfile
import unittest

import fakenet  # noqa: F401  (sets sys.path)
from pivyon_shield import manifests, osv, typosquat, versions
from pivyon_shield.commands import Context, packages_in_command


def pkgs(cmd, cwd="/nonexistent", env=None):
    return [(r.ecosystem, r.name, r.version) for r in packages_in_command(cmd, Context(cwd, env or {}))]


class CommandParsing(unittest.TestCase):
    def test_npm_family(self):
        self.assertEqual(pkgs("npm install express"), [("npm", "express", None)])
        self.assertEqual(pkgs("npm i -D @types/node@20.1.0 typescript"),
                         [("npm", "@types/node", "20.1.0"), ("npm", "typescript", None)])
        self.assertEqual(pkgs("pnpm add zod@^3 --filter web"), [("npm", "zod", "^3")])
        self.assertEqual(pkgs("yarn add left-pad"), [("npm", "left-pad", None)])
        self.assertEqual(pkgs("yarn global add serve"), [("npm", "serve", None)])
        self.assertEqual(pkgs("bun add hono"), [("npm", "hono", None)])
        self.assertEqual(pkgs("npm install"), [])
        self.assertEqual(pkgs("npm ci"), [])
        self.assertEqual(pkgs("yarn"), [])
        self.assertEqual(pkgs("npm run build"), [])
        self.assertEqual(pkgs("npm install ./local-pkg ../x.tgz github:user/repo user/repo git+https://x/y.git"), [])
        self.assertEqual(pkgs("npm i alias@npm:real-pkg@1.0.0"), [("npm", "real-pkg", "1.0.0")])

    def test_executors_and_create(self):
        self.assertEqual(pkgs("npx -y cowsay hello"), [("npm", "cowsay", None)])
        self.assertEqual(pkgs("npx -p typescript tsc --init"), [("npm", "typescript", None)])
        self.assertEqual(pkgs("pnpm dlx create-vite my-app"), [("npm", "create-vite", None)])
        self.assertEqual(pkgs("bunx prettier --write ."), [("npm", "prettier", None)])
        self.assertEqual(pkgs("npm create vite@latest my-app"), [("npm", "create-vite", None)])
        self.assertEqual(pkgs("npm init @eslint/config"), [("npm", "@eslint/create-config", None)])
        self.assertEqual(pkgs("npm init -y"), [])

    def test_pypi_family(self):
        self.assertEqual(pkgs("pip install requests"), [("PyPI", "requests", None)])
        self.assertEqual(pkgs("pip3 install -U 'fastapi[all]==0.110.0' uvicorn>=0.20"),
                         [("PyPI", "fastapi", "0.110.0"), ("PyPI", "uvicorn", None)])
        self.assertEqual(pkgs("python3 -m pip install --user black"), [("PyPI", "black", None)])
        self.assertEqual(pkgs("uv add httpx"), [("PyPI", "httpx", None)])
        self.assertEqual(pkgs("uv pip install ruff==0.4.0"), [("PyPI", "ruff", "0.4.0")])
        self.assertEqual(pkgs("uvx --from black==24.1.0 black ."), [("PyPI", "black", "24.1.0")])
        self.assertEqual(pkgs("uvx ruff check"), [("PyPI", "ruff", None)])
        self.assertEqual(pkgs("pipx install poetry"), [("PyPI", "poetry", None)])
        self.assertEqual(pkgs("poetry add pendulum@^2.0.5"), [("PyPI", "pendulum", None)])
        self.assertEqual(pkgs("poetry add pendulum@2.0.5"), [("PyPI", "pendulum", "2.0.5")])
        self.assertEqual(pkgs("pip install -e . && pip install ./dist/x.whl git+https://github.com/a/b"), [])
        self.assertEqual(pkgs("python script.py install"), [])
        self.assertEqual(pkgs("pip list"), [])

    def test_requirements_flag(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "requirements.txt"), "w") as fh:
                fh.write("# deps\nrequests==2.31.0\nflask>=2  # web\n-r more.txt\n-e .\n")
            with open(os.path.join(d, "more.txt"), "w") as fh:
                fh.write("numpy\n")
            self.assertEqual(pkgs("pip install -r requirements.txt", cwd=d),
                             [("PyPI", "requests", "2.31.0"), ("PyPI", "flask", None), ("PyPI", "numpy", None)])

    def test_other_ecosystems(self):
        self.assertEqual(pkgs("cargo add serde@1.0.200 tokio -F full"),
                         [("crates.io", "serde", "1.0.200"), ("crates.io", "tokio", None)])
        self.assertEqual(pkgs("cargo install ripgrep --version 14.1.0"), [("crates.io", "ripgrep", "14.1.0")])
        self.assertEqual(pkgs("cargo install --git https://x/y"), [])
        self.assertEqual(pkgs("go get github.com/gorilla/mux@v1.8.0"), [("Go", "github.com/gorilla/mux", "v1.8.0")])
        self.assertEqual(pkgs("go install golang.org/x/tools/gopls@latest"), [("Go", "golang.org/x/tools/gopls", "latest")])
        self.assertEqual(pkgs("go get fmt && go run . && go run main.go && go get ./..."), [])
        self.assertEqual(pkgs("gem install rails -v 7.1.0"), [("RubyGems", "rails", "7.1.0")])
        self.assertEqual(pkgs("bundle add sidekiq"), [("RubyGems", "sidekiq", None)])
        self.assertEqual(pkgs("composer require monolog/monolog:^3.0 php ext-json"),
                         [("Packagist", "monolog/monolog", "^3.0")])

    def test_shell_structure(self):
        self.assertEqual(pkgs("cd web && sudo -E npm i a1pkg; FOO=1 pip install b2pkg | tee log"),
                         [("npm", "a1pkg", None), ("PyPI", "b2pkg", None)])
        self.assertEqual(pkgs("echo $(npm install c3pkg)"), [("npm", "c3pkg", None)])
        self.assertEqual(pkgs("env CI=1 /usr/bin/npm install d4pkg"), [("npm", "d4pkg", None)])
        self.assertEqual(pkgs("cat > README.md <<'EOF'\nnpm install fake-from-docs\nEOF\nnpm install real5pkg"),
                         [("npm", "real5pkg", None)])
        self.assertEqual(pkgs("echo 'npm install quoted'"), [])
        self.assertEqual(pkgs("git commit -m 'pip install x'"), [])
        self.assertEqual(pkgs("npm install foo # comment pip install bar"), [("npm", "foo", None)])

    def test_private_registries(self):
        r = packages_in_command("npm install internal-lib --registry https://npm.corp", Context("/x", {}))
        self.assertTrue(r[0].custom_index)
        r = packages_in_command("pip install corp-lib --extra-index-url https://pypi.corp", Context("/x", {}))
        self.assertTrue(r[0].custom_index)
        r = packages_in_command("pip install corp-lib", Context("/x", {"PIP_INDEX_URL": "https://pypi.corp/simple"}))
        self.assertTrue(r[0].custom_index)
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, ".npmrc"), "w") as fh:
                fh.write("@corp:registry=https://npm.corp/\n")
            r = packages_in_command("npm i @corp/ui react", Context(d, {}))
            self.assertEqual([x.custom_index for x in r], [True, False])
        self.assertEqual(pkgs("go get corp.example.com/lib", env={"GOPRIVATE": "corp.example.com"}), [])


class Manifests(unittest.TestCase):
    def test_package_json_edit(self):
        before = '{"dependencies": {"react": "^18.2.0"}}'
        after = '{"dependencies": {"react": "^18.2.0", "zod": "3.22.4", "local": "file:../x", "gh": "user/repo"},' \
                ' "devDependencies": {"vitest": "^1"}}'
        self.assertEqual(manifests.added_or_changed("/p/package.json", before, after),
                         {("npm", "zod"): "3.22.4", ("npm", "vitest"): None})

    def test_apply_edit(self):
        cur = '{"dependencies": {"a": "1.0.0"}}'
        self.assertEqual(manifests.apply_edit("Edit", {"old_string": '"1.0.0"', "new_string": '"2.0.0"'}, cur),
                         '{"dependencies": {"a": "2.0.0"}}')
        self.assertIsNone(manifests.apply_edit("Edit", {"old_string": "missing", "new_string": "x"}, cur))
        self.assertEqual(manifests.apply_edit("Write", {"content": "new"}, cur), "new")

    def test_requirements_and_pyproject(self):
        self.assertEqual(manifests.added_or_changed("requirements-dev.txt", "requests==2.0\n", "requests==2.0\nRe_Quests2\n"),
                         {("PyPI", "re-quests2"): None})
        pyproject = '[project]\ndependencies = ["httpx>=0.27", "pydantic==2.7.0"]\n[project.optional-dependencies]\n' \
                    'dev = ["pytest"]\n[tool.poetry.dependencies]\npython = "^3.11"\nrich = "13.7.1"\nlocal = {path = "../x"}\n'
        got = manifests.added_or_changed("pyproject.toml", "", pyproject)
        if manifests._toml is not None:
            self.assertEqual(got, {("PyPI", "httpx"): None, ("PyPI", "pydantic"): "2.7.0", ("PyPI", "pytest"): None,
                                   ("PyPI", "rich"): "13.7.1"})
        else:
            self.assertIn(("PyPI", "pydantic"), got)

    def test_cargo_gem_go_composer(self):
        if manifests._toml is not None:
            cargo = '[dependencies]\nserde = "1"\ntokio = { version = "=1.37.0", features = ["full"] }\n' \
                    'mine = { path = "../mine" }\nrenamed = { package = "real-crate", version = "0.1" }\n'
            self.assertEqual(manifests.declared("Cargo.toml", cargo),
                             {("crates.io", "serde"): None, ("crates.io", "tokio"): "1.37.0", ("crates.io", "real-crate"): None})
        self.assertEqual(manifests.declared("Gemfile", "source 'https://rubygems.org'\ngem 'rails', '7.1.3'\n"
                                                       "gem 'mine', path: '../mine'\ngem \"puma\"\n"),
                         {("RubyGems", "rails"): "7.1.3", ("RubyGems", "puma"): None})
        self.assertEqual(manifests.declared("go.mod", "module x\n\nrequire (\n\tgithub.com/a/b v1.2.3\n"
                                                      "\tgolang.org/x/net v0.20.0 // indirect\n)\nrequire github.com/c/d v0.1.0\n"),
                         {("Go", "github.com/a/b"): "v1.2.3", ("Go", "golang.org/x/net"): "v0.20.0", ("Go", "github.com/c/d"): "v0.1.0"})
        self.assertEqual(manifests.declared("composer.json", '{"require": {"php": ">=8.1", "monolog/monolog": "3.5.0"}}'),
                         {("Packagist", "monolog/monolog"): "3.5.0"})

    def test_invalid_json_fails_open(self):
        self.assertEqual(manifests.added_or_changed("package.json", "{}", '{"dependencies": {'), {})


class Typosquat(unittest.TestCase):
    def test_lookalikes(self):
        self.assertEqual(typosquat.lookalike("npm", "expresss")[0], "express")
        self.assertEqual(typosquat.lookalike("npm", "crossenv")[0], "cross-env")
        self.assertEqual(typosquat.lookalike("PyPI", "reqeusts")[0], "requests")
        self.assertEqual(typosquat.lookalike("PyPI", "python-dateutils")[0], "python-dateutil")
        self.assertEqual(typosquat.lookalike("crates.io", "tokioo")[0], "tokio")
        self.assertEqual(typosquat.lookalike("npm", "lodash-utils")[0], "lodash")

    def test_popular_names_are_never_flagged(self):
        for eco, name in [("npm", "preact"), ("npm", "react-dom"), ("PyPI", "Requests"), ("PyPI", "scikit_learn"),
                          ("crates.io", "serde_json"), ("npm", "vue3"), ("PyPI", "my-unique-thing-xyz")]:
            self.assertIsNone(typosquat.lookalike(eco, name), name)


class VersionsAndCvss(unittest.TestCase):
    def test_ordering(self):
        self.assertLess(versions.compare("1.2.0-rc1", "1.2.0"), 0)
        self.assertEqual(versions.compare("1.2", "1.2.0"), 0)
        self.assertGreater(versions.compare("1.10.0", "1.9.9"), 0)
        self.assertLess(versions.compare("2.0.0a1", "2.0.0"), 0)
        self.assertLess(versions.compare("1.0.0-beta.2", "1.0.0-beta.11"), 0)
        self.assertEqual(versions.nearest_fix("4.17.15", ["4.17.19", "4.17.21", "5.0.0"]), "4.17.19")

    def test_cvss(self):
        self.assertEqual(osv.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(osv.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0)
        self.assertEqual(osv.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"), 5.4)
        self.assertIsNone(osv.cvss3_score("CVSS:4.0/AV:N"))

    def test_parse_and_dedupe_real_records(self):
        ghsa = osv.parse_vuln(fakenet.osv_doc("GHSA-q2q7-5pp4-w6pg"), "PyPI", "urllib3")
        pysec = osv.parse_vuln(fakenet.osv_doc("PYSEC-2021-108"), "PyPI", "urllib3")
        self.assertEqual(ghsa.severity, "high")
        self.assertEqual(ghsa.fixed, ["1.26.5"])
        self.assertEqual(pysec.fixed, ["1.26.5"])  # GIT ranges (commit hashes) are skipped
        merged = osv.dedupe([pysec, ghsa])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].severity, "high")
        self.assertEqual(merged[0].fixed, ["1.26.5"])
        lodash = osv.parse_vuln(fakenet.osv_doc("GHSA-p6mc-m468-83gw"), "npm", "lodash")
        self.assertEqual(lodash.fixed, ["4.17.19"])  # lodash-es range is ignored
        self.assertTrue(osv.parse_vuln(fakenet.osv_doc("MAL-2021-1"), "npm", "cxp-jquery").malicious)


if __name__ == "__main__":
    unittest.main()
