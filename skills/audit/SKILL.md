---
name: audit
description: Audit every locked dependency in the project for known vulnerabilities and malware (OSV.dev, free, no key), then fix them with the smallest safe upgrades and prove the fix. Use when the user asks to audit, scan or secure dependencies, check for CVEs or vulnerable/malicious packages, run "npm audit"/"pip-audit"-style checks across ecosystems, prepare a release or security review, or after a supply-chain incident makes the news.
argument-hint: "[path] [--fix]"
allowed-tools: Bash(python3 ${CLAUDE_PLUGIN_ROOT}/scripts/shield.py *), Bash(python ${CLAUDE_PLUGIN_ROOT}/scripts/shield.py *), Read, Grep, Glob, Edit
---

# Dependency audit and fix

The scanner reads lockfiles (package-lock.json, npm-shrinkwrap.json, yarn.lock,
pnpm-lock.yaml, bun.lock, requirements*.txt pins, poetry.lock, uv.lock,
pdm.lock, Pipfile.lock, Cargo.lock, go.mod, Gemfile.lock, composer.lock) and
checks each exact version against OSV.dev, which merges GitHub Advisories,
PyPA, RustSec, the Go vulndb, RubySec and the OpenSSF malicious-packages feed.

## 1. Scan

Run from the project root (or the path the user gave):

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/shield.py" audit . --format json
```

(`python` instead of `python3` on Windows.) Use `--format md` when you only
need a table to show the user. Exit code 2 means OSV.dev was unreachable: say
so plainly instead of reporting a clean result.

If it reports no lockfiles, tell the user which lock command would create one
for their stack, and offer to run it.

## 2. Triage, in this order

1. **Malicious** (`"malicious": true`). Treat as an incident, not a bug:
   remove the package, tell the user immediately, and recommend rotating any
   secrets present on machines where it was installed (CI included). Do not
   just bump the version.
2. **Critical / high on direct dependencies.**
3. **Critical / high on transitive dependencies.**
4. Medium / low. Dev-only (`"dev": true`) findings rank lower unless the
   package runs in CI or build tooling that handles secrets.

For each finding, glance at the advisory summary and decide whether the
project plausibly uses the affected feature (grep for the imported API). Say
so, but still fix critical/high issues: reachability guesses are not proof.

## 3. Fix with the smallest safe change

`fix` in the report is the nearest release that clears every listed advisory
(same major version when one exists).

| Ecosystem | Direct dependency | Transitive dependency |
|---|---|---|
| npm | `npm install name@FIX` (or pnpm/yarn/bun equivalent) | `npm update name`; if the parent pins it, add `"overrides": {"name": "FIX"}` (`pnpm.overrides`, yarn `resolutions`) |
| PyPI | update the pin in requirements/pyproject, then `uv lock` / `poetry lock` / `pip install` | add it as an explicit constraint at the fixed version |
| crates.io | `cargo update -p name --precise FIX` | same command |
| Go | `go get module@FIX && go mod tidy` | same |
| RubyGems | `bundle update name --conservative` | same |
| Packagist | `composer update vendor/name --with-dependencies` | same |

Rules:
- If `fix` crosses a major version, read the package's changelog or release
  notes for breaking changes before upgrading, and tell the user it is a major
  bump. Prefer one PR-sized batch per ecosystem.
- If no fix exists, say so, and suggest mitigation (an alternative package,
  removing the dependency, or a config workaround from the advisory).
- Pivyon Shield's install hook will vet every version you install. If it
  asks or blocks, respect that and report it.

## 4. Prove it

1. Re-run the scan and show the before/after counts.
2. Run the project's tests / typecheck / build.
3. Summarize for the user: what was found, what changed (package, old -> new
   version, advisory ids), what remains and why.

## CI

The same scanner works as a CI gate with no account:

```bash
python3 path/to/pivyon-shield/scripts/shield.py audit . --fail-on high
```

exits 1 when any finding is at or above the chosen level (`malicious`,
`critical`, `high`, `medium`, `low`). Offer to add it to the user's CI.
