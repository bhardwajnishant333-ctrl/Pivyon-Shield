---
name: vet
description: Vet a package before recommending or adding it - checks that it really exists, whether it imitates a popular package, its age, release cadence, adoption, license, install scripts, known vulnerabilities and malware history, using free registry data and OSV.dev. Use whenever you are about to suggest a new dependency, when the user asks "is X safe / legit / maintained", when comparing libraries ("A vs B"), or when a package name came from memory, a blog post, or another AI and has not been verified.
argument-hint: "<ecosystem:package> [...]"
allowed-tools: Bash(python3 ${CLAUDE_PLUGIN_ROOT}/scripts/shield.py *), Bash(python ${CLAUDE_PLUGIN_ROOT}/scripts/shield.py *)
---

# Vet a dependency before you choose it

Package names from memory are the main source of hallucinated installs.
Verify names before you write them into code, docs or install commands.

## Run

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/shield.py" vet npm:fastify npm:express pypi:httpx crates:reqwest
```

Prefixes: `npm:`, `pypi:`, `crates:`, `go:`, `gem:`, `composer:`. Pin a
version with `npm:lodash@4.17.15` or `pypi:urllib3==1.26.4`. Add
`--format json` when you need the raw fields.

To see what the install hook would decide for a command, without running it:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/shield.py" check "pip install fastapi-users[sqlalchemy] uvicorn"
```

## Read the verdict

- **DO NOT USE**: the package does not exist (hallucinated), is known
  malware, or was taken down by the registry. Never suggest it. Find the real
  name in the library's official docs.
- **CHECK FIRST**: lookalike of a popular package, brand new, a release
  younger than the cooldown, or a serious known vulnerability. Explain the
  specific signal to the user before going ahead.
- **OK, with notes**: usable. Mention material notes (deprecated, install
  scripts, low adoption, vulnerable pinned version with a fix).
- **UNVERIFIED**: a registry or OSV.dev could not be reached. Say that the
  check did not run; do not call the package safe.

## When comparing candidates

Give a short recommendation and the reason, grounded in the table: prefer the
package that exists under the exact name, has steady recent releases, broad
adoption (popularity rank or downloads), a permissive license compatible with
the project, and no unfixed advisories. Flag any license that differs from
the project's (GPL/AGPL in a proprietary codebase in particular).
