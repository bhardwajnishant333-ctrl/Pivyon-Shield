# Submitting Pivyon Shield to the Claude plugin directory

Form: https://clau.de/plugin-directory-submission

## Checklist

- [x] Public GitHub repository with the plugin committed: `bhardwajnishant333-ctrl/pivyon-shield` (the plugin and its marketplace live at the repository root)
- [x] `.claude-plugin/plugin.json` with name, description, version, author, license, homepage
- [x] Square icon, 1024×1024 PNG in the Pivyon brand (ink `#0b0b0d`, paper `#f2f1ec`, lime `#c8ff3e`; the Pivyon "p" mark inside a shield): `.claude-plugin/icon.png`, source in `brand/pivyon-shield-mark.svg`. The directory reads it only on the first save, so it is final.
- [x] README with an install line, what the plugin does, data sent, configuration, limitations
- [x] MIT LICENSE
- [x] `claude plugin validate .` passes with no warnings
- [x] The repository is also its own marketplace (`.claude-plugin/marketplace.json`)
- [x] Tests: `python3 -m unittest discover -s tests` (43 offline tests; Python 3.8, 3.11, 3.12, 3.13)
- [x] End-to-end in a real Claude Code session (2.1.310): a hallucinated npm install was denied, a
      `package.json` edit adding the real npm-removed typosquat `lodahs` was denied before the file
      changed, and a legitimate `left-pad` install went through with a deprecation note.
- [ ] Make the repository public, if it is not already, before you submit.

## Suggested form answers

**Plugin name:** pivyon-shield (display name: Pivyon Shield)

**Publisher:** Pivyon (https://pivyon.com, hello@pivyon.com)

**Category:** Security

**One-line description:** Keep your Claude Code development safe from malware, without thinking about it. Zero setup, free forever. Pivyon Shield checks every package Claude installs and blocks the fake and malicious ones before they can compromise your code or your machine.

**What problem does it solve?**
Coding agents run `npm install` / `pip install` on their own, and language models invent plausible
package names. Attackers register those names (slopsquatting), along with typosquats, and sometimes
hijack releases of popular packages. Pivyon Shield is a PreToolUse hook that checks every package
before the command runs, whether it comes from a shell command or from an edit to package.json,
requirements.txt, pyproject.toml, Cargo.toml, go.mod, Gemfile or composer.json. It blocks names that
don't exist, known malware (OSV / OpenSSF malicious-packages) and registry takedowns. It asks a human
about lookalikes, brand-new packages and releases younger than a 24-hour cooldown. It tells Claude
the fix version for known vulnerabilities. Two skills go further: `/pivyon-shield:audit` scans every
lockfile and lets Claude fix vulnerable dependencies and prove the fix, and `/pivyon-shield:vet`
does due diligence before a dependency is chosen.

**How is it different from existing directory plugins?**
The directory's supply-chain plugins (Endor Labs, Sonatype, Aikido, JFrog, Socket-style services)
need a vendor account or API key. None of them guards the agent's install boundary for free. Package
Shield works out of the box with no signup, uses only the public registries and OSV.dev, and is pure
Python standard library, so it installs nothing.

**External services / data sent:** package names and versions only, sent to the public registries
the package managers already use (registry.npmjs.org, api.npmjs.org, pypi.org, crates.io,
proxy.golang.org, rubygems.org, repo.packagist.org) and to api.osv.dev. No source code, file
contents, credentials or telemetry. All of these are free and need no key.

**Permissions / behavior:** one PreToolUse hook on Bash, Write, Edit and MultiEdit. It can return
deny or ask for risky packages, and otherwise stays silent. It fails open when offline or on any
internal error. Users can tune it in `.pivyon-shield.json`, and `"mode": "off"` disables it.

**Requirements:** Python 3.8+ on PATH (`python3`, `python` or `py -3`).

## Before each future release

1. Bump `version` in `.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json`.
2. Optionally refresh `data/*.txt` (popular-package snapshots).
3. Run the tests and both validate commands, then push.
