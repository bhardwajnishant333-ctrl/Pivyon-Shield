#!/usr/bin/env python3
"""pivyon-shield command line.

  shield.py hook                     PreToolUse hook (reads hook JSON on stdin)
  shield.py audit [PATH] [--format md|json] [--fail-on LEVEL]
  shield.py vet npm:express pypi:requests crates:serde ...
  shield.py check "npm install expresss"
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib"))

from pivyon_shield import __version__  # noqa: E402


def main(argv):
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__.strip())
        return 0
    cmd, rest = argv[0], argv[1:]
    if cmd == "hook":
        from pivyon_shield.hook import main as hook_main

        return hook_main()
    if cmd == "audit":
        from pivyon_shield.audit import main as audit_main

        return audit_main(rest)
    if cmd in ("vet", "check"):
        from pivyon_shield.vet import main as vet_main

        return vet_main(rest, cmd)
    if cmd in ("--version", "version"):
        print("pivyon-shield", __version__)
        return 0
    sys.stderr.write("unknown command: %s\n%s\n" % (cmd, __doc__.strip()))
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
