"""Pivyon Shield: a supply-chain firewall for coding agents.

Stops hallucinated, typosquatted, malicious, freshly hijacked and vulnerable
packages before an agent installs them, using only free public data
(the package registries themselves and OSV.dev). Pure standard library.
"""

__version__ = "1.0.0"

USER_AGENT = (
    "pivyon-shield/%s (+https://github.com/bhardwajnishant333-ctrl/pivyon-shield)"
    % __version__
)
