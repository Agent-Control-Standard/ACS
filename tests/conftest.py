"""Shared patterns for the guards that keep the site from contacting a third party.

The two guards were duplicated regexes in separate files. One definition means they
cannot drift, and the drift is what would let one of them quietly stop matching.
"""
import re

# Anchor links are prose and fetch nothing. Only these constructs reach a third party.
RESOURCE_TAG = re.compile(
    r"""<(?:script|link|img|iframe|source|audio|video|embed|object)\b[^>]*?"""
    r"""(?:src|href|data)\s*=\s*['"](?:https?:)?//([^/'"]+)""",
    re.I,
)
IMPORT_RULE = re.compile(r"""@import\s+(?:url\()?['"]?(?:https?:)?//([^/'"]+)""", re.I)
# A stylesheet reaches a third party with no script, through url() in background-image,
# @font-face src, or a cursor. HTML-only scanning cannot see any of it.
URL_FUNC = re.compile(r"""url\(\s*['"]?(?:https?:)?//([^/'"]+)""", re.I)


def third_party_hosts(text: str, self_hosts: set[str]) -> set[str]:
    """Return every third-party host the text would load from."""
    hosts = {m.group(1) for m in RESOURCE_TAG.finditer(text)}
    hosts |= {m.group(1) for m in IMPORT_RULE.finditer(text)}
    hosts |= {m.group(1) for m in URL_FUNC.finditer(text)}
    return hosts - self_hosts
