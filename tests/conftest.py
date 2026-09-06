"""Shared guards that keep the published site from contacting a third party.

The guard has been found incomplete five times. Every earlier version enumerated the
attributes that fetch, and each new construct was a fresh gap: a poster attribute, an
unquoted value, a stylesheet, a base element, an inline script body. So this one
enumerates the positions that do not fetch instead. Anything else carrying an absolute
URL counts as a fetch, which makes an unanticipated construct a failure rather than a
silent pass.
"""
import html.parser
import json
import re
from pathlib import Path

# Positions a browser resolves but never fetches from. Everything else is a fetch.
# Form action is deliberately absent. A form needs no click: a script calling submit()
# fires the request on load, and the URL never appears in the script text.
NON_FETCHING = frozenset({
    ("a", "href"), ("area", "href"),
    ("blockquote", "cite"), ("q", "cite"), ("ins", "cite"), ("del", "cite"),
})
# A namespace URI names a vocabulary. No browser resolves it, and the built site
# carries several hundred of them on inline SVG.
NON_FETCHING_ATTRS = frozenset({"xmlns"})
# These link types make an anchor fetch or open a connection with no click, so the
# anchor exemption does not apply when one of them is present.
SPECULATIVE_REL = frozenset({
    "prefetch", "preconnect", "dns-prefetch", "preload", "modulepreload",
})

# The URL parser strips ASCII tab and newline before resolving, so a scheme broken
# across one still fetches. Strip them before matching rather than after.
_NOISE = re.compile(r"[\t\r\n]")
# In an attribute, a protocol-relative value is a fetch.
_IN_ATTR = re.compile(r"""(?:[a-z][a-z0-9+.-]*:)?//([^\s/?#'\"),]+)""", re.I)
# In script text, require a scheme. A bare // opens a JavaScript comment far more
# often than a protocol-relative URL, and a false positive here is the kind of noise
# that gets a guard switched off.
_IN_TEXT = re.compile(r"""\bhttps?://([^\s/?#'\"),]+)""", re.I)

# CSS reaches the network only through url(), image-set(), and @import. That set is
# closed, unlike the HTML one, so enumerating it here is safe. Comments are stripped
# first because a vendor licence banner carries URLs that fetch nothing, and data:
# payloads are skipped because an inlined SVG carries an xmlns that is not a request.
_CSS_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_CSS_FETCH = re.compile(
    r"""(?:url\(\s*|image-set\(\s*|@import\s+(?:url\(\s*)?)['"]?([^'")\s]+)""", re.I
)
_CSS_HOST = re.compile(r"""^(?:[a-z][a-z0-9+.-]*:)?//([^/?#]+)""", re.I)

# Scripts under this path come from the installed theme and are pinned by uv.lock.
# The prefix is relative to the mkdocs output root, which is the directory the
# built_site fixture builds into and _site/docs in the deploy workflow. A prefix,
# not a substring: as a substring any path merely containing the segment passes.
VENDORED_PREFIXES = ("assets/javascripts/",)


def write_schema(root: Path, rel: str, sid: str, body: dict | None = None) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {"$id": sid}
    doc.update(body or {})
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


class _Scanner(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.attr_values: list[str] = []
        self.text_values: list[str] = []
        self.bases: list[str] = []
        self._capturing: str | None = None

    def _collect(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        seen = dict(attrs)
        if tag == "base":
            self.bases.append(seen.get("href") or "")
        speculative = bool(set((seen.get("rel") or "").lower().split()) & SPECULATIVE_REL)
        for name, value in attrs:
            if not value:
                continue
            if name.split(":")[0] in NON_FETCHING_ATTRS:
                continue
            if (tag, name) in NON_FETCHING and not speculative:
                continue
            self.attr_values.append(value)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._collect(tag, attrs)
        if tag in ("script", "style"):
            self._capturing = tag

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # A self-closed script or style has no body. Aliasing this to handle_starttag
        # would leave capturing switched on for the rest of the document, so every
        # later paragraph would be scanned as if it were script text.
        self._collect(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag == self._capturing:
            self._capturing = None

    def handle_data(self, data: str) -> None:
        if self._capturing:
            self.text_values.append(data)


def _scan(markup: str) -> _Scanner:
    scanner = _Scanner()
    scanner.feed(markup)
    return scanner


def third_party_hosts(markup: str, self_hosts: set[str]) -> set[str]:
    """Return every third-party host the markup would fetch from.

    A base element counts, because it redirects every relative URL on the page. It is
    folded in here rather than offered as a second function each caller has to
    remember, since coverage a call site opts into is how this guard came to be
    incomplete five times.
    """
    scanner = _scan(markup)
    hosts: set[str] = set()
    for value in scanner.attr_values + scanner.bases:
        hosts |= {m.group(1).lower() for m in _IN_ATTR.finditer(_NOISE.sub("", value))}
    for value in scanner.text_values:
        hosts |= {m.group(1).lower() for m in _IN_TEXT.finditer(_NOISE.sub("", value))}
    return hosts - {host.lower() for host in self_hosts}


def external_bases(markup: str) -> list[str]:
    """Return every base element href, for a test that names the construct directly."""
    return [href for href in _scan(markup).bases if href]


def stylesheet_hosts(css: str, self_hosts: set[str]) -> set[str]:
    """Return every third-party host a stylesheet would fetch from."""
    hosts: set[str] = set()
    for match in _CSS_FETCH.finditer(_CSS_COMMENT.sub(" ", css)):
        value = match.group(1)
        if value.lower().startswith("data:"):
            continue
        host = _CSS_HOST.match(value)
        if host:
            hosts.add(host.group(1).lower())
    return hosts - {host.lower() for host in self_hosts}
