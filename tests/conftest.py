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
_IN_ATTR = re.compile(r"""(?:[a-z][a-z0-9+.-]*:)?//([^\s/?#'\"),<>]+)""", re.I)
# In script text, require a scheme. A bare // opens a JavaScript comment far more
# often than a protocol-relative URL, and a false positive here is the kind of noise
# that gets a guard switched off.
_IN_TEXT = re.compile(r"""\bhttps?://([^\s/?#'\"),<>]+)""", re.I)
# Script and style bodies are taken from the raw markup rather than from parser
# events. HTML honors a self-closing slash only on void and foreign elements, so
# <script/>body</script> runs in a browser, and Python's parser reports it through a
# handler that never enters raw-text mode. Tracking capture across events therefore
# either misses the body or sweeps whatever follows until some later closing tag.
# Matching the element outright has neither failure.
# Script and style bodies come from one left-to-right pass over the raw markup.
# HTML tokenization is context sensitive: inside these elements the text is raw, so
# <!-- opens no comment there and a browser runs whatever follows, while outside one
# a comment hides everything to its terminator. Four earlier attempts scanned for
# comments and elements with separate patterns, and every pairing hid something real.
_OPEN_RAWTEXT = re.compile(r"<(script|style)\b[^>]*>", re.I)
# A browser closes on </script/> and </script data-x="y">, discarding what it finds
# before the bracket, so the end tag accepts anything up to it.
_CLOSE_RAWTEXT = {name: re.compile(rf"</{name}[^>]*>", re.I) for name in ("script", "style")}

# CSS reaches the network only through url(), image-set(), and @import. That set is
# closed, unlike the HTML one, so enumerating it here is safe. Comments are stripped
# first because a vendor licence banner carries URLs that fetch nothing, and data:
# payloads are skipped because an inlined SVG carries an xmlns that is not a request.
_CSS_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_CSS_FETCH = re.compile(
    r"""(?:url\(\s*|image-set\(\s*|@import\s*(?:url\(\s*)?)['"]?([^'")\s]+)""", re.I
)
_CSS_HOST = re.compile(r"""^(?:[a-z][a-z0-9+.-]*:)?//([^/?#]+)""", re.I)

# Scripts come from the installed theme, pinned by uv.lock. The path is relative to
# the mkdocs output root, which is the directory built_site builds into and
# _site/docs in the deploy workflow.
VENDORED_PREFIX = "assets/javascripts/"


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
        self.bases: list[str] = []

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

    handle_startendtag = handle_starttag


def _scan(markup: str) -> _Scanner:
    scanner = _Scanner()
    scanner.feed(markup)
    return scanner


def _element_bodies(markup: str) -> list[str]:
    """Return the body of every script and style element a browser would run."""
    bodies: list[str] = []
    pos = 0
    while pos < len(markup):
        comment = markup.find("<!--", pos)
        opening = _OPEN_RAWTEXT.search(markup, pos)
        if opening is None and comment == -1:
            break
        if comment != -1 and (opening is None or comment < opening.start()):
            end = markup.find("-->", comment + 4)
            # An unterminated comment consumes the rest of the document.
            pos = len(markup) if end == -1 else end + 3
            continue
        closing = _CLOSE_RAWTEXT[opening.group(1).lower()].search(markup, opening.end())
        if closing is None:
            # No end tag, so the element owns the rest of the document and runs.
            bodies.append(markup[opening.end():])
            break
        bodies.append(markup[opening.end():closing.start()])
        pos = closing.end()
    return bodies


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
    for body in _element_bodies(markup):
        hosts |= {m.group(1).lower() for m in _IN_TEXT.finditer(_NOISE.sub("", body))}
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


def theme_script_names() -> set[str]:
    """Return every script the installed theme ships, relative to its assets root.

    A path check cannot tell a first-party file dropped into the theme's own output
    directory from the theme's own code, because mkdocs copies docs/assets/ there
    verbatim. Comparing against what the package installs can.
    """
    import material

    root = Path(material.__file__).parent / "templates" / "assets" / "javascripts"
    return {path.relative_to(root).as_posix() for path in root.rglob("*.js")}


def stray_scripts(built_site: Path) -> list[str]:
    """Return every built script the pinned theme does not ship."""
    vendored = theme_script_names()
    stray: list[str] = []
    for path in built_site.rglob("*.js"):
        rel = path.relative_to(built_site).as_posix()
        if not rel.startswith(VENDORED_PREFIX) or rel[len(VENDORED_PREFIX):] not in vendored:
            stray.append(rel)
    return stray
