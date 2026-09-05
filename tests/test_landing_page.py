"""Content guards on the page that ships.

These run against render() output, not the template. The template is hand-reviewed,
but the injected sections are not.
"""
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from render_landing import render

REPO = Path(__file__).resolve().parents[1]
LANDING = REPO / "landing"


@pytest.fixture(scope="module")
def page() -> str:
    return render(
        (LANDING / "index.html").read_text(encoding="utf-8"),
        REPO / "specification",
        (REPO / "GOVERNANCE.md").read_text(encoding="utf-8"),
        (LANDING / "assets" / "starburst.svg").read_text(encoding="utf-8"),
    )


def test_the_hero_diagram_is_present(page):
    assert "<svg" in page
    for label in ["LLM", "Tool", "Output", "Sub", "Memory", "Code", "ACS"]:
        assert label in page


def test_no_root_relative_links(page):
    """A project Pages site serves from /agent-control-standard/, so /docs/ would 404."""
    assert not re.search(r"""(href|src)\s*=\s*['"]/(?!/)""", page)


def test_no_retired_project_links(page):
    assert "aos.owasp.org" not in page


def test_the_only_email_is_the_approved_one(page):
    found = set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", page))
    assert found == {"rock.lambros@owasp.org"}


def test_no_third_party_origin(page):
    """The page must contact nothing. Same reasoning that removed analytics."""
    hosts = set(re.findall(r"""(?:href|src)\s*=\s*['"]https?://([^/'"]+)""", page))
    allowed = {"github.com", "owasp.slack.com", "owasp.org", "www.apache.org",
               "creativecommons.org", "eur-lex.europa.eu", "doi.org"}
    assert hosts <= allowed, f"unexpected origins: {hosts - allowed}"


def test_no_inline_event_handlers(page):
    """Parsed, not grepped. An escaped payload contains the text `onfocus=` inside an
    attribute value while being entirely inert, so a regex reports a false positive."""
    from html.parser import HTMLParser

    class Collector(HTMLParser):
        def __init__(self) -> None:
            super().__init__()
            self.handlers: list[str] = []
            self.schemes: list[str] = []

        def handle_starttag(self, tag, attrs):
            for name, value in attrs:
                if name.startswith("on"):
                    self.handlers.append(f"<{tag} {name}>")
                if name in ("href", "src") and value and value.lower().startswith("javascript:"):
                    self.schemes.append(f"<{tag} {name}={value[:40]}>")

    collector = Collector()
    collector.feed(page)
    assert not collector.handlers, collector.handlers
    assert not collector.schemes, collector.schemes


def test_no_em_dash(page):
    assert "—" not in page


def test_the_title_has_no_em_dash_and_is_present(page):
    match = re.search(r"<title>(.*?)</title>", page)
    assert match and "—" not in match.group(1)


def test_footer_links_the_governing_documents(page):
    for doc in ["GOVERNANCE.md", "SECURITY.md", "CODE_OF_CONDUCT.md", "LICENSING.md"]:
        assert doc in page


def test_license_names_are_linked(page):
    assert "apache.org/licenses/LICENSE-2.0" in page
    assert "creativecommons.org/licenses/by-sa/4.0" in page


def test_dark_theme_and_reduced_motion_are_defined():
    css = (LANDING / "assets" / "acs.css").read_text(encoding="utf-8")
    assert 'data-theme="dark"' in css
    assert "prefers-color-scheme: dark" in css
    assert "prefers-reduced-motion: reduce" in css
    svg = (LANDING / "assets" / "starburst.svg").read_text(encoding="utf-8")
    # `animation: none` does not reach SMIL, so the SVG carries its own guard.
    assert "prefers-reduced-motion: reduce" in svg


def test_focus_ring_and_muted_text_meet_contrast():
    """Encodes the measurements that four inherited token values failed."""
    css = (LANDING / "assets" / "acs.css").read_text(encoding="utf-8")

    def luminance(hex_color: str) -> float:
        h = hex_color.lstrip("#")
        channels = []
        for i in (0, 2, 4):
            c = int(h[i : i + 2], 16) / 255
            channels.append(c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4)
        return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]

    def ratio(a: str, b: str) -> float:
        la, lb = luminance(a), luminance(b)
        hi, lo = max(la, lb), min(la, lb)
        return (hi + 0.05) / (lo + 0.05)

    def token(name: str, block: str) -> str:
        section = css.split(block, 1)[1]
        return re.search(rf"{name}:\s*(#[0-9a-fA-F]{{6}})", section).group(1)

    light_ring = token("--acs-focus-ring", ":root {")
    assert ratio(light_ring, "#ffffff") >= 3.0
    dark_ring = token("--acs-focus-ring", ':root[data-theme="dark"]')
    assert ratio(dark_ring, "#0a0a0a") >= 3.0
    dark_muted = token("--acs-text-muted", ':root[data-theme="dark"]')
    assert ratio(dark_muted, "#161616") >= 4.5
    light_hex = token("--acs-hex-stroke", ":root {")
    assert ratio(light_hex, "#f4f5f7") >= 3.0
