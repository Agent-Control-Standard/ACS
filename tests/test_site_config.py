"""Regression guard on the built documentation site.

Verified before this change: with GOOGLE_ANALYTICS_KEY empty, and also with the variable
unset entirely, Material emitted <script src=".../gtag/js?id=">. No env value suppressed
it, so the analytics block had to be removed. Removing it alone was not enough: the theme
also fetched Roboto from fonts.googleapis.com on all 37 pages.
"""
import os
import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

# Anchor links are prose and fetch nothing. Only resource loads reach a third party,
# so the guard matches loading constructs rather than every href on the page.
RESOURCE_TAG = re.compile(
    r"""<(?:script|link|img|iframe|source|audio|video|embed|object)\b[^>]*?"""
    r"""(?:src|href|data)\s*=\s*['"](?:https?:)?//([^/'"]+)""",
    re.I,
)
IMPORT_RULE = re.compile(r"""@import\s+(?:url\()?['"]?(?:https?:)?//([^/'"]+)""", re.I)

# The canonical URL the test build is given. Anything else is a third party.
SELF_HOSTS = {"example.org"}


@pytest.fixture(scope="module")
def built_site(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("site")
    env = dict(os.environ)
    env.pop("GOOGLE_ANALYTICS_KEY", None)
    env["GITHUB_PAGES_URL"] = "https://example.org/"
    result = subprocess.run(
        ["uv", "run", "mkdocs", "build", "--strict", "-d", str(out)],
        cwd=REPO, env=env, capture_output=True, text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"mkdocs build failed:\n{result.stdout}\n{result.stderr}")
    return out


def test_mkdocs_config_declares_no_analytics():
    assert "analytics" not in (REPO / "mkdocs.yml").read_text(encoding="utf-8")


def test_mkdocs_config_disables_theme_fonts():
    """Material fetches Roboto from Google unless font is false."""
    assert re.search(r"^\s*font:\s*false\s*$", (REPO / "mkdocs.yml").read_text(encoding="utf-8"), re.M)


def test_built_site_loads_nothing_from_google(built_site):
    for page in built_site.rglob("*.html"):
        text = page.read_text(encoding="utf-8")
        assert "googletagmanager" not in text
        assert "fonts.googleapis.com" not in text
        assert "fonts.gstatic.com" not in text


def test_built_site_loads_no_third_party_resource(built_site):
    """The site must fetch nothing it does not serve itself.

    Measured before this guard existed: the built site had zero third-party resource
    loads once analytics and theme fonts were off. An empty result is the correct
    result, so any host appearing here is a regression.
    """
    offenders: dict[str, str] = {}
    for page in built_site.rglob("*.html"):
        text = page.read_text(encoding="utf-8")
        for match in list(RESOURCE_TAG.finditer(text)) + list(IMPORT_RULE.finditer(text)):
            host = match.group(1)
            if host not in SELF_HOSTS:
                offenders.setdefault(host, page.name)
    assert not offenders, f"third-party resource loads: {offenders}"
