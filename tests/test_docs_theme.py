"""Guards on the documentation site's theme and its published URLs.

The canonical bug these cover was invisible to every earlier test, because none of them
compared the URL a page declares against the path it is published at.
"""
import os
import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
DOCS_BASE = "https://example.org/agent-control-standard/docs/"


@pytest.fixture(scope="module")
def built_docs(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("docs")
    env = dict(os.environ)
    env.pop("GOOGLE_ANALYTICS_KEY", None)
    env["GITHUB_PAGES_URL"] = DOCS_BASE
    result = subprocess.run(
        ["uv", "run", "mkdocs", "build", "--strict", "-d", str(out)],
        cwd=REPO, env=env, capture_output=True, text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"mkdocs build failed:\n{result.stdout}\n{result.stderr}")
    return out


def test_every_canonical_matches_the_page_path(built_docs):
    """A canonical that omits /docs/ names a URL that does not exist."""
    wrong = []
    for page in built_docs.rglob("index.html"):
        match = re.search(r'rel="canonical" href="([^"]+)"', page.read_text(encoding="utf-8"))
        if not match:
            continue
        relative = page.parent.relative_to(built_docs).as_posix()
        expected = DOCS_BASE if relative == "." else f"{DOCS_BASE}{relative}/"
        if match.group(1) != expected:
            wrong.append((relative, match.group(1)))
    assert not wrong, f"canonical does not match publish path: {wrong[:5]}"


def test_sitemap_urls_sit_under_the_docs_path(built_docs):
    sitemap = built_docs / "sitemap.xml"
    if not sitemap.exists():
        import gzip
        text = gzip.open(built_docs / "sitemap.xml.gz", "rt").read()
    else:
        text = sitemap.read_text(encoding="utf-8")
    urls = re.findall(r"<loc>([^<]+)</loc>", text)
    assert urls, "sitemap has no entries"
    assert all(u.startswith(DOCS_BASE) for u in urls), [u for u in urls if not u.startswith(DOCS_BASE)][:5]


def test_docs_stylesheet_declares_the_acs_tokens():
    css = (REPO / "docs" / "stylesheets" / "extra.css").read_text(encoding="utf-8")
    for token in ['[data-md-color-scheme="default"]', '[data-md-color-scheme="slate"]',
                  "--md-text-font", "--md-typeset-a-color"]:
        assert token in css


def test_docs_use_the_same_mark_as_the_landing_page():
    config = (REPO / "mkdocs.yml").read_text(encoding="utf-8")
    assert "logo: assets/icon.svg" in config
    assert "favicon: assets/icon.svg" in config
    assert (REPO / "docs" / "assets" / "icon.svg").is_file()
