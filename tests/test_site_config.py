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

ALLOWED_HOSTS = {
    "creativecommons.org", "csrc.nist.gov", "cyclonedx.org",
    "developers.googleblog.com", "doi.org", "eur-lex.europa.eu",
    "example.org", "genai-security-project.github.io", "github.com",
    "google-a2a.github.io", "google.github.io", "json-schema.org",
    "modelcontextprotocol.io", "news.microsoft.com", "ocsf.io",
    "opentelemetry.io", "owasp.org", "owasp.slack.com", "schema.ocsf.io",
    "spdx.dev", "squidfunk.github.io", "www.apache.org", "www.jpmorgan.com",
    "www.jsonrpc.org",
}


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


def test_built_site_fetches_no_unexpected_origin(built_site):
    for page in built_site.rglob("*.html"):
        for host in re.findall(r"""(?:src|href)\s*=\s*['"]https?://([^/'"]+)""",
                               page.read_text(encoding="utf-8")):
            assert host in ALLOWED_HOSTS, f"{page.name} fetches {host}"
