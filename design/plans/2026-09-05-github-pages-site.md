# GitHub Pages Site Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish a landing page, the MkDocs specification site, and all 44 JSON schemas to GitHub Pages on every merge to `main`, so that schema `$id` URIs resolve for the first time.

**Architecture:** One GitHub Actions workflow assembles three independent parts into a single Pages artifact. The landing page is hand-authored HTML and CSS with build-time content injection. Schema publish paths derive from each schema's own `$id`, and the build fails if any `$id` or `$ref` in the package does not resolve.

**Tech Stack:** Python 3.11+, uv, MkDocs Material, pytest, GitHub Actions, hand-authored HTML and CSS with no JavaScript framework.

**Spec:** `design/2026-09-05-github-pages-landing.md`

## Global Constraints

- Python `>=3.11`, matching `pyproject.toml` `requires-python`.
- uv pinned to `0.9.9` in CI, matching `.github/workflows/sync_version.yml`.
- Every GitHub Action SHA-pinned with a trailing version comment. Reuse the pins already in this repository where they exist.
- Workflow-level `permissions: {}`. Jobs grant only what they need.
- Schema `$id` values must not change. `$id` is versioned by spec version (`v0.1.0`), not release version (`version.txt`, currently `0.1.1`).
- No email address anywhere in the repository except `rock.lambros@owasp.org` on the landing page.
- No link may reference `aos.owasp.org`.
- Landing page links must be relative (`docs/`), never root-relative (`/docs/`). A project Pages site serves from `/agent-control-standard/`.
- Prose follows `STYLE.md`. Avoid em dashes, semicolons, sentences starting with conjunctions, and filler words (just, very, really, actually, certainly, basically, literally, utilize, facilitate, leverage, robust, seamless, transformative, holistic, unlock, unleash, empower).
- Never credit an AI in commit messages, code comments, file headers, or documentation.
- All work lands on branch `feat/github-pages-site`.

---

## File Structure

| File | Responsibility |
|---|---|
| `tools/publish_schemas.py` | Place each schema at the path its `$id` declares. Verify every `$ref` resolves. |
| `tools/render_landing.py` | Replace named placeholders in the landing page from repository state. |
| `landing/index.html` | Landing page markup and copy. |
| `landing/assets/acs.css` | Design tokens, layout, light and dark themes. |
| `landing/assets/starburst.svg` | Hero diagram. |
| `landing/assets/icon.svg` | Favicon. |
| `tests/test_publish_schemas.py` | Schema publishing and ref-closure tests. |
| `tests/test_render_landing.py` | Content injection tests. |
| `tests/test_site_config.py` | Regression test that no analytics tag ships. |
| `.github/workflows/deploy-pages.yml` | Build and deploy. |
| `mkdocs.yml` | Modified: remove `extra.analytics`. |
| `.gitignore` | Modified: add `_site/`. |
| `pyproject.toml` | Modified: add a `dev` dependency group with pytest. |
| `CLAUDE.md` | Modified: contact exception, hosting section. |

---

## Task 1: Schema publisher

Publishes schemas to the paths their own `$id` values declare, and fails the build if the package does not resolve completely. This is the task that closes the 404 gap and keeps it closed.

**Files:**
- Create: `tools/publish_schemas.py`
- Create: `tests/test_publish_schemas.py`
- Modify: `pyproject.toml`
- Modify: `uv.lock` (regenerated)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `BASE: str` module constant, the schema namespace prefix.
  - `class SchemaError(Exception)`
  - `load_schemas(source: Path) -> dict[Path, dict]`
  - `target_for(doc: dict, path: Path) -> str` returning the `$id`-relative path, for example `v0.1.0/acs_schema.json`.
  - `iter_refs(node: object) -> Iterator[str]`
  - `publish(source: Path, out: Path) -> list[str]` returning sorted relative paths.
  - CLI: `python tools/publish_schemas.py <source> <out>`.

- [ ] **Step 1: Add pytest as a dev dependency**

Append to `pyproject.toml`:

```toml
[dependency-groups]
dev = [ "pytest>=8.0",]
```

- [ ] **Step 2: Regenerate the lockfile**

Run: `uv lock`
Expected: `uv.lock` updates to include pytest and its dependencies.

- [ ] **Step 3: Write the failing tests**

Create `tests/test_publish_schemas.py`:

```python
"""Tests for the schema publisher."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from publish_schemas import BASE, SchemaError, iter_refs, publish, target_for


def write_schema(root: Path, rel: str, sid: str, body: dict | None = None) -> Path:
    """Write a schema file at rel with the given $id."""
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {"$id": sid}
    doc.update(body or {})
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def test_target_for_strips_the_namespace_base():
    doc = {"$id": BASE + "v0.1.0/acs_schema.json"}
    assert target_for(doc, Path("any.json")) == "v0.1.0/acs_schema.json"


def test_target_for_rejects_a_missing_id():
    with pytest.raises(SchemaError, match="no \\$id"):
        target_for({}, Path("broken.json"))


def test_target_for_rejects_an_out_of_namespace_id():
    doc = {"$id": "https://example.com/schema/v0.1.0/x.json"}
    with pytest.raises(SchemaError, match="outside namespace"):
        target_for(doc, Path("broken.json"))


def test_iter_refs_finds_nested_and_listed_refs():
    doc = {
        "$ref": "a.json",
        "properties": {"x": {"$ref": "b.json"}},
        "anyOf": [{"$ref": "c.json"}],
    }
    assert sorted(iter_refs(doc)) == ["a.json", "b.json", "c.json"]


def test_publish_places_files_at_their_declared_id_path(tmp_path):
    src, out = tmp_path / "spec", tmp_path / "out"
    # On-disk layout deliberately differs from the URI layout.
    write_schema(src, "ACS/acs_schema.json", BASE + "v0.1.0/acs_schema.json")
    published = publish(src, out)
    assert published == ["v0.1.0/acs_schema.json"]
    assert (out / "v0.1.0" / "acs_schema.json").is_file()


def test_publish_resolves_a_parent_relative_ref(tmp_path):
    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/provenance.json", BASE + "v0.1.0/provenance.json")
    write_schema(
        src,
        "v0.1.0/hooks/session-start.json",
        BASE + "v0.1.0/hooks/session-start.json",
        {"properties": {"p": {"$ref": "../provenance.json"}}},
    )
    assert len(publish(src, out)) == 2


def test_publish_fails_on_a_dangling_ref(tmp_path):
    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(
        src,
        "v0.1.0/a.json",
        BASE + "v0.1.0/a.json",
        {"properties": {"p": {"$ref": "./missing.json"}}},
    )
    with pytest.raises(SchemaError, match="which no \\$id publishes"):
        publish(src, out)


def test_publish_ignores_a_self_fragment_ref(tmp_path):
    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(
        src,
        "v0.1.0/a.json",
        BASE + "v0.1.0/a.json",
        {"properties": {"p": {"$ref": "#/$defs/x"}}, "$defs": {"x": {"type": "string"}}},
    )
    assert publish(src, out) == ["v0.1.0/a.json"]


def test_publish_ignores_an_external_ref(tmp_path):
    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(
        src,
        "v0.1.0/a.json",
        BASE + "v0.1.0/a.json",
        {"properties": {"p": {"$ref": "https://json-schema.org/draft/2020-12/schema"}}},
    )
    assert publish(src, out) == ["v0.1.0/a.json"]


def test_publish_fails_when_no_schemas_are_found(tmp_path):
    with pytest.raises(SchemaError, match="no schemas found"):
        publish(tmp_path / "empty", tmp_path / "out")


def test_publish_handles_the_real_specification_tree(tmp_path):
    """The repository's own schemas must publish and resolve completely."""
    repo = Path(__file__).resolve().parents[1]
    published = publish(repo / "specification", tmp_path / "out")
    assert len(published) == 44
    assert "v0.1.0/acs_schema.json" in published
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `uv run pytest tests/test_publish_schemas.py -v`
Expected: FAIL, collection error `ModuleNotFoundError: No module named 'publish_schemas'`

- [ ] **Step 5: Write the implementation**

Create `tools/publish_schemas.py`:

```python
#!/usr/bin/env python3
"""Publish JSON schemas to the paths their own $id values declare.

The on-disk layout does not match the URI layout. specification/ACS/acs_schema.json
declares an $id of .../schema/v0.1.0/acs_schema.json, so deriving the destination from
$id avoids a hardcoded special case and lets a future spec version publish untouched.
"""
from __future__ import annotations

import json
import shutil
import sys
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urldefrag, urljoin

BASE = "https://genai-security-project.github.io/agent-control-standard/schema/"


class SchemaError(Exception):
    """A schema is missing an $id, sits outside the namespace, or has a dangling $ref."""


def load_schemas(source: Path) -> dict[Path, dict]:
    """Parse every JSON file under source, keyed by path."""
    return {
        path: json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(source.rglob("*.json"))
    }


def target_for(doc: dict, path: Path) -> str:
    """Return the publish path a document's $id declares, relative to the schema root."""
    sid = doc.get("$id")
    if not sid:
        raise SchemaError(f"{path}: no $id")
    if not sid.startswith(BASE):
        raise SchemaError(f"{path}: $id outside namespace: {sid}")
    return sid[len(BASE) :]


def iter_refs(node: object) -> Iterator[str]:
    """Yield every $ref string anywhere in a parsed document."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                yield value
            else:
                yield from iter_refs(value)
    elif isinstance(node, list):
        for item in node:
            yield from iter_refs(item)


def verify_refs(docs: dict[Path, dict], published: dict[str, str]) -> None:
    """Fail if a $ref inside our namespace points at something we did not publish."""
    for path, doc in docs.items():
        sid = doc["$id"]
        for ref in iter_refs(doc):
            target, _ = urldefrag(urljoin(sid, ref))
            # A same-document fragment and an external reference are both fine.
            if target == sid or not target.startswith(BASE):
                continue
            if target not in published:
                raise SchemaError(
                    f"{path}: $ref {ref!r} resolves to {target}, which no $id publishes"
                )


def publish(source: Path, out: Path) -> list[str]:
    """Copy every schema to its $id-declared path. Return sorted relative paths."""
    docs = load_schemas(source)
    if not docs:
        raise SchemaError(f"no schemas found under {source}")
    published: dict[str, str] = {}
    for path, doc in docs.items():
        rel = target_for(doc, path)
        destination = out / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
        published[doc["$id"]] = rel
    verify_refs(docs, published)
    return sorted(published.values())


def main(argv: list[str]) -> int:
    source = Path(argv[1]) if len(argv) > 1 else Path("specification")
    out = Path(argv[2]) if len(argv) > 2 else Path("_site/schema")
    try:
        files = publish(source, out)
    except SchemaError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"published {len(files)} schemas to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `uv run pytest tests/test_publish_schemas.py -v`
Expected: PASS, 11 tests

- [ ] **Step 7: Run the publisher against the real tree**

Run: `uv run python tools/publish_schemas.py specification /tmp/schema-check`
Expected: `published 44 schemas to /tmp/schema-check`

- [ ] **Step 8: Commit**

```bash
git add pyproject.toml uv.lock tools/publish_schemas.py tests/test_publish_schemas.py
git commit -m "Publish schemas to the paths their \$id values declare

Derives each destination from the schema's own \$id rather than from
hardcoded directory names, then asserts that every \$ref inside the
namespace resolves to a published file.

The on-disk layout does not match the URI layout, so a hardcoded copy
needs a special case for specification/ACS/acs_schema.json and breaks
again on the first new spec version directory."
```

---

## Task 2: Landing page markup, styles, and assets

Builds the static page. Content that varies with repository state uses named placeholders that Task 3 fills.

**Files:**
- Create: `landing/index.html`
- Create: `landing/assets/acs.css`
- Create: `landing/assets/starburst.svg`
- Create: `landing/assets/icon.svg`
- Create: `tests/test_landing_page.py`
- Modify: `CLAUDE.md`

**Interfaces:**
- Consumes: nothing.
- Produces: three placeholder tokens that Task 3 replaces, spelled exactly `<!--ACS:SPEC_VERSION-->`, `<!--ACS:SCHEMA_COUNT-->`, `<!--ACS:WORKSTREAMS-->`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_landing_page.py`:

```python
"""Structural guards on the landing page. These encode premortem findings."""
import re
from pathlib import Path

import pytest

LANDING = Path(__file__).resolve().parents[1] / "landing"
HTML = LANDING / "index.html"
CSS = LANDING / "assets" / "acs.css"
SVG = LANDING / "assets" / "starburst.svg"

PLACEHOLDERS = ["<!--ACS:SPEC_VERSION-->", "<!--ACS:SCHEMA_COUNT-->", "<!--ACS:WORKSTREAMS-->"]


@pytest.fixture(scope="module")
def html() -> str:
    return HTML.read_text(encoding="utf-8")


def test_every_placeholder_is_present(html):
    for token in PLACEHOLDERS:
        assert token in html


def test_no_root_relative_links(html):
    """A project Pages site serves from /agent-control-standard/, so /docs/ would 404."""
    assert not re.search(r'(href|src)="/(?!/)', html)


def test_no_retired_project_links(html):
    assert "aos.owasp.org" not in html


def test_the_only_email_is_the_approved_one(html):
    found = set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", html))
    assert found == {"rock.lambros@owasp.org"}


def test_slack_points_at_the_owasp_workspace(html):
    assert "owasp.slack.com" in html
    assert "#team-genai-asi-acs-general" in html


def test_dark_theme_tokens_are_defined():
    css = CSS.read_text(encoding="utf-8")
    assert "--acs-page" in css
    assert 'data-theme="dark"' in css
    assert "prefers-color-scheme: dark" in css


def test_animation_respects_reduced_motion():
    css = CSS.read_text(encoding="utf-8")
    assert "prefers-reduced-motion: reduce" in css


def test_starburst_has_six_nodes_and_a_centre():
    svg = SVG.read_text(encoding="utf-8")
    for label in ["LLM", "Tool", "Output", "Sub", "Memory", "Code", "ACS"]:
        assert label in svg
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_landing_page.py -v`
Expected: FAIL, `FileNotFoundError` for `landing/index.html`

- [ ] **Step 3: Write the design tokens and layout**

Create `landing/assets/acs.css`. Token values are taken from the live site's stylesheet, not approximated.

```css
/* ACS landing page. Tokens mirror agentcontrolstandard.org. */

:root {
  --acs-page: #ffffff;
  --acs-surface: #f4f5f7;
  --acs-surface-2: #eef0f4;
  --acs-text: #121212;
  --acs-text-soft: #5f636d;
  --acs-text-muted: #6b7079;
  --acs-text-inverse: #f7f7f7;
  --acs-brand: #111111;
  --acs-accent-navy: #1b4f72;
  --acs-accent-teal: #17a2b8;
  --acs-border: #e5e7eb;
  --acs-border-strong: #d0d5dd;
  --acs-footer: #111111;
  --acs-focus-ring: hsla(0, 0%, 7%, 0.18);
  --acs-grid-line: hsla(0, 0%, 7%, 0.04);
  --acs-node-fill: #ffffff;
  --acs-node-stroke: #6b7079;
  --acs-spoke: #6b7079;
  --acs-hex-fill: #f4f5f7;
  --acs-hex-stroke: #c4cdd8;
  --acs-tier-1: #0f7b3f;
  --acs-tier-2: #1b4f72;
  --acs-tier-3: #6b46c1;
  --acs-font: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
    "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  --acs-mono: "JetBrains Mono", "Fira Code", ui-monospace, SFMono-Regular, monospace;
}

/* Dark tokens are redefined in two places so the toggle wins in both directions. */
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --acs-page: #0a0a0a;
    --acs-surface: #161616;
    --acs-surface-2: #202020;
    --acs-text: #ffffff;
    --acs-text-soft: #9ca3af;
    --acs-text-muted: #6b7280;
    --acs-brand: #1b4f72;
    --acs-accent-navy: #2e86c1;
    --acs-accent-teal: #1abc9c;
    --acs-border: #2a2a2a;
    --acs-border-strong: #373737;
    --acs-footer: #0a0a0a;
    --acs-focus-ring: hsla(0, 0%, 100%, 0.2);
    --acs-grid-line: hsla(0, 0%, 100%, 0.04);
    --acs-node-fill: #111111;
    --acs-node-stroke: #a0aec0;
    --acs-spoke: #3d4f65;
    --acs-hex-fill: #0d1117;
    --acs-hex-stroke: #63b3ed;
    --acs-tier-1: #48bb78;
    --acs-tier-2: #63b3ed;
    --acs-tier-3: #805ad5;
  }
}

:root[data-theme="dark"] {
  --acs-page: #0a0a0a;
  --acs-surface: #161616;
  --acs-surface-2: #202020;
  --acs-text: #ffffff;
  --acs-text-soft: #9ca3af;
  --acs-text-muted: #6b7280;
  --acs-brand: #1b4f72;
  --acs-accent-navy: #2e86c1;
  --acs-accent-teal: #1abc9c;
  --acs-border: #2a2a2a;
  --acs-border-strong: #373737;
  --acs-footer: #0a0a0a;
  --acs-focus-ring: hsla(0, 0%, 100%, 0.2);
  --acs-grid-line: hsla(0, 0%, 100%, 0.04);
  --acs-node-fill: #111111;
  --acs-node-stroke: #a0aec0;
  --acs-spoke: #3d4f65;
  --acs-hex-fill: #0d1117;
  --acs-hex-stroke: #63b3ed;
  --acs-tier-1: #48bb78;
  --acs-tier-2: #63b3ed;
  --acs-tier-3: #805ad5;
}

* { box-sizing: border-box; }

body {
  margin: 0;
  font-family: var(--acs-font);
  color: var(--acs-text);
  background-color: var(--acs-page);
  background-image: linear-gradient(var(--acs-grid-line) 1px, transparent 1px),
    linear-gradient(90deg, var(--acs-grid-line) 1px, transparent 1px);
  background-size: 64px 64px;
  line-height: 1.6;
}

a { color: inherit; }
a:focus-visible,
button:focus-visible { outline: 3px solid var(--acs-focus-ring); outline-offset: 2px; }

.layout { display: grid; grid-template-columns: 260px 1fr; }

.sidebar {
  position: sticky;
  top: 0;
  align-self: start;
  height: 100vh;
  padding: 2rem 1.5rem;
  border-right: 1px solid var(--acs-border);
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.wordmark { font-weight: 700; letter-spacing: 0.12em; font-size: 1.1rem; }
.sidebar nav { display: flex; flex-direction: column; gap: 0.6rem; }
.sidebar nav a { text-decoration: none; color: var(--acs-text-soft); }
.sidebar nav a:hover { color: var(--acs-text); }
.sidebar h2 { font-size: 0.75rem; text-transform: uppercase; color: var(--acs-text-muted); }

main { padding: 4rem 3rem; max-width: 1100px; }
section { padding-block: 3.5rem; border-top: 1px solid var(--acs-border); }
section:first-of-type { border-top: 0; }

.hero { display: grid; grid-template-columns: 1fr 1fr; gap: 3rem; align-items: center; }
.hero h1 { font-size: clamp(2.5rem, 6vw, 4.5rem); line-height: 1.02; letter-spacing: -0.03em; margin: 0; }
.hero p { font-size: 1.15rem; color: var(--acs-text-soft); }

.cta-row { display: flex; flex-wrap: wrap; gap: 0.75rem; margin-top: 1.5rem; }
.cta {
  display: inline-flex;
  align-items: center;
  min-height: 50px;
  padding: 0.85rem 1.25rem;
  border: 1px solid var(--acs-border-strong);
  border-radius: 999px;
  font-weight: 600;
  text-decoration: none;
  transition: transform 0.15s ease, background-color 0.15s ease;
}
.cta:hover { background-color: var(--acs-surface); transform: translateY(-1px); }
.cta-primary { background-color: var(--acs-brand); color: var(--acs-text-inverse); border-color: var(--acs-brand); }

.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 1.25rem; }
.card { padding: 1.5rem; border: 1px solid var(--acs-border); border-radius: 14px; background-color: var(--acs-surface); }
.card h3 { margin-top: 0; }

.tier { border-left: 4px solid var(--acs-border-strong); padding-left: 1rem; margin-bottom: 1.25rem; }
.tier-1 { border-left-color: var(--acs-tier-1); }
.tier-2 { border-left-color: var(--acs-tier-2); }
.tier-3 { border-left-color: var(--acs-tier-3); }

table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 0.6rem 0.5rem; border-bottom: 1px solid var(--acs-border); }
code { font-family: var(--acs-mono); background-color: var(--acs-surface-2); padding: 0.15em 0.4em; border-radius: 4px; }

footer { background-color: var(--acs-footer); color: var(--acs-text-inverse); padding: 3rem; }
footer a { color: var(--acs-text-inverse); }

@media (max-width: 1024px) {
  .layout { grid-template-columns: 1fr; }
  .sidebar { position: static; height: auto; border-right: 0; border-bottom: 1px solid var(--acs-border); }
  .hero { grid-template-columns: 1fr; }
  main { padding: 2rem 1.25rem; }
}

/* Premortem FM-6: continuous motion is a vestibular trigger and a battery cost. */
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation: none !important; transition: none !important; }
  .starburst animate,
  .starburst animateMotion { display: none; }
}
```

- [ ] **Step 4: Write the starburst**

Create `landing/assets/starburst.svg`. Geometry is taken from the live site: a `0 0 680 680` viewBox, centre at `(340, 340)`, six nodes of radius 48, and a centre hexagon. Node centres, clockwise from top: `(340, 80)` LLM agent, `(565.17, 210)` Tool call, `(565.17, 470)` Output guard, `(340, 600)` Sub agent, `(114.83, 470)` Memory store, `(114.83, 210)` Code exec.

```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 680 680" fill="none"
     class="starburst" role="img" aria-label="Six agent decision points routed through an ACS control panel">
  <defs>
    <radialGradient id="acs-glow" cx="50%" cy="50%" r="50%">
      <stop offset="0%" stop-color="currentColor" stop-opacity="0.15"/>
      <stop offset="100%" stop-color="currentColor" stop-opacity="0"/>
    </radialGradient>
  </defs>

  <circle cx="340" cy="340" r="150" fill="url(#acs-glow)" color="var(--acs-hex-stroke)">
    <animate attributeName="r" values="140;170;140" dur="8s" repeatCount="indefinite"/>
  </circle>

  <!-- Orbit rings expand outward on an eight second cycle, offset by half. -->
  <circle cx="340" cy="340" r="60" fill="none" stroke="var(--acs-hex-stroke)" stroke-width="0.5" opacity="0">
    <animate attributeName="r" values="60;240" dur="8s" begin="0s" repeatCount="indefinite"/>
    <animate attributeName="opacity" values="0.2;0" dur="8s" begin="0s" repeatCount="indefinite"/>
  </circle>
  <circle cx="340" cy="340" r="60" fill="none" stroke="var(--acs-hex-stroke)" stroke-width="0.5" opacity="0">
    <animate attributeName="r" values="60;240" dur="8s" begin="4s" repeatCount="indefinite"/>
    <animate attributeName="opacity" values="0.2;0" dur="8s" begin="4s" repeatCount="indefinite"/>
  </circle>

  <!--
    One group per node. Each carries a dashed quadratic spoke to the centre, a particle
    travelling that spoke, the node circle, and a two-line label. Stagger the particle
    begin times by 1.5s so traffic reads as continuous rather than synchronised.
  -->
  <g class="spoke">
    <path d="M340,340 Q356,197 340,80" stroke="var(--acs-spoke)" stroke-width="1.2" stroke-dasharray="4 3" fill="none"/>
    <circle r="3.5" fill="var(--acs-node-stroke)" opacity="0.7">
      <animateMotion dur="5s" begin="0s" repeatCount="indefinite" path="M340,340 Q356,197 340,80"/>
    </circle>
    <circle cx="340" cy="80" r="48" fill="var(--acs-node-fill)" stroke="var(--acs-node-stroke)" stroke-width="2" stroke-opacity="0.5"/>
    <text x="340" y="75" text-anchor="middle" fill="var(--acs-text-soft)" font-size="17" font-family="Inter, sans-serif">LLM</text>
    <text x="340" y="96" text-anchor="middle" fill="var(--acs-text-soft)" font-size="17" font-family="Inter, sans-serif">agent</text>
  </g>

  <g class="spoke">
    <path d="M340,340 Q471.84,282.36 565.17,210" stroke="var(--acs-spoke)" stroke-width="1.2" stroke-dasharray="4 3" fill="none"/>
    <circle r="3.5" fill="var(--acs-node-stroke)" opacity="0.7">
      <animateMotion dur="5.3s" begin="1.5s" repeatCount="indefinite" path="M340,340 Q471.84,282.36 565.17,210"/>
    </circle>
    <circle cx="565.17" cy="210" r="48" fill="var(--acs-node-fill)" stroke="var(--acs-node-stroke)" stroke-width="2" stroke-opacity="0.5"/>
    <text x="565.17" y="205" text-anchor="middle" fill="var(--acs-text-soft)" font-size="17" font-family="Inter, sans-serif">Tool</text>
    <text x="565.17" y="226" text-anchor="middle" fill="var(--acs-text-soft)" font-size="17" font-family="Inter, sans-serif">call</text>
  </g>

  <g class="spoke">
    <path d="M340,340 Q455.84,425.36 565.17,470" stroke="var(--acs-spoke)" stroke-width="1.2" stroke-dasharray="4 3" fill="none"/>
    <circle r="3.5" fill="var(--acs-node-stroke)" opacity="0.7">
      <animateMotion dur="5.6s" begin="3s" repeatCount="indefinite" path="M340,340 Q455.84,425.36 565.17,470"/>
    </circle>
    <circle cx="565.17" cy="470" r="48" fill="var(--acs-node-fill)" stroke="var(--acs-node-stroke)" stroke-width="2" stroke-opacity="0.5"/>
    <text x="565.17" y="465" text-anchor="middle" fill="var(--acs-text-soft)" font-size="17" font-family="Inter, sans-serif">Output</text>
    <text x="565.17" y="486" text-anchor="middle" fill="var(--acs-text-soft)" font-size="17" font-family="Inter, sans-serif">guard</text>
  </g>

  <g class="spoke">
    <path d="M340,340 Q324,483 340,600" stroke="var(--acs-spoke)" stroke-width="1.2" stroke-dasharray="4 3" fill="none"/>
    <circle r="3.5" fill="var(--acs-node-stroke)" opacity="0.7">
      <animateMotion dur="5.9s" begin="4.5s" repeatCount="indefinite" path="M340,340 Q324,483 340,600"/>
    </circle>
    <circle cx="340" cy="600" r="48" fill="var(--acs-node-fill)" stroke="var(--acs-node-stroke)" stroke-width="2" stroke-opacity="0.5"/>
    <text x="340" y="595" text-anchor="middle" fill="var(--acs-text-soft)" font-size="17" font-family="Inter, sans-serif">Sub</text>
    <text x="340" y="616" text-anchor="middle" fill="var(--acs-text-soft)" font-size="17" font-family="Inter, sans-serif">agent</text>
  </g>

  <g class="spoke">
    <path d="M340,340 Q208.16,397.64 114.83,470" stroke="var(--acs-spoke)" stroke-width="1.2" stroke-dasharray="4 3" fill="none"/>
    <circle r="3.5" fill="var(--acs-node-stroke)" opacity="0.7">
      <animateMotion dur="6.2s" begin="6s" repeatCount="indefinite" path="M340,340 Q208.16,397.64 114.83,470"/>
    </circle>
    <circle cx="114.83" cy="470" r="48" fill="var(--acs-node-fill)" stroke="var(--acs-node-stroke)" stroke-width="2" stroke-opacity="0.5"/>
    <text x="114.83" y="465" text-anchor="middle" fill="var(--acs-text-soft)" font-size="17" font-family="Inter, sans-serif">Memory</text>
    <text x="114.83" y="486" text-anchor="middle" fill="var(--acs-text-soft)" font-size="17" font-family="Inter, sans-serif">store</text>
  </g>

  <g class="spoke">
    <path d="M340,340 Q224.16,254.64 114.83,210" stroke="var(--acs-spoke)" stroke-width="1.2" stroke-dasharray="4 3" fill="none"/>
    <circle r="3.5" fill="var(--acs-node-stroke)" opacity="0.7">
      <animateMotion dur="6.5s" begin="7.5s" repeatCount="indefinite" path="M340,340 Q224.16,254.64 114.83,210"/>
    </circle>
    <circle cx="114.83" cy="210" r="48" fill="var(--acs-node-fill)" stroke="var(--acs-node-stroke)" stroke-width="2" stroke-opacity="0.5"/>
    <text x="114.83" y="205" text-anchor="middle" fill="var(--acs-text-soft)" font-size="17" font-family="Inter, sans-serif">Code</text>
    <text x="114.83" y="226" text-anchor="middle" fill="var(--acs-text-soft)" font-size="17" font-family="Inter, sans-serif">exec</text>
  </g>

  <g>
    <polygon points="340,272 398.89,306 398.89,374 340,408 281.11,374 281.11,306"
             fill="var(--acs-hex-fill)" stroke="var(--acs-hex-stroke)" stroke-width="2"/>
    <polygon points="340,291.04 382.4,315.52 382.4,364.48 340,388.96 297.6,364.48 297.6,315.52"
             fill="none" stroke="var(--acs-hex-stroke)" stroke-width="0.5" opacity="0.4"/>
    <text x="340" y="326" text-anchor="middle" fill="var(--acs-text)" font-size="18" font-family="Inter, sans-serif">ACS</text>
    <text x="340" y="346" text-anchor="middle" fill="var(--acs-text)" font-size="18" font-family="Inter, sans-serif">control</text>
    <text x="340" y="366" text-anchor="middle" fill="var(--acs-text)" font-size="18" font-family="Inter, sans-serif">panel</text>
  </g>
</svg>
```

- [ ] **Step 5: Write the favicon**

Create `landing/assets/icon.svg`, matching the live site's mark:

```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="32" height="32">
  <rect width="32" height="32" rx="6" fill="#1B4F72"/>
  <text x="16" y="21.5" text-anchor="middle" font-family="Inter, system-ui, sans-serif"
        font-size="12" font-weight="700" letter-spacing="0.5" fill="#FFFFFF">ACS</text>
</svg>
```

- [ ] **Step 6: Write the page**

Create `landing/index.html`. Copy follows `STYLE.md` and mirrors the live site's narrative.

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ACS — Agent Control Standard</title>
<meta name="description" content="The open standard for runtime agent control. Declarative hooks, policy enforcement, and observability across AI agent frameworks.">
<link rel="icon" href="assets/icon.svg">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=JetBrains+Mono&display=swap">
<link rel="stylesheet" href="assets/acs.css">
</head>
<body>
<div class="layout">
  <aside class="sidebar">
    <a class="wordmark" href=".">ACS</a>
    <nav aria-label="Sections">
      <a href="#problem">The problem</a>
      <a href="#solution">The solution</a>
      <a href="#architecture">How it works</a>
      <a href="#why-now">Why now</a>
      <a href="#status">Spec status</a>
      <a href="#workstreams">Workstreams</a>
      <a href="#contribute">Contribute</a>
    </nav>
    <div>
      <h2>External resources</h2>
      <nav aria-label="External resources">
        <a href="docs/">Specification</a>
        <a href="https://github.com/GenAI-Security-Project/agent-control-standard">GitHub</a>
        <a href="https://owasp.slack.com">Slack</a>
      </nav>
    </div>
    <button id="theme-toggle" type="button" aria-live="polite">Switch theme</button>
  </aside>

  <main>
    <section class="hero">
      <div>
        <h1>The runtime control plane for AI agents.</h1>
        <p>Agent Control Standard (ACS) is the open standard that defines how agent
        platforms expose middleware hooks and how open-source tooling enforces safety
        policy through those hooks. Declarative controls. Portable across frameworks.
        Enforced at runtime.</p>
        <div class="cta-row">
          <a class="cta cta-primary" href="docs/">Read the specification</a>
          <a class="cta" href="https://github.com/GenAI-Security-Project/agent-control-standard">View on GitHub</a>
          <a class="cta" href="https://owasp.slack.com">Join the conversation</a>
        </div>
      </div>
      <div><!--STARBURST--></div>
    </section>

    <section id="problem">
      <h2>Agents are shipping fast. Controls are not</h2>
      <p>AI agents act across organizational boundaries. The industry standardized how
      agents communicate through MCP and A2A, and documented the risks through the OWASP
      Agentic Top 10. Runtime control never got the same treatment.</p>
      <ul>
        <li>System prompts are not controls.</li>
        <li>Model improvements do not cover edge cases or adversarial inputs.</li>
        <li>Proprietary guardrails create vendor lock-in.</li>
      </ul>
    </section>

    <section id="solution">
      <h2>Three layers, one standard</h2>
      <div class="cards">
        <div class="card">
          <h3>Instrument</h3>
          <p>ACS defines standardized middleware hooks at every agent decision point. A
          Guardian Agent intercepts the action and returns a verdict: allow, deny, or
          modify.</p>
        </div>
        <div class="card">
          <h3>Trace</h3>
          <p>Agents emit structured trace data through OpenTelemetry, the pipeline your
          teams already run. ACS maps those traces to OCSF so security events land in the
          SIEM without a custom parser.</p>
        </div>
        <div class="card">
          <h3>Inspect</h3>
          <p>Enterprises cannot secure what they cannot inventory. AgBOM captures tools,
          models, and dependencies as the agent acquires them, which a static SBOM cannot
          do.</p>
        </div>
      </div>
    </section>

    <section id="architecture">
      <h2>How it works</h2>
      <div class="tier tier-1">
        <h3>Tier 1: Platform layer</h3>
        <p>Agent frameworks expose standardized middleware hooks.</p>
      </div>
      <div class="tier tier-2">
        <h3>Tier 2: Enforcement layer</h3>
        <p>An open-source SDK reads declarative policy and returns verdicts through those hooks.</p>
      </div>
      <div class="tier tier-3">
        <h3>Tier 3: Enterprise layer</h3>
        <p>Custom classifiers and domain-specific logic plug in behind the same interface.</p>
      </div>
    </section>

    <section id="why-now">
      <h2>Why now</h2>
      <p>The EU AI Act requires demonstrable human oversight of high-risk AI systems,
      including the ability to intervene in real time. The NIST AI Risk Management
      Framework calls for continuous monitoring and the capacity to disengage autonomous
      systems operating outside acceptable parameters.</p>
      <p>Both describe controls that have to exist at runtime. Neither is satisfied by a
      system prompt.</p>
    </section>

    <section id="built-with">
      <h2>Built with the community</h2>
      <p>OWASP ASI, AIVSS, OpenTelemetry, CycloneDX, SPDX, MCP, and A2A.</p>
    </section>

    <section id="status">
      <h2>Spec status</h2>
      <table>
        <tr><th>Specification version</th><td><code><!--ACS:SPEC_VERSION--></code></td></tr>
        <tr><th>Published schemas</th><td><!--ACS:SCHEMA_COUNT--></td></tr>
      </table>
      <p>Every schema resolves at the URI its <code>$id</code> declares. Start at
      <a href="schema/v0.1.0/acs_schema.json">the root schema</a>.</p>
    </section>

    <section id="workstreams">
      <h2>Workstreams</h2>
      <p>Each workstream owns a slice of the standard and runs its own review.</p>
      <table>
        <thead><tr><th>Workstream</th><th>Leads</th></tr></thead>
        <tbody><!--ACS:WORKSTREAMS--></tbody>
      </table>
    </section>

    <section id="contribute">
      <h2>Contribute</h2>
      <p>ACS is an open specification. The fastest way to shape it is to use it and tell
      us what breaks.</p>
      <ul>
        <li>Join <a href="https://owasp.slack.com">owasp.slack.com</a> and the
        <code>#team-genai-asi-acs-general</code> channel.</li>
        <li>Open an issue or a discussion on
        <a href="https://github.com/GenAI-Security-Project/agent-control-standard">GitHub</a>.</li>
        <li>Report a vulnerability through GitHub private vulnerability reporting.</li>
        <li>General contact: <a href="mailto:rock.lambros@owasp.org">rock.lambros@owasp.org</a></li>
      </ul>
    </section>
  </main>
</div>

<footer>
  <p>ACS is vendor neutral and community governed. Licensed under Apache 2.0.
  Documentation under CC BY-SA 4.0.</p>
  <p>A project of the OWASP GenAI Security Project.</p>
</footer>

<script>
  // Theme toggle. The page renders correctly without this; it only overrides the
  // system preference and remembers the override.
  (function () {
    var root = document.documentElement;
    try {
      var saved = localStorage.getItem("acs-theme");
      if (saved) root.setAttribute("data-theme", saved);
    } catch (e) { /* private mode blocks storage; system preference still applies */ }
    document.getElementById("theme-toggle").addEventListener("click", function () {
      var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("acs-theme", next); } catch (e) { /* ignore */ }
    });
  })();
</script>
</body>
</html>
```

- [ ] **Step 7: Inline the starburst**

Replace the `<!--STARBURST-->` comment in `landing/index.html` with the full contents of
`landing/assets/starburst.svg`, minus its XML declaration. Inlining is required because an
SVG loaded through `<img>` cannot read the page's CSS custom properties, so the diagram
would not follow the theme.

- [ ] **Step 8: Run the tests to verify they pass**

Run: `uv run pytest tests/test_landing_page.py -v`
Expected: PASS, 8 tests

- [ ] **Step 9: Amend the contact policy**

In `CLAUDE.md`, replace the first sentence of the "Contact channels" section with:

```markdown
The repository carries no email addresses except one. `rock.lambros@owasp.org` appears on
the landing page as general project contact. Every other channel stays as it was:
community contact is GitHub Discussions and the `#team-genai-asi-acs-general` channel on
`owasp.slack.com`, security reporting is GitHub private vulnerability reporting, and Code
of Conduct enforcement routes to the OWASP CoC process so that a report about a maintainer
does not land with the maintainers. Do not add any other contact address to documentation,
`project.owasp.yaml`, or the site config.
```

- [ ] **Step 10: Commit**

```bash
git add landing/ tests/test_landing_page.py CLAUDE.md
git commit -m "Add the landing page, its design tokens, and the starburst diagram

Tokens mirror agentcontrolstandard.org so the page matches the site it
will eventually replace. The starburst binds its fills and strokes to
theme tokens, which the live site's copy does not, so the diagram works
in dark mode.

Tests guard three things that are easy to regress: no root-relative
links, which 404 on a project Pages path; no aos.owasp.org links; and
one approved email address rather than any address.

Records the contact-policy exception in CLAUDE.md so the address does
not read as drift to a later reader."
```

---

## Task 3: Build-time content injection

Fills the placeholders from repository state so the published page cannot drift from the specification and the governance roster.

**Files:**
- Create: `tools/render_landing.py`
- Create: `tests/test_render_landing.py`

**Interfaces:**
- Consumes: `publish_schemas.load_schemas`, `publish_schemas.target_for`, and the three placeholder tokens from Task 2.
- Produces:
  - `class RenderError(Exception)`
  - `spec_version(source: Path) -> str`
  - `schema_count(source: Path) -> int`
  - `parse_workstreams(text: str) -> list[tuple[str, str]]`
  - `render_workstreams(rows: list[tuple[str, str]]) -> str`
  - `render(template: str, source: Path, governance: str) -> str`
  - CLI: `python tools/render_landing.py <landing_dir> <out_dir>`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_render_landing.py`:

```python
"""Tests for build-time content injection."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from publish_schemas import BASE
from render_landing import (
    RenderError,
    parse_workstreams,
    render,
    render_workstreams,
    schema_count,
    spec_version,
)

GOVERNANCE = """# Governance

## Project lead

| Role | Name |
| --- | --- |
| Project Lead | Rock Lambros ([@rocklambros](https://github.com/rocklambros)) |

## Workstream leads

Prose that must not be parsed as a row.

| Workstream | Leads |
| --- | --- |
| Identity | Eva Benn ([@evabenn](https://github.com/evabenn)) |
| Spec | Bar Kaduri ([@bar-capsule](https://github.com/bar-capsule)) |

## Origins

Not a workstream.
"""


@pytest.fixture
def spec_tree(tmp_path: Path) -> Path:
    root = tmp_path / "specification"
    (root / "v0.1.0").mkdir(parents=True)
    for name in ("a.json", "b.json"):
        (root / "v0.1.0" / name).write_text(
            json.dumps({"$id": BASE + f"v0.1.0/{name}"}), encoding="utf-8"
        )
    return root


def test_spec_version_reads_the_id_namespace(spec_tree):
    assert spec_version(spec_tree) == "v0.1.0"


def test_schema_count_counts_every_schema(spec_tree):
    assert schema_count(spec_tree) == 2


def test_spec_version_rejects_a_mixed_namespace(tmp_path):
    root = tmp_path / "specification"
    root.mkdir()
    for version in ("v0.1.0", "v0.2.0"):
        (root / f"{version}.json").write_text(
            json.dumps({"$id": BASE + f"{version}/x.json"}), encoding="utf-8"
        )
    with pytest.raises(RenderError, match="more than one spec version"):
        spec_version(root)


def test_parse_workstreams_reads_only_the_workstream_table():
    rows = parse_workstreams(GOVERNANCE)
    assert [name for name, _ in rows] == ["Identity", "Spec"]


def test_parse_workstreams_fails_without_the_section():
    with pytest.raises(RenderError, match="Workstream leads"):
        parse_workstreams("# Governance\n\nNothing here.\n")


def test_render_workstreams_converts_markdown_links_to_html():
    html = render_workstreams([("Identity", "Eva Benn ([@evabenn](https://example.com))")])
    assert '<a href="https://example.com">@evabenn</a>' in html
    assert "<tr><td>Identity</td>" in html


def test_render_fills_every_placeholder(spec_tree):
    template = (
        "<p><!--ACS:SPEC_VERSION--></p>"
        "<p><!--ACS:SCHEMA_COUNT--></p>"
        "<tbody><!--ACS:WORKSTREAMS--></tbody>"
    )
    out = render(template, spec_tree, GOVERNANCE)
    assert "v0.1.0" in out
    assert ">2<" in out
    assert "Identity" in out


def test_render_fails_when_a_placeholder_survives(spec_tree):
    with pytest.raises(RenderError, match="unfilled placeholder"):
        render("<p><!--ACS:UNKNOWN--></p>", spec_tree, GOVERNANCE)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_render_landing.py -v`
Expected: FAIL, collection error `ModuleNotFoundError: No module named 'render_landing'`

- [ ] **Step 3: Write the implementation**

Create `tools/render_landing.py`:

```python
#!/usr/bin/env python3
"""Fill the landing page's placeholders from repository state.

Injection happens at build time rather than in the browser, so the published page stays
static and renders with JavaScript disabled.
"""
from __future__ import annotations

import html
import re
import shutil
import sys
from pathlib import Path

from publish_schemas import SchemaError, load_schemas, target_for

WORKSTREAM_HEADING = "## Workstream leads"
MD_LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
PLACEHOLDER = re.compile(r"<!--ACS:[A-Z_]+-->")


class RenderError(Exception):
    """Repository state does not supply what the template asks for."""


def _versions(source: Path) -> set[str]:
    try:
        docs = load_schemas(source)
    except SchemaError as error:
        raise RenderError(str(error)) from error
    return {target_for(doc, path).split("/")[0] for path, doc in docs.items()}


def spec_version(source: Path) -> str:
    """Return the single spec version the schema namespace declares."""
    versions = _versions(source)
    if not versions:
        raise RenderError(f"no schemas found under {source}")
    if len(versions) > 1:
        raise RenderError(
            f"more than one spec version published: {sorted(versions)}. "
            "The page shows one, so decide which is current."
        )
    return versions.pop()


def schema_count(source: Path) -> int:
    return len(load_schemas(source))


def parse_workstreams(text: str) -> list[tuple[str, str]]:
    """Read the two-column table under the Workstream leads heading."""
    lines = text.splitlines()
    try:
        start = lines.index(WORKSTREAM_HEADING)
    except ValueError as error:
        raise RenderError(f"GOVERNANCE.md: no '{WORKSTREAM_HEADING}' section") from error

    rows: list[tuple[str, str]] = []
    for line in lines[start + 1 :]:
        if line.startswith("## "):
            break
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if len(cells) != 2:
            continue
        # Skip the header row and the dashed separator.
        if cells[0].lower() == "workstream" or set(cells[0]) <= set("-: "):
            continue
        rows.append((cells[0], cells[1]))

    if not rows:
        raise RenderError("GOVERNANCE.md: the workstream table is empty")
    return rows


def _to_html(markdown: str) -> str:
    # Escape first, then substitute, so the anchors we insert keep real quotes.
    return MD_LINK.sub(r'<a href="\2">\1</a>', html.escape(markdown, quote=False))


def render_workstreams(rows: list[tuple[str, str]]) -> str:
    return "".join(
        f"<tr><td>{_to_html(name)}</td><td>{_to_html(leads)}</td></tr>" for name, leads in rows
    )


def render(template: str, source: Path, governance: str) -> str:
    """Replace every placeholder. Fail if one survives."""
    out = template.replace("<!--ACS:SPEC_VERSION-->", spec_version(source))
    out = out.replace("<!--ACS:SCHEMA_COUNT-->", str(schema_count(source)))
    out = out.replace("<!--ACS:WORKSTREAMS-->", render_workstreams(parse_workstreams(governance)))
    survivors = PLACEHOLDER.findall(out)
    if survivors:
        raise RenderError(f"unfilled placeholder: {', '.join(sorted(set(survivors)))}")
    return out


def main(argv: list[str]) -> int:
    landing = Path(argv[1]) if len(argv) > 1 else Path("landing")
    out = Path(argv[2]) if len(argv) > 2 else Path("_site")
    repo = Path(__file__).resolve().parents[1]
    try:
        page = render(
            (landing / "index.html").read_text(encoding="utf-8"),
            repo / "specification",
            (repo / "GOVERNANCE.md").read_text(encoding="utf-8"),
        )
    except RenderError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    out.mkdir(parents=True, exist_ok=True)
    (out / "index.html").write_text(page, encoding="utf-8")
    shutil.copytree(landing / "assets", out / "assets", dirs_exist_ok=True)
    print(f"rendered landing page to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_render_landing.py -v`
Expected: PASS, 8 tests

- [ ] **Step 5: Render the real page and check it by eye**

Run: `uv run python tools/render_landing.py landing /tmp/landing-check && open /tmp/landing-check/index.html`
Expected: the page renders with `v0.1.0`, `44`, and five workstream rows. Toggle the theme and confirm the starburst follows it.

- [ ] **Step 6: Commit**

```bash
git add tools/render_landing.py tests/test_render_landing.py
git commit -m "Inject spec version and workstreams into the landing page at build time

Reads the version from the schema \$id namespace and the roster from
GOVERNANCE.md, so neither can drift from the repository. Injection runs
at build time, so the published page needs no client-side fetch.

Fails the build when a placeholder survives, when the governance table
is missing, and when the namespace carries more than one spec version,
because the page shows a single version and that ambiguity needs a human
decision."
```

---

## Task 4: Site configuration cleanup

Removes the analytics tag and keeps local builds out of the working tree.

**Files:**
- Modify: `mkdocs.yml`
- Modify: `.gitignore`
- Create: `tests/test_site_config.py`

**Interfaces:**
- Consumes: nothing.
- Produces: a MkDocs build that emits no third-party tracker.

- [ ] **Step 1: Write the failing test**

Create `tests/test_site_config.py`:

```python
"""Regression guard on the built documentation site.

Verified before this change: with GOOGLE_ANALYTICS_KEY set to an empty string, and also
with the variable unset entirely, Material emitted <script src=".../gtag/js?id=">. No env
value suppressed it, so the analytics block itself had to be removed.
"""
import os
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def test_built_site_contains_no_analytics_tag(tmp_path):
    env = dict(os.environ)
    env.pop("GOOGLE_ANALYTICS_KEY", None)
    env["GITHUB_PAGES_URL"] = "https://example.org/"
    subprocess.run(
        ["uv", "run", "mkdocs", "build", "--strict", "-d", str(tmp_path)],
        cwd=REPO,
        env=env,
        check=True,
        capture_output=True,
    )
    for page in tmp_path.rglob("*.html"):
        assert "googletagmanager" not in page.read_text(encoding="utf-8")


def test_mkdocs_config_declares_no_analytics():
    assert "analytics" not in (REPO / "mkdocs.yml").read_text(encoding="utf-8")
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_site_config.py -v`
Expected: FAIL, `assert "googletagmanager" not in ...` and `assert "analytics" not in ...`

- [ ] **Step 3: Remove the analytics block**

In `mkdocs.yml`, delete these four lines from the `extra:` block:

```yaml
  analytics:
    provider: google
    property: !ENV GOOGLE_ANALYTICS_KEY
```

Leave the rest of `extra:` intact, so `social:` remains the first key under it.

- [ ] **Step 4: Ignore local build output**

Append to `.gitignore`:

```gitignore
_site/
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/test_site_config.py -v`
Expected: PASS, 2 tests

- [ ] **Step 6: Commit**

```bash
git add mkdocs.yml .gitignore tests/test_site_config.py
git commit -m "Stop shipping a Google Analytics tag with an empty property

Material emits a googletagmanager script tag whenever the analytics
block exists, including when GOOGLE_ANALYTICS_KEY is unset entirely.
Publishing as configured would have sent a third-party request carrying
the referrer and client IP of every documentation reader, in exchange
for no analytics data.

No environment value suppresses the tag, so the block had to go. Adding
analytics back means restoring the block and supplying a real property
through a repository secret."
```

---

## Task 5: Deploy workflow

Assembles the artifact and publishes it. Pull requests build without deploying.

**Files:**
- Create: `.github/workflows/deploy-pages.yml`
- Modify: `CLAUDE.md`

**Interfaces:**
- Consumes: `tools/publish_schemas.py`, `tools/render_landing.py`, `landing/`, `mkdocs.yml`.
- Produces: a Pages deployment at `https://genai-security-project.github.io/agent-control-standard/`.

- [ ] **Step 1: Write the workflow**

Create `.github/workflows/deploy-pages.yml`:

```yaml
# Builds and publishes the landing page, the documentation site, and the JSON schemas.
# Pull requests build but do not deploy, so a broken build surfaces before merge rather
# than after. Merge to main publishes with no human in the loop.
name: Deploy Pages

on:
  push:
    branches: ["main"]
  pull_request:
  workflow_dispatch:

# Deny by default. Each job grants itself only what it needs.
permissions: {}

# Scope the group by ref so a pull request build never queues behind a deploy.
# Stale pull request builds cancel. Deploys never cancel, because a cancelled deploy
# leaves the site half published.
concurrency:
  group: pages-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - name: Check out the repository
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - name: Install uv
        uses: astral-sh/setup-uv@c771a70e6277c0a99b617c7a806ffedaca235ff9 # v9.0.0
        with:
          version: "0.9.9"

      - name: Install dependencies from the lockfile
        run: uv sync --locked --no-dev

      - name: Configure Pages
        id: pages
        uses: actions/configure-pages@45bfe0192ca1faeb007ade9deae92b16b8254a0d # v6.0.0

      - name: Build the documentation site
        env:
          # mkdocs.yml reads site_url from this. Unset produces no canonical URL.
          GITHUB_PAGES_URL: ${{ steps.pages.outputs.base_url }}
        # --no-dev on every run call, so uv never re-adds the test dependencies that
        # `uv sync --no-dev` deliberately left out of the deploy environment.
        run: uv run --no-dev mkdocs build --strict -d _site/docs

      - name: Render the landing page
        run: uv run --no-dev python tools/render_landing.py landing _site

      - name: Publish the schemas
        # Fails when any $id or $ref in the package does not resolve.
        run: uv run --no-dev python tools/publish_schemas.py specification _site/schema

      - name: Upload the artifact
        if: github.event_name != 'pull_request'
        uses: actions/upload-pages-artifact@fc324d3547104276b827a68afc52ff2a11cc49c9 # v5.0.0
        with:
          path: _site

  deploy:
    if: github.event_name != 'pull_request'
    needs: build
    runs-on: ubuntu-latest
    permissions:
      pages: write
      id-token: write
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    steps:
      - name: Deploy to Pages
        id: deployment
        uses: actions/deploy-pages@368f82528645a54fb793d4d04e342629a3f51346 # v5.0.1

      - name: Verify the schema namespace resolves
        # The gap this workflow exists to close. Assert it closed.
        run: |
          set -euo pipefail
          URL="${{ steps.deployment.outputs.page_url }}schema/v0.1.0/acs_schema.json"
          CODE="$(curl -sS -o /dev/null -w '%{http_code}' --retry 5 --retry-delay 5 \
            --retry-all-errors "$URL")"
          if [ "$CODE" != "200" ]; then
            echo "::error::$URL returned $CODE, expected 200"
            exit 1
          fi
          echo "$URL returned 200"
```

- [ ] **Step 2: Validate the workflow parses**

Run: `uv run python -c "import yaml,pathlib; yaml.safe_load(pathlib.Path('.github/workflows/deploy-pages.yml').read_text())"`
Expected: no output, exit 0

- [ ] **Step 3: Reproduce the build locally**

```bash
rm -rf _site
GITHUB_PAGES_URL="https://genai-security-project.github.io/agent-control-standard/" \
  uv run mkdocs build --strict -d _site/docs
uv run python tools/render_landing.py landing _site
uv run python tools/publish_schemas.py specification _site/schema
```

Expected: `published 44 schemas to _site/schema`, and `_site` contains `index.html`,
`docs/index.html`, and `schema/v0.1.0/acs_schema.json`.

- [ ] **Step 4: Run the full test suite**

Run: `uv run pytest -v`
Expected: PASS, 29 tests

- [ ] **Step 5: Record what this repository now hosts**

In `CLAUDE.md`, replace the body of the "Hosting (decoupled from this repo)" section with:

```markdown
This repository is the source of truth for the ACS spec and, since the Pages workflow
landed, it also publishes the site. `.github/workflows/deploy-pages.yml` builds three
things on every merge to `main`: the landing page from `landing/`, the MkDocs
documentation under `/docs/`, and the JSON schemas under `/schema/<spec-version>/`.

Schema publish paths derive from each schema's own `$id`, so a new spec version directory
publishes with no workflow edit, and the build fails when any `$id` or `$ref` does not
resolve.

The marketing site at **agentcontrolstandard.org** is still built and deployed from a
separate repository. It will redirect here later. Adding the custom domain makes GitHub
301 the `github.io` URIs to it, which schema tooling follows. Do not rebase `$id` onto the
marketing domain during that cutover.
```

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/deploy-pages.yml CLAUDE.md
git commit -m "Build and publish the site on every merge to main

Assembles the landing page, the documentation, and the schemas into one
Pages artifact. Pull requests build without deploying, so a broken build
surfaces before merge rather than after.

Concurrency queues rather than cancels, because a cancelled deploy
leaves the site half published. The deploy job asserts that the root
schema returns 200, which is the gap this workflow exists to close."
```

---

## Task 6: Enable Pages and verify the first deploy

The only step that changes state outside the repository. Requires admin rights, which the project lead holds.

**Files:** none.

**Interfaces:**
- Consumes: the workflow from Task 5.
- Produces: a live site.

- [ ] **Step 1: Open the pull request**

```bash
git push -u origin feat/github-pages-site
gh pr create --title "Publish the ACS site and schemas from this repository" \
  --body "Enables GitHub Pages and publishes three things on every merge to main: a landing page matching the agentcontrolstandard.org design, the existing MkDocs specification site, and all 44 JSON schemas at the URIs their \$id values declare.

Schema publish paths derive from each schema's own \$id, and the build fails when any \$id or \$ref does not resolve.

Also removes the Google Analytics block. Material emitted a tag with an empty property whenever the block was present, including with the variable unset.

Design: design/2026-09-05-github-pages-landing.md
Plan: design/plans/2026-09-05-github-pages-site.md"
```

- [ ] **Step 2: Confirm the PR build is green**

Run: `gh pr checks --watch`
Expected: the `build` job passes and no `deploy` job runs.

- [ ] **Step 3: Enable Pages with the workflow build type**

This publishes a public website. Confirm with the project lead before running it.

```bash
gh api -X POST repos/GenAI-Security-Project/agent-control-standard/pages \
  -f 'build_type=workflow'
```

Expected: JSON describing the new Pages site. If it returns `409 Conflict`, Pages is
already enabled; switch the build type instead:

```bash
gh api -X PUT repos/GenAI-Security-Project/agent-control-standard/pages \
  -f 'build_type=workflow'
```

- [ ] **Step 4: Merge**

```bash
gh pr merge --squash
```

- [ ] **Step 5: Watch the deploy**

Run: `gh run watch`
Expected: `build` then `deploy` both pass, including the schema verification step.

- [ ] **Step 6: Verify the three surfaces by hand**

```bash
BASE="https://genai-security-project.github.io/agent-control-standard"
for path in "" "docs/" "schema/v0.1.0/acs_schema.json" "schema/v0.1.0/hooks/session-start.json"; do
  printf '%s -> %s\n' "$path" "$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/$path")"
done
```

Expected: `200` for all four.

- [ ] **Step 7: Verify a schema resolves at its declared `$id`**

```bash
curl -sS "https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/acs_schema.json" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['\$id'])"
```

Expected: the URL prints back its own `$id`, confirming the file is served at the URI it
declares. This is the outcome the whole plan exists to produce.

---

## Self-Review

**Spec coverage.** Every section of `design/2026-09-05-github-pages-landing.md` maps to a
task: schema publishing to Task 1, landing page and tokens and starburst to Task 2,
generated content to Task 3, the analytics removal and `.gitignore` to Task 4, the pipeline
and the `CLAUDE.md` hosting section to Task 5, and Pages enablement plus the smoke test to
Task 6. The accepted risk and the domain cutover note are recorded in the spec and repeated
in the `CLAUDE.md` amendment rather than implemented.

**Premortem coverage.** FM-1 is Task 1. FM-2 is Task 4, with the failing test written
before the fix. FM-4 and the email guard are tests in Task 2. FM-5 is Task 3. FM-6 is the
reduced-motion block in Task 2. FM-7, FM-8, and FM-10 are the workflow in Task 5. FM-9 is
Task 4.

**Type consistency.** `render_landing.py` imports `load_schemas`, `target_for`, and
`SchemaError` from `publish_schemas`, all defined in Task 1 with matching signatures. The
placeholder tokens are spelled identically in Task 2's HTML, Task 2's test, and Task 3's
implementation and tests. Both CLI entry points take `<source> <out>` in that order.

**Known gap, deliberately out of scope.** Seven A2A hook pages under
`docs/spec/instrument/a2a/hooks/` are absent from the `mkdocs.yml` navigation and will
publish as orphans reachable only by direct URL. `--strict` does not fail on this, because
MkDocs reports it at INFO level. Fix it separately.
