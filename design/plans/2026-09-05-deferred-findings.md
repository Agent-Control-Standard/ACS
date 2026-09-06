# Deferred Findings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the twenty findings carried from the Pages branch reviews and from the premortem of this work's own first design, on a site that is already live and serving 44 schemas to external consumers.

**Architecture:** Five commits, each one coherent idea with its own tests. The order matters once: the non-normative fix is a real defect on a live site and goes first.

**Tech Stack:** Python 3.11+, uv, pytest, MkDocs Material, GitHub Actions.

**Spec:** `design/2026-09-05-deferred-findings-design.md` (version 2.0)

## Global Constraints

- Python `>=3.11`, matching `pyproject.toml` `requires-python`.
- The published site must load no third-party asset and make no third-party request.
- `$id` and `GOVERNANCE.md` are untrusted input. `$id` is a pull-request-writable string used to build a filesystem path.
- Every GitHub Action stays SHA-pinned with its version comment. No `uses:` line changes in this plan.
- Never interpolate `${{ }}` inside a `run:` block.
- No em dash anywhere. American English. No semicolons in prose, including comments and docstrings. CSS and Python statements ending in semicolons are syntax, not prose. No sentences starting with conjunctions. Avoid: just, very, really, actually, certainly, basically, literally, utilize, facilitate, leverage, robust, seamless, transformative, holistic, unlock, unleash, empower.
- Never credit an AI in commit messages, code comments, or file headers. The git author stays the human.
- All work lands on branch `fix/deferred-findings`.

---

## File Structure

| File | Change |
|---|---|
| `tools/publish_schemas.py` | Normalize `NON_NORMATIVE`, restructure `publish()` into validate-then-write |
| `tools/render_landing.py` | Shared `_version_key`, single load via `_schema_facts`, widened error boundary |
| `tools/verify_published.py` | Exception handling, final-sleep, diagnostics |
| `tests/conftest.py` | Widened attribute coverage, first-party JS assertion helper |
| `tests/test_publish_schemas.py` | Non-normative matrix, absence-not-emptiness, regex drift |
| `tests/test_render_landing.py` | Anchor assertion, `main()` coverage |
| `tests/test_site_config.py` | Widened guard, per-host page lists |
| `tests/test_landing_page.py` | Widened guard, starburst root assertion |
| `tests/test_docs_theme.py` | Same file coverage as its sibling |
| `tests/test_verify_published.py` | **New.** The module has no coverage today |
| `.github/workflows/deploy-pages.yml` | Branch gate on two steps |
| `landing/assets/starburst.svg` | One root `font-family` |
| `.github/CODEOWNERS`, `SECURITY.md`, `CLAUDE.md`, `LICENSING.md` | Ownership and document corrections |

---

## Task 1: Normalize the non-normative check

The live defect. A draft schema under a directory named `Proposals` publishes to the normative namespace that external tools fetch. Measured: `Proposals`, `PROPOSALS`, `proposal`, and `drafts` all publish today.

**Files:**
- Modify: `tools/publish_schemas.py`
- Test: `tests/test_publish_schemas.py`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: `NON_NORMATIVE: tuple[str, ...]` widened and compared case-folded. No signature changes.

- [ ] **Step 1: Write the failing matrix test**

Add to `tests/test_publish_schemas.py`:

```python
@pytest.mark.parametrize("directory", [
    "proposals", "Proposals", "PROPOSALS",
    "proposal", "drafts", "draft", "wip", "experimental",
])
@pytest.mark.parametrize("depth", ["{d}", "v0.1.0/{d}", "nested/deep/{d}"])
def test_a_draft_directory_cannot_claim_the_normative_namespace(tmp_path, directory, depth):
    """One name at one depth in one casing hid this defect through four reviews.

    Measured before the fix: Proposals, PROPOSALS, proposal, and drafts all published
    a draft schema to the live normative namespace.
    """
    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/real.json", BASE + "v0.1.0/real.json")
    write_schema(src, f"{depth.format(d=directory)}/draft.json", BASE + "v0.1.0/draft.json")
    with pytest.raises(SchemaError, match="must not claim the normative namespace"):
        publish(src, out)
```

- [ ] **Step 2: Run it and watch it fail**

Run: `uv run pytest tests/test_publish_schemas.py -k draft_directory -q`
Expected: FAIL. 21 of 24 cases fail (only the three lowercase `proposals` cases pass).

- [ ] **Step 3: Widen and normalize the check**

In `tools/publish_schemas.py`, replace the `NON_NORMATIVE` constant and its comment:

```python
# Draft schemas must never claim a normative URI. The comparison is case-folded
# because a directory named Proposals carries the same intent as proposals, and a
# path check that is not normalized is incomplete rather than strict. This list is
# the part a contributor will forget to extend, so the test covers every name in it
# at several depths and casings.
NON_NORMATIVE = ("proposals", "proposal", "drafts", "draft", "wip", "experimental")
```

Then replace the check inside `target_for`:

```python
    if any(part.casefold() in NON_NORMATIVE for part in path.parts):
        raise SchemaError(
            f"{path}: a file under a draft directory must not claim the "
            f"normative namespace ($id: {sid})"
        )
```

- [ ] **Step 4: Run the matrix and the suite**

Run: `uv run pytest tests/test_publish_schemas.py -q`
Expected: PASS, all 24 parametrized cases plus the existing tests.

- [ ] **Step 5: Confirm the real tree is unaffected**

Run: `uv run python tools/publish_schemas.py specification /tmp/t1 && ls /tmp/t1/v0.1.0 | wc -l`
Expected: `published 44 schemas`, and the count is unchanged. `specification/proposals/` holds only a Markdown file, so nothing that published before stops publishing.

- [ ] **Step 6: Commit**

```bash
git add tools/publish_schemas.py tests/test_publish_schemas.py
git commit -m "Refuse the normative namespace to every draft directory

The check compared path segments against one lowercase literal, so a
draft schema under a directory named Proposals published to the live
namespace that external tools fetch. Measured: Proposals, PROPOSALS,
proposal, and drafts all published.

An earlier review proposed matching only the top-level directory and
that recommendation was declined on the grounds that matching at any
depth fails safe. Both arguments were about depth. The defect was string
equality, so neither addressed it.

The comparison is now case-folded across a family of draft directory
names, and the test covers every name at three depths in three casings,
because one name at one depth in one casing is what hid this."
```

---

## Task 2: Validate everything, then write validated bytes

**Files:**
- Modify: `tools/publish_schemas.py`
- Test: `tests/test_publish_schemas.py`

**Interfaces:**
- Consumes: `NON_NORMATIVE` from Task 1, unchanged in shape.
- Produces: `publish(source, out) -> list[str]`, same signature. `verify_refs(docs, by_id)` unchanged.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_publish_schemas.py`:

```python
def test_a_dangling_ref_writes_nothing_at_all(tmp_path):
    """Verification runs before any write, so a failure leaves no output directory.

    Measured before the fix: a dangling $ref wrote all 44 files before raising,
    because verification ran after the copy loop. A partial tree came from an $id
    failure instead, which raised mid-loop at 43 of 44.
    """
    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/a.json", BASE + "v0.1.0/a.json",
                 {"properties": {"p": {"$ref": "./missing.json"}}})
    write_schema(src, "v0.1.0/b.json", BASE + "v0.1.0/b.json")
    with pytest.raises(SchemaError, match="which no \\$id publishes"):
        publish(src, out)
    assert not out.exists(), "the output directory must not exist after a failure"


def test_an_id_failure_also_writes_nothing(tmp_path):
    """The other failure class. Before the fix this wrote every file up to the bad one."""
    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/a.json", BASE + "v0.1.0/a.json")
    write_schema(src, "v0.1.0/z.json", BASE + "../escape.json")
    with pytest.raises(SchemaError):
        publish(src, out)
    assert not out.exists()


def test_published_bytes_come_from_the_validated_read(tmp_path):
    """The write uses the bytes validation saw, not a fresh read of the source.

    Re-reading at write time leaves a window between validation and write that the
    restructure widens, because every other schema is validated in between.
    """
    src, out = tmp_path / "spec", tmp_path / "out"
    target = write_schema(src, "v0.1.0/a.json", BASE + "v0.1.0/a.json", {"marker": "original"})
    original = target.read_bytes()
    publish(src, out)
    assert (out / "v0.1.0" / "a.json").read_bytes() == original
```

- [ ] **Step 2: Run and watch them fail**

Run: `uv run pytest tests/test_publish_schemas.py -k "writes_nothing or validated_read" -q`
Expected: FAIL. The two `writes_nothing` tests fail on `assert not out.exists()` because `publish` calls `out.mkdir` before the loop.

- [ ] **Step 3: Restructure publish()**

In `tools/publish_schemas.py`, replace the whole body of `publish()`:

```python
def publish(source: Path, out: Path) -> list[str]:
    """Validate every schema, then write the bytes validation saw.

    Nothing is created until the whole package has passed. A fork pull request reaches
    this code on a runner before human review, so bounding what a failed run leaves on
    disk is the point. Writing the bytes read during validation, rather than re-reading
    the source, closes the window between the two.
    """
    docs = load_schemas(source)
    if not docs:
        raise SchemaError(f"no schemas found under {source}")

    out_root = out.resolve()
    by_id: dict[str, dict] = {}
    seen: dict[str, Path] = {}
    planned: list[tuple[Path, str, bytes]] = []

    for path, doc in docs.items():
        rel = target_for(doc, path)
        sid = doc["$id"]
        if sid in seen:
            raise SchemaError(f"{path}: duplicate $id {sid}, already declared by {seen[sid]}")
        seen[sid] = path

        destination = (out / rel).resolve()
        # Belt and braces. SAFE_TAIL should make this unreachable. If it ever is
        # reachable, the build stops rather than writing outside the artifact.
        if not destination.is_relative_to(out_root):
            raise SchemaError(f"{path}: $id escapes the output root: {sid}")

        planned.append((destination, rel, path.read_bytes()))
        by_id[sid] = doc

    verify_refs(docs, by_id)

    for destination, _rel, payload in planned:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)

    return sorted(rel for _destination, rel, _payload in planned)
```

`shutil` is still used by nothing else in this module. Remove the `import shutil` line.

- [ ] **Step 4: Run the suite**

Run: `uv run pytest tests/test_publish_schemas.py -q`
Expected: PASS.

- [ ] **Step 5: Confirm output is byte-identical to before**

```bash
git stash && uv run python tools/publish_schemas.py specification /tmp/before >/dev/null && git stash pop
uv run python tools/publish_schemas.py specification /tmp/after
diff -r /tmp/before /tmp/after && echo "IDENTICAL"
```

Expected: `published 44 schemas` and `IDENTICAL`. The restructure must not change what is published.

- [ ] **Step 6: Commit**

```bash
git add tools/publish_schemas.py tests/test_publish_schemas.py
git commit -m "Validate the whole package before writing any of it

Verification ran after the copy loop, so a dangling reference wrote all
44 files before failing, and an id failure wrote every file up to the
bad one. Neither reached the live site, because the build job stops
before the upload step either way.

The reason to fix it is narrower than availability. This code runs on a
runner against a fork pull request's tree before human review, so
bounding what a failed run leaves on disk is the point.

The write now uses the bytes validation read. Re-reading the source at
write time leaves a window that the restructure would have widened,
since every other schema is validated in between."
```

---

## Task 3: The publish pipeline

**Files:**
- Modify: `tools/render_landing.py`, `tools/verify_published.py`, `.github/workflows/deploy-pages.yml`
- Create: `tests/test_verify_published.py`
- Test: `tests/test_render_landing.py`

**Interfaces:**
- Consumes: `publish_schemas.load_schemas`, `target_for`, `SchemaError`.
- Produces: `_version_key(version: str) -> tuple[int, ...]`, `_schema_facts(source: Path) -> tuple[str, int]`.

- [ ] **Step 1: Write the failing tests for the renderer**

Add to `tests/test_render_landing.py`:

```python
def test_version_selection_is_shared_between_both_callers(spec_tree):
    """The numeric comparison exists to stop v0.10.0 sorting below v0.2.0.

    Two independent copies of it would let a future change land in one and not the
    other, and the only multi-version test calls spec_version directly rather than
    going through render.
    """
    import render_landing

    assert render_landing._version_key("v0.10.0") > render_landing._version_key("v0.2.0")
    facts_version, _count = render_landing._schema_facts(spec_tree)
    assert facts_version == render_landing.spec_version(spec_tree)


def test_schema_facts_loads_the_tree_once(spec_tree, monkeypatch):
    import render_landing

    calls = []
    original = render_landing.load_schemas
    monkeypatch.setattr(render_landing, "load_schemas",
                        lambda source: (calls.append(source), original(source))[1])
    render_landing._schema_facts(spec_tree)
    assert len(calls) == 1, f"expected one load, got {len(calls)}"


def test_main_reports_a_copy_failure_without_a_traceback(tmp_path, capsys):
    """copytree sat outside the error boundary, so an unreadable assets directory
    produced a traceback rather than the module's diagnostic."""
    import render_landing

    landing = tmp_path / "landing"
    (landing / "assets").mkdir(parents=True)
    (landing / "index.html").write_text("<!--ACS:STARBURST-->", encoding="utf-8")
    (landing / "assets" / "starburst.svg").write_text("<svg/>", encoding="utf-8")
    assert render_landing.main(["x", str(landing), str(tmp_path / "out")]) == 1
    assert "error:" in capsys.readouterr().err
```

- [ ] **Step 2: Run and watch them fail**

Run: `uv run pytest tests/test_render_landing.py -k "version_selection or loads_the_tree or copy_failure" -q`
Expected: FAIL with `AttributeError: module 'render_landing' has no attribute '_version_key'`.

- [ ] **Step 3: Implement the renderer changes**

In `tools/render_landing.py`, add above `spec_version`:

```python
def _version_key(version: str) -> tuple[int, ...]:
    """Order versions numerically, so v0.10.0 sorts above v0.2.0 rather than below."""
    return tuple(int(part) for part in version.lstrip("v").split("."))


def _schema_facts(source: Path) -> tuple[str, int]:
    """Return the highest spec version and the schema count from a single load."""
    try:
        docs = load_schemas(source)
    except SchemaError as error:
        raise RenderError(str(error)) from error
    if not docs:
        raise RenderError(f"no schemas found under {source}")
    versions = {target_for(doc, path).split("/")[0] for path, doc in docs.items()}
    return max(versions, key=_version_key), len(docs)
```

Replace the body of `spec_version` so it shares the comparison:

```python
    versions = _versions(source)
    if not versions:
        raise RenderError(f"no schemas found under {source}")
    return max(versions, key=_version_key)
```

In `render`, replace the two separate calls with one:

```python
    version, count = _schema_facts(source)
    out = template.replace("<!--ACS:SPEC_VERSION-->", html.escape(version))
    out = out.replace("<!--ACS:SCHEMA_COUNT-->", str(count))
```

In `main`, move the output phase inside the error boundary and give the copy its own message:

```python
    try:
        page = render(
            (landing / "index.html").read_text(encoding="utf-8"),
            repo / "specification",
            (repo / "GOVERNANCE.md").read_text(encoding="utf-8"),
            (landing / "assets" / "starburst.svg").read_text(encoding="utf-8"),
        )
        out.mkdir(parents=True, exist_ok=True)
        (out / "index.html").write_text(page, encoding="utf-8")
        shutil.copytree(landing / "assets", out / "assets", dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns("starburst.svg"))
    except (RenderError, SchemaError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        # shutil.Error subclasses OSError, so a copy failure lands here too. The
        # message names the whole output phase rather than only the read half.
        print(f"error: cannot read a source or write the output: {error}", file=sys.stderr)
        return 1
```

- [ ] **Step 4: Write the verifier tests**

Create `tests/test_verify_published.py`. The module had no coverage at all, so these are its first:

```python
"""Tests for the post-deploy verifier.

The module had no test file, so its retry loop and parsing guards shipped unverified.
Fetching is stubbed rather than served, so the suite stays fast.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import verify_published as vp


@pytest.fixture(autouse=True)
def no_sleeping(monkeypatch):
    slept = []
    monkeypatch.setattr(vp.time, "sleep", lambda seconds: slept.append(seconds))
    return slept


def test_a_document_serving_its_own_id_passes(monkeypatch, capsys):
    url = "https://example.org/schema/v0.1.0/a.json"
    monkeypatch.setattr(vp, "fetch", lambda u: {"$id": u})
    vp.check("https://example.org/", "schema/v0.1.0/a.json")
    assert "ok:" in capsys.readouterr().out


def test_a_mismatched_id_fails_immediately(monkeypatch, no_sleeping):
    monkeypatch.setattr(vp, "fetch", lambda u: {"$id": "https://example.org/other.json"})
    with pytest.raises(SystemExit, match="serves"):
        vp.check("https://example.org/", "schema/v0.1.0/a.json")
    assert no_sleeping == [], "a wrong document is not a propagation delay"


def test_a_non_object_body_reports_what_was_served(monkeypatch):
    """A JSON array parses but has no $id. Reading .get on it raised AttributeError."""
    monkeypatch.setattr(vp, "fetch", lambda u: ["not", "an", "object"])
    with pytest.raises(SystemExit, match="not a JSON object"):
        vp.check("https://example.org/", "schema/v0.1.0/a.json")


def test_a_decoding_failure_is_retried(monkeypatch, no_sleeping):
    def boom(url):
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

    monkeypatch.setattr(vp, "fetch", boom)
    with pytest.raises(SystemExit):
        vp.check("https://example.org/", "schema/v0.1.0/a.json")
    assert len(no_sleeping) == vp.ATTEMPTS - 1, "the final attempt must not sleep"


def test_the_base_url_is_normalized(monkeypatch, capsys):
    seen = []
    monkeypatch.setattr(vp, "fetch", lambda u: (seen.append(u), {"$id": u})[1])
    vp.check("https://example.org", "schema/a.json")
    assert seen == ["https://example.org/schema/a.json"]
```

- [ ] **Step 5: Run them and watch them fail**

Run: `uv run pytest tests/test_verify_published.py -q`
Expected: FAIL. `test_a_non_object_body_reports_what_was_served` raises `AttributeError`, and `test_a_decoding_failure_is_retried` fails because `UnicodeDecodeError` is uncaught and the final attempt sleeps.

- [ ] **Step 6: Implement the verifier changes**

In `tools/verify_published.py`, replace the body of `check`:

```python
def check(base: str, path: str) -> None:
    url = f"{base.rstrip('/')}/{path}"
    last: Exception | None = None
    for attempt in range(1, ATTEMPTS + 1):
        try:
            doc = fetch(url)
        except (urllib.error.URLError, json.JSONDecodeError, UnicodeDecodeError) as error:
            last = error
            print(f"attempt {attempt}/{ATTEMPTS}: {url} not ready ({error})")
            # The last attempt has nothing left to wait for.
            if attempt < ATTEMPTS:
                time.sleep(DELAY_SECONDS)
            continue
        if not isinstance(doc, dict):
            # It parsed and it is wrong. Retrying cannot help, and calling this
            # unavailable would send an operator looking at DNS.
            raise SystemExit(f"::error::{url} is not a JSON object: {type(doc).__name__}")
        served = doc.get("$id")
        if served != url:
            raise SystemExit(f"::error::{url} serves $id {served!r}, expected its own URL")
        print(f"ok: {url} serves its own $id")
        return
    raise SystemExit(f"::error::{url} never became available: {last}")
```

- [ ] **Step 7: Gate the two workflow steps**

In `.github/workflows/deploy-pages.yml`, change the `if:` on the Configure Pages step and on the Upload the artifact step from `if: github.event_name != 'pull_request'` to:

```yaml
        if: github.event_name != 'pull_request' && github.ref == 'refs/heads/main'
```

- [ ] **Step 8: Run everything**

Run: `uv run pytest -q`
Expected: PASS.

Run: `uv run python -c "import yaml, pathlib; yaml.safe_load(pathlib.Path('.github/workflows/deploy-pages.yml').read_text()); print('parses')"`
Expected: `parses`.

- [ ] **Step 9: Commit**

```bash
git add tools/render_landing.py tools/verify_published.py tests/test_render_landing.py tests/test_verify_published.py .github/workflows/deploy-pages.yml
git commit -m "Share the version comparison, and give the verifier its first tests

The numeric version comparison exists to stop v0.10.0 sorting below
v0.2.0. Loading the schemas once for the page would have duplicated that
comparison, so both callers now share one function.

The renderer's output phase moves inside the error boundary. A copy
failure previously escaped as a traceback, and the message now names the
whole phase rather than only the read half.

The verifier had no test file, so its retry loop and parsing guards
shipped unverified. It now retries a decoding failure, reports a body
that parses but is not an object rather than raising AttributeError, and
stops sleeping after the final attempt, which bought nothing.

Gating the artifact steps on the branch stops a dispatch from a feature
branch uploading something no deploy consumes. It does not reduce fork
pull request exposure, because publishing runs on every pull request by
design, which is what makes the pre-merge build a gate."
```

---

## Task 4: Widen the guard to its class

The guard has been found incomplete four times. Each previous fix corrected the instance.

**Files:**
- Modify: `tests/conftest.py`, `tests/test_site_config.py`, `tests/test_landing_page.py`, `tests/test_docs_theme.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `third_party_hosts(text, self_hosts) -> set[str]`, unchanged signature. `VENDORED_PREFIXES: tuple[str, ...]`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_site_config.py`:

```python
def test_the_guard_catches_every_fetch_triggering_attribute():
    """The recurring failure has been attribute coverage, not quoting style.

    Measured before this fix: a video poster pointing at a third party passed the
    guard undetected, as did background, formaction, and cite.
    """
    from conftest import third_party_hosts

    for markup in [
        '<video poster="//evil.tld/a.jpg"></video>',
        '<body background="//evil.tld/b.png">',
        '<img srcset="//evil.tld/e.png 2x">',
        '<script src=//evil.tld/f.js></script>',
        '<link rel="stylesheet" href="//evil.tld/g.css">',
        '<object data="//evil.tld/h.swf">',
        '<iframe src="https://evil.tld/j"></iframe>',
    ]:
        assert third_party_hosts(markup, set()) == {"evil.tld"}, markup

    # A prose citation is navigation, not a fetch. Counting it is the defect that
    # forced hosts onto an allowlist the last time this guard was widened.
    for prose in [
        '<a href="https://github.com/x">link</a>',
        '<a href="https://www.jpmorgan.com/y">citation</a>',
        '<blockquote cite="https://example.org/z">quote</blockquote>',
    ]:
        assert third_party_hosts(prose, set()) == set(), prose


def test_the_site_ships_no_first_party_javascript(built_site):
    """Every script in the built site comes from the pinned theme.

    Scanning vendored bundles for hostnames produces findings nobody can action, so
    the guard asserts the property that matters instead: nothing of ours is a script.
    """
    from conftest import VENDORED_SEGMENT

    stray = [
        p.relative_to(built_site).as_posix()
        for p in built_site.rglob("*.js")
        if VENDORED_SEGMENT not in p.relative_to(built_site).as_posix()
    ]
    assert not stray, f"first-party JavaScript entered the site: {stray}"
```

- [ ] **Step 2: Run and watch them fail**

Run: `uv run pytest tests/test_site_config.py -k "fetch_triggering or first_party_javascript" -q`
Expected: FAIL. The attribute test fails on the first case, because `poster` is not in the pattern. The JavaScript test fails on `ImportError` for `VENDORED_PREFIXES`.

- [ ] **Step 3: Widen the shared patterns**

In `tests/conftest.py`, replace `RESOURCE_TAG` and add the prefixes:

```python
# Anchor links are prose and fetch nothing, which is why the tag list stays. The
# recurring gap has been attribute coverage rather than quoting style, so these name
# every attribute that causes a passive fetch on a tag where it does one.
#
# href is separated because it fetches on link and navigates on a. Folding them
# together reintroduces the defect where a prose citation counted as an asset load.
# cite, longdesc, and formaction are deliberately absent: browsers do not fetch the
# first two, and the third is a submission target rather than a passive load.
RESOURCE_TAG = re.compile(
    r"""<(?:script|img|iframe|video|audio|source|embed|object|track|input|body|table|td|html)\b[^>]*?"""
    r"""\b(?:src|srcset|poster|data|background|manifest)\s*=\s*['"]?(?:https?:)?//([^\s/'">]+)""",
    re.I,
)
LINK_HREF = re.compile(
    r"""<link\b[^>]*?\bhref\s*=\s*['"]?(?:https?:)?//([^\s/'">]+)""",
    re.I,
)

# Scripts under this path come from the installed theme and are pinned by uv.lock.
# Their bundles carry attribution URLs that no scan can meaningfully audit, so the
# guard asserts that nothing outside them is a script rather than reading them. The
# match is on the path containing the segment, because the documentation build nests
# its copy under docs/.
VENDORED_SEGMENT = "assets/javascripts/"
```

Add `LINK_HREF` to the union inside `third_party_hosts`:

```python
    hosts |= {m.group(1) for m in LINK_HREF.finditer(text)}
```

- [ ] **Step 4: Run and confirm they pass**

Run: `uv run pytest tests/test_site_config.py -q`
Expected: PASS.

- [ ] **Step 5: Give the docs guard the same coverage as its sibling**

In `tests/test_docs_theme.py`, the page loop at `test_docs_do_not_call_the_github_api_at_runtime` scans `*.html` only. Add a stylesheet pass to the origin guard there so the two files cannot drift:

```python
def test_the_docs_stylesheet_loads_no_third_party_resource(built_docs):
    """The theme stylesheet is generated from our tokens and reaches every page."""
    from conftest import third_party_hosts

    hosts: set[str] = set()
    for sheet in (built_docs / "stylesheets").rglob("*.css"):
        hosts |= third_party_hosts(sheet.read_text(encoding="utf-8"), set())
    assert not hosts, f"third-party resource loads in the docs stylesheet: {hosts}"
```

- [ ] **Step 6: Report every affected page, not the first**

In `tests/test_site_config.py`, change the offender collection in `test_built_site_loads_no_third_party_resource` from `offenders.setdefault(host, asset.name)` to accumulate:

```python
    offenders: dict[str, list[str]] = {}
    for asset in list(built_site.rglob("*.html")) + list(built_site.rglob("*.css")):
        for host in third_party_hosts(asset.read_text(encoding="utf-8"), SELF_HOSTS):
            offenders.setdefault(host, []).append(asset.name)
    assert not offenders, f"third-party resource loads: {offenders}"
```

- [ ] **Step 7: Strengthen the anchor and starburst assertions**

In `tests/test_render_landing.py`, replace `test_render_workstreams_drops_a_javascript_scheme` body:

```python
def test_render_workstreams_drops_a_javascript_scheme():
    """Asserting the substring is absent passes for code that emits an anchor with
    no href. The element must not appear at all."""
    html = render_workstreams([("X", "[@x](javascript:alert(1))")])
    assert "javascript:" not in html
    assert "<a" not in html
    assert "@x" in html
```

In `tests/test_landing_page.py`, replace the starburst font assertion so it names the element:

```python
def test_the_starburst_sets_its_font_on_the_root_element():
    """A count of one is satisfied by a declaration on the wrong element."""
    svg = (LANDING / "assets" / "starburst.svg").read_text(encoding="utf-8")
    root = svg[svg.index("<svg"): svg.index(">", svg.index("<svg")) + 1]
    assert "font-family" in root
    assert svg.count("font-family") == 1
```

- [ ] **Step 8: Prove the guard bites, then revert**

```bash
cp docs/stylesheets/extra.css /tmp/x.bak
printf '\n.z { background-image: url("https://evil.tld/x.png"); }\n' >> docs/stylesheets/extra.css
uv run pytest -q; echo "^ must FAIL"
cp /tmp/x.bak docs/stylesheets/extra.css
uv run pytest -q; echo "^ must PASS"
git diff --stat docs/stylesheets/extra.css
```

Expected: a failure with the injection present, a pass after reverting, and an empty diff. Put both results in your report.

- [ ] **Step 9: Commit**

```bash
git add tests/
git commit -m "Widen the third-party guard to its class

This guard has been found incomplete four times. It allowlisted hosts,
then covered one file of two, then read markup but not stylesheets. Each
fix corrected the instance.

Attribute coverage was the recurring gap rather than quoting style, so
the pattern now names every attribute a browser fetches from. Measured
before the fix: a video poster pointing at a third party passed
undetected, as did background, formaction, and cite.

Scanning JavaScript was considered and rejected on measurement. The
build emits roughly twenty vendored files whose attribution URLs no scan
can action. The guard asserts the property that matters instead, which
is that the site ships no first-party script, so anything of ours
entering that surface fails and gets a human decision."
```

---

## Task 5: Documents, ownership, and tracking

**Files:**
- Modify: `landing/assets/starburst.svg`, `SECURITY.md`, `CLAUDE.md`, `LICENSING.md`, `.github/CODEOWNERS`, `tools/publish_schemas.py`
- Test: `tests/test_publish_schemas.py`, `tests/test_landing_page.py`

**Interfaces:**
- Consumes: the starburst assertion from Task 4.
- Produces: nothing.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_publish_schemas.py`:

```python
@pytest.mark.parametrize("tail", ["v0.1.0/%2e%2e/x.json", "v0.1.0/a%41.json", "v0.1.0/..%2fx.json"])
def test_both_path_checks_reject_percent_encoding(tail):
    """The decode check is redundant with SAFE_TAIL today, and that is a fact about
    today's pattern rather than an enforced invariant. If SAFE_TAIL is ever loosened
    to admit a percent sign, this fails rather than silently promoting the decode
    check to load-bearing."""
    from publish_schemas import SAFE_TAIL
    from urllib.parse import unquote

    assert not SAFE_TAIL.match(tail), "SAFE_TAIL must reject percent-encoding on its own"
    assert unquote(tail) != tail, "the decode check must also reject it"
```

Add to `tests/test_landing_page.py`:

```python
def test_security_policy_does_not_hedge_on_a_live_site():
    """The site is live, so a conditional about enabling Pages reads as out of scope."""
    assert "once Pages is enabled" not in (REPO / "SECURITY.md").read_text(encoding="utf-8")


def test_claude_md_is_owned_by_the_restricted_tier():
    """It instructs AI agents operating in this repository, which is the same class of
    control surface as the workflows."""
    owners = (REPO / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
    assert "/CLAUDE.md" in owners
```

- [ ] **Step 2: Run and watch them fail**

Run: `uv run pytest tests/test_landing_page.py -k "security_policy or claude_md" -q`
Expected: FAIL on both.

- [ ] **Step 3: Set the starburst font once on the root**

In `landing/assets/starburst.svg`, add the stack to the opening `<svg>` tag:

```
     font-family="Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"
```

Then remove all fifteen `font-family="Inter, sans-serif"` attributes from the `<text>` elements. Verified in a browser engine that a `<text>` inside a `<g>` inherits the root value.

- [ ] **Step 4: Correct the documents**

`SECURITY.md`: merge the two overlapping in-scope rows into one naming the build and publish tooling including the workflows, and remove `once Pages is enabled` from the row describing the published site.

`CLAUDE.md`: replace `The landing page links both, so publishing an address does not pull reports out of the processes that handle them independently.` with:

```markdown
The landing page links the security reporting process and the Code of Conduct process,
so publishing an address does not pull reports out of either.
```

`LICENSING.md`: move the `## Provenance of the landing page design` section so it sits directly after the scope table it explains, before `## Contributing`.

`.github/CODEOWNERS`: add to the restricted block, beside the other root documents:

```
/CLAUDE.md      @rocklambros @fewdisc @GangGreenTemperTatum @mamicidal @sclintonowasp
```

- [ ] **Step 5: Add the closure comment**

In `tools/publish_schemas.py`, extend the docstring line in `target_for` that mentions the decode check:

```python
    The decode check is redundant with SAFE_TAIL, which admits no percent sign in any
    character class. It stays because it names the attempt: a percent-encoded traversal
    reports as such rather than as a generic pattern failure, which is the difference
    between a build log saying someone tried something and one saying someone typoed.
```

- [ ] **Step 6: Run the suite and rebuild**

```bash
uv run pytest -q
rm -rf _site
GITHUB_PAGES_URL="https://genai-security-project.github.io/agent-control-standard/docs/" uv run mkdocs build --strict -d _site/docs
uv run python tools/render_landing.py landing _site
uv run python tools/publish_schemas.py specification _site/schema
grep -c 'font-family' _site/index.html
```

Expected: the suite passes, the build succeeds, and the rendered page carries exactly one `font-family` from the inlined diagram.

- [ ] **Step 7: Commit**

```bash
git add landing/assets/starburst.svg SECURITY.md CLAUDE.md LICENSING.md .github/CODEOWNERS tools/publish_schemas.py tests/
git commit -m "Correct the documents and own the file that instructs agents

The security policy described the published site as in scope once Pages
is enabled. It went live, so a researcher read a conditional about a
running property and a defensive reading could argue it was excluded.

CLAUDE.md instructs AI coding agents operating in this repository, which
is the same class of control surface as the workflows, and it was the
one root document absent from the restricted owner list.

The diagram sets its font once on the root element and inherits it,
rather than repeating a shorter fallback on fifteen text elements.

The percent-decode check gains the reasoning for keeping it. It is
redundant with the pattern today, and it stays because it names the
attempt rather than reporting a generic failure."
```

---

## Task 6: Track what is not being fixed

**Files:** none.

- [ ] **Step 1: Open the tracking issue**

This is an outward-facing action on a public repository. Confirm with the project lead before running it.

```bash
gh issue create --title "Publish a schema.lock so consumers can detect content drift" --body "$(cat <<'BODY'
Published schemas are mutable in place. A constraint loosened under a released spec version reaches every consumer resolving that `$id` with no record they can check against a previously fetched copy.

This has now been deferred twice. The first deferral is recorded in `design/plans/2026-09-05-github-pages-site.md` as finding F21, described there as the highest-value follow-up. The second is in `design/2026-09-05-deferred-findings-design.md` under Out of scope. Neither is a tracked item, which is how a highest-value item disappears.

Shape of the change:

- `specification/schema.lock` carrying a sha256 per `$id`
- The build fails when a hash under an already-released spec version changes without a matching lockfile update in the same commit
- The lock publishes alongside the schemas so consumers can pin content rather than location

Related and worth folding in, since both are about detecting drift in published content and both touch the same two workflow files:

- Post-deploy verification checks 2 of 44 published URIs, hardcoded identically in `deploy-pages.yml` and `monitor-pages.yml` with nothing keeping them in sync or tracking schema additions.
BODY
)"
```

- [ ] **Step 2: Record the issue number**

Add the issue reference to the Out of scope section of `design/2026-09-05-deferred-findings-design.md`, replacing `A tracking issue is in scope` with `Tracked as #<number>`.

- [ ] **Step 3: Commit**

```bash
git add design/2026-09-05-deferred-findings-design.md
git commit -m "Point the deferral at its tracking issue

Two deferrals recorded only in prose inside dated design files is how a
highest-value item stops being work and becomes archaeology."
```

---

## Self-Review

**Spec coverage.** All twenty findings map to a task: 2 to Task 1; 1 to Task 2; 4, 5, 6, 7, 8, 19 to Task 3; 9, 10, 11 to Task 4; 3, 12, 13, 14, 15, 16, 17 to Task 5; 18 and 20 to Task 6. Finding 3 closes with its comment in Task 5 Step 5 and its drift test in Task 5 Step 1, which is the work version 1.0 promised and never specified.

**Placeholder scan.** No TBD, no "similar to Task N", no "add appropriate error handling". Every code step carries the code.

**Type consistency.** `_version_key` and `_schema_facts` are defined in Task 3 and referenced only there and in its tests. `VENDORED_PREFIXES` is defined in Task 4 Step 3 and consumed in Task 4 Step 1, which reads out of order, so Step 2 states the expected `ImportError` explicitly. `third_party_hosts` keeps its signature throughout. `publish` and `verify_refs` keep theirs.

**One deviation from the spec, recorded.** The spec's C4 called for scanning every text asset. Measurement while writing this plan showed that a `*.js` scan hits roughly twenty vendored files carrying attribution URLs, so the spec was corrected in the same change to assert that the site ships no first-party script instead. That is narrower and honest about what it checks.

**Known gap, deliberately out of scope.** Findings 18 and 20 are tracked rather than fixed, and Task 6 needs the project lead's approval before it runs, because opening a public issue is outward-facing.
