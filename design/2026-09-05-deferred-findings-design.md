# Closing the deferred findings from the Pages branch

Version: 1.0
Owner: ACS project lead
Date: 2026-09-05
Status: approved design, not yet implemented

## Goal

Close the fifteen findings that the Pages branch reviews raised and deliberately deferred as non-blocking. Thirteen become code, test, or prose changes. Two are re-examined and closed as already correct, with their reasoning recorded so a later reviewer does not raise them again.

The site is live and serving. Nothing here changes what it publishes. Every change either removes a way the tooling can fail, tightens a guard, or corrects a document.

## What the findings are

The Pages branch went through an adversarial premortem, per-task reviews, a whole-branch review, and a re-review. Findings that were real but did not block merge were logged and carried. This closes that list.

| # | Where | Finding |
|---|---|---|
| 1 | `tools/publish_schemas.py` | `verify_refs` runs after every file is copied, so a dangling `$ref` leaves a partially populated output directory |
| 2 | `tools/publish_schemas.py` | `NON_NORMATIVE` matches any path segment named `proposals`, not only the top-level directory |
| 3 | `tools/publish_schemas.py` | The percent-decode check is subsumed by `SAFE_TAIL` |
| 4 | `tools/render_landing.py` | `shutil.copytree` sits outside the error boundary, so an unreadable assets directory produces a traceback |
| 5 | `tools/render_landing.py` | `load_schemas` runs twice per render |
| 6 | `tools/verify_published.py` | Raises `AttributeError` on a 200 whose JSON parses but is not an object, and does not catch `UnicodeDecodeError` |
| 7 | `tools/verify_published.py` | Sleeps after the final attempt before raising |
| 8 | `.github/workflows/deploy-pages.yml` | `configure-pages` and `upload-pages-artifact` run on a `workflow_dispatch` from any branch, uploading an artifact the deploy will skip |
| 9 | `tests/test_render_landing.py` | The `javascript:` test asserts a substring is absent but not that no anchor is emitted |
| 10 | `tests/conftest.py` | `RESOURCE_TAG` does not match `srcset` or unquoted attribute values |
| 11 | `tests/test_site_config.py` | The offender map records only the first page per host |
| 12 | `landing/assets/starburst.svg` | Fifteen text elements hardcode a shorter font fallback than the page's stack |
| 13 | `CLAUDE.md` | "The landing page links both" has an ambiguous subject |
| 14 | `LICENSING.md` | The provenance section sits after License history rather than beside the scope table it explains |
| 15 | `SECURITY.md` | Two in-scope rows overlap, one naming the workflows and one naming the tooling that includes them |

## Two findings close as correct

Both were re-examined rather than accepted from the log. Each gains a comment recording why it stands, so the reasoning survives the next review.

**Finding 3, the percent-decode check.** `SAFE_TAIL` excludes `%` from every character class, so the decode comparison is redundant today. It is redundant on purpose. Removing it makes one regex the only thing between a crafted `$id` and the filesystem, and the point of the three-layer check is that no single layer is load-bearing. The reviewer who raised it said as much, describing it as belt and braces rather than a defect.

**Finding 2, the `NON_NORMATIVE` match.** Matching any path segment named `proposals` is looser than matching the top-level directory. The looseness fails safe: it refuses the normative namespace to anything under a directory of that name, anywhere. Tightening it would permit a nested `proposals/` to publish as normative, which is the outcome the check exists to prevent. The proposed fix makes the code worse.

## Design

Four commits, each one coherent idea with its own tests.

### C1: verify the package before writing any of it

`publish()` currently resolves a path, checks containment, copies the file, and repeats, then calls `verify_refs` once every file is on disk. A dangling `$ref` therefore fails the build with a partially populated output directory.

Restructure into two passes over the same data:

1. Resolve `rel`, `sid`, and the contained destination for every schema. Detect duplicate `$id`. Build the `$id` map.
2. Run `verify_refs`.
3. Copy.

`verify_refs` takes the parsed documents and the `$id` map. It never reads the output tree, so this reordering needs no signature change and no new state.

This removes the window rather than cleaning up after it. The failure mode becomes: nothing is written at all.

### C2: the publish pipeline

**`render_landing.py`.** Move `shutil.copytree` inside the `try` that already catches `OSError`, so an unreadable assets directory produces the module's `error:` line rather than a traceback.

Add an internal `_schema_facts(source)` that loads the schemas once and returns the version and the count together. `render()` calls it. `spec_version` and `schema_count` stay as public wrappers over their own loads, because the tests call them directly and their contract is unchanged.

**`verify_published.py`.** Widen the retry clause to include `UnicodeDecodeError`, and guard that the parsed body is an object before reading `$id`, so a valid-JSON non-object fails with the module's diagnostic instead of `AttributeError`. Skip the sleep on the final attempt.

**`deploy-pages.yml`.** Gate `configure-pages` and `upload-pages-artifact` on `github.ref == 'refs/heads/main'` as well as the event, matching the condition the deploy job already carries. A dispatch from a feature branch stops producing an artifact nothing consumes.

### C3: the guards

**`conftest.py`.** Extend `RESOURCE_TAG` to match `srcset` and unquoted attribute values. The pattern currently requires a quote, so `src=https://host/x.js` passes unseen.

**`test_site_config.py` and `test_landing_page.py`.** Collect every page per offending host rather than the first, so a failure names the whole blast radius.

**`test_render_landing.py`.** Assert the `javascript:` case emits no anchor element at all. The current assertion passes for an implementation that emits `<a>` without an `href`.

### C4: documentation and assets

**`starburst.svg`.** Declare `font-family` once on the root element with the same stack `--acs-font` uses, and remove the fifteen per-element declarations. SVG inherits the property, so the labels fall back through the curated stack rather than straight to a generic sans when Inter is unavailable.

**`SECURITY.md`.** Merge the two overlapping in-scope rows into one that names the build and publish tooling including the workflows.

**`CLAUDE.md`.** Give "The landing page links both" an explicit subject, naming the two reporting processes.

**`LICENSING.md`.** Move the provenance section to sit after the scope table it explains, before License history.

## Testing

Every code change in C1 through C3 gets a test that fails before the fix.

The two that carry the most weight:

- C1's test asserts the output directory is empty after a dangling `$ref`. It fails today, because the directory holds whatever was copied before verification ran.
- C3's widened pattern gets a mutation check rather than only an assertion. Inject `srcset` and unquoted-attribute payloads, confirm the guard catches both, revert. This guard has been incomplete three times across the branch's history, so it is verified by watching it fail rather than by reading the regex.

C4's checkable parts get assertions: `SECURITY.md` names the workflows in exactly one in-scope row, and the starburst declares `font-family` exactly once. The prose changes are reviewed by reading.

## Verification

The whole change is verified by the full suite, a clean rebuild of all three surfaces, and a re-run of the live schema check against the published site to confirm nothing regressed for consumers already fetching those URIs.

## Out of scope

`specification/schema.lock`. Published schemas remain mutable in place with no hash record, so a loosened constraint under a released spec version reaches consumers silently. The whole-branch review called it the highest-value follow-up and a separate change, because it carries release-process implications this one does not.
