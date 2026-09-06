# Closing the deferred findings from the Pages branch

Version: 2.0
Owner: ACS project lead
Date: 2026-09-05
Status: approved design, not yet implemented

Version 1.0 went through a six-perspective adversarial premortem and did not survive. Its central judgment was wrong: it closed one finding as "already correct" when the code is defective, and a draft schema in a directory named `Proposals` publishes to the live normative namespace. Two further claims in it were factually false. This revision reopens that finding, corrects the false claims, and widens the scope the premortem showed was too narrow.

## Goal

Close the findings carried from the Pages branch reviews, plus the findings the premortem of version 1.0 raised against the plan to close them.

The site is live and serving 44 schemas that external tools fetch. Nothing here changes what it publishes. Every change either removes a way the tooling can fail silently, widens a guard that has now been found incomplete four times, or corrects a document that is false.

## What changed from version 1.0

| Was | Now |
|---|---|
| Finding 2 closed as already correct | **Reopened as a real defect.** `NON_NORMATIVE` is exact-match and case-sensitive |
| Finding 3 closed because "no single layer is load-bearing" | Still closed, but for the correct reason. The old reasoning was false |
| "A dangling `$ref` leaves a partially populated directory" | False. It writes every file. Partial output comes from `$id` validation failures |
| C1 framed as removing a live-site failure window | Reframed. The window was already inert. The real benefit is bounding what a fork pull request leaves on a runner |
| C3 widened the guard to `srcset` and unquoted values | Widened to the **class**: every built asset, and every fetch-triggering attribute |
| Two closures "gain a comment" | Now an explicit step in a named commit, because version 1.0 promised it and specified no work |

## The defect version 1.0 missed

`target_for` refuses the normative namespace to any file under a directory named `proposals`:

```python
NON_NORMATIVE = ("proposals",)
if any(part in NON_NORMATIVE for part in path.parts):
```

That is exact string equality against one lowercase literal. Measured against the real code:

| Directory | Outcome |
|---|---|
| `proposals/` | refused |
| `Proposals/` | **publishes to the normative namespace** |
| `PROPOSALS/` | **publishes** |
| `proposal/` | **publishes** |
| `drafts/` | **publishes** |

A draft schema reaching `/schema/v0.1.0/` is fetched by every external tool resolving that `$id`, and nothing detects it: the post-deploy check inspects two of the 44 published paths.

Version 1.0 declined a reviewer's recommendation to tighten this to a top-level match, arguing the loose match "fails safe." Both that recommendation and that objection argued about **depth**. The defect is **string equality**. The disagreement was on the wrong axis.

## Findings and disposition

| # | Where | Disposition |
|---|---|---|
| 1 | `publish_schemas.py` partial output | Fix, with the rationale corrected. See C1 |
| 2 | `NON_NORMATIVE` matching | **Fix.** Reopened, see above |
| 3 | percent-decode redundancy | Close, with corrected reasoning and a drift test |
| 4 | `render_landing.py` error boundary | Fix |
| 5 | `render_landing.py` double load | Fix, with a shared version helper mandated |
| 6 | `verify_published.py` exception handling | Fix |
| 7 | `verify_published.py` final sleep | Fix |
| 8 | workflow artifact on dispatch | Fix, with its limits stated |
| 9 | `javascript:` test strength | Fix |
| 10 | guard attribute and file coverage | Fix, as a class |
| 11 | offender diagnostics | Fix |
| 12 | starburst font fallback | Fix |
| 13 | `CLAUDE.md` ambiguous sentence | Fix |
| 14 | `LICENSING.md` section placement | Fix |
| 15 | `SECURITY.md` duplicate row | Fix |
| 16 | `SECURITY.md` says "once Pages is enabled" on a live site | **New.** Fix |
| 17 | `CLAUDE.md` absent from the restricted CODEOWNERS tier | **New.** Fix |
| 18 | Post-deploy verification covers 2 of 44 URIs, duplicated across two workflows | **New.** Fix |
| 19 | `verify_published.py` has no test file at all | **New.** Fix |
| 20 | `schema.lock` deferred twice with no durable tracking | **New.** Track, do not implement |

## One finding still closes

**Finding 3, the percent-decode check.** `SAFE_TAIL` admits `%` in no character class, so any percent-encoded input is rejected by the pattern regardless of the decode comparison. Version 1.0 defended keeping the check by claiming "no single layer is load-bearing." That is false: for this input class exactly one layer is load-bearing, and it is `SAFE_TAIL`.

The check stays for a different and correct reason. It turns a percent-encoded traversal attempt into a distinctly labelled error, `$id must not be percent-encoded`, rather than a generic pattern failure. That distinction is what tells an operator reading a CI log that someone tried something, rather than that someone made a typo. Intent signal in a build log is worth three lines of code.

The redundancy is a fact about today's `SAFE_TAIL`, not an enforced invariant. A test asserts both checks reject the same input set, so loosening `SAFE_TAIL` later fails loudly instead of silently promoting the decode check to load-bearing.

No claim in this document attributes reasoning to an unnamed reviewer. Version 1.0 did, and the attribution could not be verified from the repository, which makes it an appeal to authority rather than an argument.

## Design

Five commits, each one coherent idea with its own tests.

### C1: validate everything, then write validated bytes

Two defects, one restructure.

**The stated cause in version 1.0 was wrong.** Measured: a dangling `$ref` writes all 44 files before raising, because `verify_refs` runs after the loop. A partially populated directory comes from a `target_for` failure, which raises mid-loop, and produces 43 of 44.

**The stated benefit was also wrong.** The build job runs `publish_schemas.py` before `upload-pages-artifact`, with no `continue-on-error`. A failure stops the job, the artifact never uploads, and Pages keeps serving the last good deployment. The partial directory never reached the live site under either ordering.

The real benefit is narrower and worth stating accurately: the module's own docstring records that "a fork pull request reaches this code on the runner before human review." Verifying before writing bounds what a hostile pull request's build step leaves on disk. That is the threat model this serves.

Restructure `publish()` into three phases:

1. For every schema, resolve `rel`, `sid`, and the contained destination. Detect duplicate `$id`. Read the file's bytes. Build the `$id` map.
2. Run `verify_refs`.
3. Create directories and write the bytes read in phase 1.

Phase 3 writes the bytes phase 1 validated, rather than re-reading the source. Version 1.0 specified `shutil.copyfile`, which re-reads at copy time and opens a window between validation and write that the restructure makes wider, since all of phases 1 and 2 now sit between reading a file and writing it. Holding the bytes closes it.

No `mkdir` happens before phase 3. On failure the output directory does not exist at all, so the test asserts absence rather than emptiness. Version 1.0 said "empty," which a reasonable implementation satisfies while leaving empty directories behind.

### C2: normalize the non-normative check

Replace exact matching with a normalized comparison, and treat the directory name as a prefix family rather than one literal:

```python
# Draft schemas must never claim a normative URI. The comparison is case-folded
# because a directory named Proposals is the same intent as proposals, and a
# path-based safety check that is not normalized is incomplete rather than strict.
NON_NORMATIVE = ("proposals", "proposal", "drafts", "draft", "wip", "experimental")
...
if any(part.casefold() in NON_NORMATIVE for part in path.parts):
```

The name list is the part a future contributor will forget to extend, so the failure has to be loud where it matters. A test asserts every name in the list is refused at top level and nested, in three casings.

This does not make the check complete. A contributor inventing a seventh convention still bypasses it. The durable fix is inverting the rule so that only files under a versioned directory may claim the namespace, which `SAFE_TAIL` already half-enforces on the `$id` side. Record that as the follow-up rather than pretending the name list closes the class.

### C3: the publish pipeline

**`render_landing.py`.** Move `shutil.copytree` inside the existing `try`. Verified: `shutil.Error` subclasses `OSError`, so the existing clause catches it. Give the copy its own `except` with a message naming a copy failure, because reusing "cannot read a landing page source" points a reader at the wrong half of the operation. Move `out.mkdir` and the `index.html` write inside the same boundary, so the whole output phase is covered rather than one statement of it.

Add `_version_key(version)` as a shared pure function, and have both `_versions`-derived selection and `_schema_facts` call it. Version 1.0 specified `_schema_facts` without requiring the algorithm be shared, which forces the numeric-tuple comparison to exist twice. That comparison exists specifically to stop `v0.10.0` sorting below `v0.2.0`, and a divergence between two copies would ship a wrong version string to the live page with no test to catch it, because the only multi-version test calls `spec_version` directly and never goes through `render`.

**`verify_published.py`.** Widen the retry clause to `UnicodeDecodeError`. Guard that the parsed body is a mapping before reading `$id`. Skip the sleep after the final attempt. Distinguish the diagnostics: a body that parses but is wrong reports what was served, rather than "never became available," which sends an operator looking at DNS during an encoding problem.

**`deploy-pages.yml`.** Gate `configure-pages` and `upload-pages-artifact` on `github.ref == 'refs/heads/main'` as well as the event.

State the limit plainly in the commit message: this closes a wasted upload on a dispatch from a branch. It does not reduce fork pull request exposure, because `Publish the schemas` carries no condition and runs on every pull request by design, which is what makes the pre-merge build a gate at all.

### C4: fix the guard's class, not its fourth instance

The no-third-party guard has now been found incomplete four times. Each previous fix corrected the instance: allowlisting hosts, then one file of two, then HTML but not stylesheets. Each left the same structural gap, which is that the guard's scope is a hardcoded list rather than the build output.

Two dimensions widen together.

**File coverage.** Scan every text asset the build emits, not `*.html` and `*.css`. Measured: no test globs `*.js`, and the shipped Material bundle contains the literal strings `https://api.github.com`, `https://unpkg.com`, and `https://clipboardjs.com`. The `api.github.com` hook is absent from the built pages, confirmed, so those strings are most likely inert attribution banners and inactive fallbacks. The finding is not that the site leaks. It is that no guard could tell us either way.

Vendored third-party bundles will contain such strings legitimately, so a bare scan of `*.js` fails immediately on Material's own bundle. The guard therefore separates first-party output from vendored assets: files the build generates are scanned strictly, and vendored bundle paths are recorded in an explicit, commented exception list. An exception list that names three files and explains why is a control. An extension allowlist that silently skips a whole language is not.

**Attribute coverage.** Add the fetch-triggering attributes the pattern misses regardless of quoting: `poster`, `background`, `formaction`, `cite`, `longdesc`, `manifest`, and `srcset`, plus unquoted values. Measured: `<video poster="//evil.example/beacon.jpg">` passes the current guard undetected. The recurring failure category is attribute-name coverage, so a mutation test that only injects `srcset` would miss the fifth instance the same way.

**`test_docs_theme.py`** also globs `*.html` and gets the same treatment, so the two do not drift.

### C5: documents, ownership, and tracking

**`SECURITY.md`.** Merge the two overlapping in-scope rows. Separately, remove "once Pages is enabled" from the row describing the published site. The site went live today, so a researcher currently reads a conditional about a live property, and a defensive reading could argue it was out of scope.

**`CLAUDE.md`.** Give "The landing page links both" an explicit subject naming the security reporting process and the Code of Conduct process. Version 1.0 specified the fix without showing the resulting text, which left an implementer free to resolve the ambiguity differently than intended.

**`.github/CODEOWNERS`.** Add `/CLAUDE.md` to the restricted tier. Every other root governance document the branch touched is there. `CLAUDE.md` is not, so it falls to the twelve-handle default, three of whom are recorded as inert pending acceptance. The file instructs AI coding agents operating in this repository, which makes it a control surface of the same class as the workflows.

**`LICENSING.md`.** Move the provenance section to sit after the scope table it explains.

**`landing/assets/starburst.svg`.** Declare `font-family` once on the root element with the same stack `--acs-font` uses, and remove the fifteen per-element declarations. Verified in a real browser engine that a `<text>` inside a `<g>` inherits it.

**Add the closure comments.** Version 1.0 promised both closed findings would gain a comment recording why they stand, then specified no commit containing that work. The comment on the percent-decode check lands here, carrying the corrected reasoning.

**Open a tracking issue for `specification/schema.lock`.** It has now been deferred twice, and the record lives only in prose inside two dated design files. Zero issues reference it. Published schemas remain mutable in place with no hash record, so a loosened constraint under a released spec version reaches consumers silently. Implementation stays out of scope. The tracking does not.

## Testing

Every code change in C1 through C4 gets a test that fails before the fix. Three carry more weight than the rest.

**The non-normative test is a matrix, not a case.** Every name in `NON_NORMATIVE`, at top level and nested, in lower, title, and upper casing. The defect this closes was invisible precisely because the one existing test used a single name at a single depth in a single casing.

**The guard gets a mutation check across both dimensions.** Inject a third-party host through `poster`, through `srcset`, through an unquoted `src`, and through a `url()` in a stylesheet, and confirm each fails. Then revert. This guard has been incomplete four times, so it is verified by watching it fail rather than by reading the regex.

**`tests/test_verify_published.py` is a new file.** The module has no test coverage at all today, so version 1.0's claim that every change gets a test was unmeetable for three of its own changes. The retry loop is tested with a stubbed fetch rather than a live server, so it runs in milliseconds.

Two weaker assertions from version 1.0 are strengthened. The C1 test asserts the output directory does not exist, not that it is empty. The starburst test asserts `font-family` appears on the root `<svg>` element specifically, not that it appears once, because a single declaration on the wrong element satisfies a count.

## Verification

The full suite, a clean rebuild of all three surfaces, and a re-run of the live schema check against the published site to confirm nothing regressed for consumers already fetching those URIs.

## Out of scope, with reasons

**`specification/schema.lock`.** Implementation is a separate change with release-process implications this one does not carry. A tracking issue is in scope, because two deferrals with no durable record is how a highest-value item disappears.

**Inverting the non-normative rule to an allowlist.** C2 makes the current check correct for the names it knows. Making it complete means requiring every publishable schema to live under a versioned source directory, which changes the repository layout contract and deserves its own design.

**Widening post-deploy verification beyond two URIs, and giving the two workflows one source for that path list.** Finding 18 is real: a defect in the other 42 schemas ships undetected. The fix belongs with the `schema.lock` change, because both are about detecting drift in published content, and splitting them means touching the same two workflow files twice.

**Alerting on a failed monitor run.** Nothing pages anyone today. That is a repository settings and notification-routing decision rather than a code change.

**The review process itself.** Three audited pull requests touching restricted paths merged with an administrative bypass and no recorded review. That is a staffing and governance decision for the project lead, recorded here because a premortem found it, not because this change addresses it.
