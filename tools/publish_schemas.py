#!/usr/bin/env python3
"""Publish JSON schemas to the paths their own $id values declare.

The on-disk layout does not match the URI layout. specification/ACS/acs_schema.json
declares an $id of .../schema/v0.1.0/acs_schema.json, so deriving the destination from
$id avoids a hardcoded special case and lets a new spec version publish untouched.

$id is attacker-influenced input, not trusted identity. Anyone who can land a file under
specification/ controls the string, and a fork pull request reaches this code on the
runner before review. Every path derived from it is validated and contained.
"""
from __future__ import annotations

import json
import re
import shutil
import sys
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import unquote, urldefrag, urljoin

BASE = "https://genai-security-project.github.io/agent-control-standard/schema/"

# A publishable tail: version directory, then nested names, ending in .json.
SAFE_TAIL = re.compile(r"^v[0-9]+(?:\.[0-9]+)*/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_.-]+\.json$")

# Draft schemas live here. They must never publish to a normative URI.
NON_NORMATIVE = ("proposals",)


class SchemaError(Exception):
    """A schema has an unusable $id, an unsafe publish path, or an unresolvable $ref."""


def load_schemas(source: Path) -> dict[Path, dict]:
    """Parse every JSON file under source that declares an $id.

    Files without an $id are skipped rather than fatal. Example payloads and fixtures
    live under specification/ too, and a contributor adding one must not stop the deploy.
    """
    schemas: dict[Path, dict] = {}
    for path in sorted(source.rglob("*.json")):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise SchemaError(f"{path}: invalid JSON: {error}") from error
        if not isinstance(doc, dict) or "$id" not in doc:
            continue
        schemas[path] = doc
    return schemas


def target_for(doc: dict, path: Path) -> str:
    """Return the validated publish path a document's $id declares.

    Rejects anything that would escape the output root or land outside the versioned
    namespace. The check runs on the decoded string so percent-encoded traversal
    cannot slip past it.
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
    if any(part in NON_NORMATIVE for part in path.parts):
        raise SchemaError(
            f"{path}: a file under {'/'.join(NON_NORMATIVE)}/ must not claim the "
            f"normative namespace ($id: {sid})"
        )
    return tail


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


def resolve_pointer(doc: dict, pointer: str) -> bool:
    """Return whether a JSON Pointer resolves inside doc. An empty pointer means the root."""
    if pointer in ("", "/"):
        return True
    node: object = doc
    for raw in pointer.lstrip("/").split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict):
            if token not in node:
                return False
            node = node[token]
        elif isinstance(node, list):
            if not token.isdigit() or int(token) >= len(node):
                return False
            node = node[int(token)]
        else:
            return False
    return True


def verify_refs(docs: dict[Path, dict], by_id: dict[str, dict]) -> None:
    """Fail if a $ref inside our namespace does not resolve, fragment included.

    Checking only the file leaves the likeliest real breakage undetected: renaming a
    $defs entry another schema points at. The package holds one cross-file fragment
    reference and it targets the signature definition.
    """
    for path, doc in docs.items():
        sid = doc["$id"]
        for ref in iter_refs(doc):
            target, fragment = urldefrag(urljoin(sid, ref))
            if not target.startswith(BASE):
                continue  # external reference, not ours to publish
            if target not in by_id:
                raise SchemaError(
                    f"{path}: $ref {ref!r} resolves to {target}, which no $id publishes"
                )
            if fragment == "" or fragment.startswith("/"):
                if not resolve_pointer(by_id[target], fragment):
                    raise SchemaError(
                        f"{path}: $ref {ref!r} points at {fragment!r}, "
                        f"which does not exist in {target}"
                    )


def publish(source: Path, out: Path) -> list[str]:
    """Copy every schema to its $id-declared path. Return sorted relative paths."""
    docs = load_schemas(source)
    if not docs:
        raise SchemaError(f"no schemas found under {source}")

    out.mkdir(parents=True, exist_ok=True)
    out_root = out.resolve()
    by_id: dict[str, dict] = {}
    seen: dict[str, Path] = {}
    published: list[str] = []

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

        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
        by_id[sid] = doc
        published.append(rel)

    verify_refs(docs, by_id)
    return sorted(published)


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
