"""Tests for the schema publisher.

The negative cases are the point. $id reaches this code from any pull request, including
a fork's, and it is used to build a filesystem path.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from publish_schemas import BASE, SchemaError, iter_refs, publish, resolve_pointer, target_for

REPO = Path(__file__).resolve().parents[1]


def write_schema(root: Path, rel: str, sid: str, body: dict | None = None) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {"$id": sid}
    doc.update(body or {})
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


# --- $id validation -------------------------------------------------------

def test_target_for_strips_the_namespace_base():
    assert target_for({"$id": BASE + "v0.1.0/acs_schema.json"}, Path("a")) == "v0.1.0/acs_schema.json"


def test_target_for_rejects_a_missing_id():
    with pytest.raises(SchemaError, match="no \\$id"):
        target_for({}, Path("broken.json"))


def test_target_for_rejects_an_out_of_namespace_id():
    with pytest.raises(SchemaError, match="outside namespace"):
        target_for({"$id": "https://example.com/schema/v0.1.0/x.json"}, Path("broken.json"))


@pytest.mark.parametrize(
    "tail",
    [
        "../index.html",
        "../../../../pwned.txt",
        "/etc/passwd",
        "v0.1.0/../../x.json",
        "v0.1.0/%2e%2e/x.json",
        "index.html",
        "v0.1.0/x.txt",
        "",
    ],
)
def test_target_for_rejects_unsafe_publish_paths(tail):
    """Each of these escapes the artifact or lands outside the versioned namespace."""
    with pytest.raises(SchemaError):
        target_for({"$id": BASE + tail}, Path("evil.json"))


def test_publish_refuses_an_id_that_escapes_the_output_root(tmp_path):
    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/a.json", BASE + "../../../../pwned.txt")
    with pytest.raises(SchemaError):
        publish(src, out)
    assert not (tmp_path.parent / "pwned.txt").exists()


def test_publish_rejects_a_draft_claiming_the_normative_namespace(tmp_path):
    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/a.json", BASE + "v0.1.0/a.json")
    write_schema(src, "proposals/draft.json", BASE + "v0.1.0/draft.json")
    with pytest.raises(SchemaError, match="normative namespace"):
        publish(src, out)


def test_publish_rejects_a_duplicate_id(tmp_path):
    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/a.json", BASE + "v0.1.0/dup.json", {"x": 1})
    write_schema(src, "v0.1.0/b.json", BASE + "v0.1.0/dup.json", {"x": 2})
    with pytest.raises(SchemaError, match="duplicate \\$id"):
        publish(src, out)


# --- placement ------------------------------------------------------------

def test_publish_places_files_at_their_declared_id_path(tmp_path):
    src, out = tmp_path / "spec", tmp_path / "out"
    # On-disk layout deliberately differs from the URI layout.
    write_schema(src, "ACS/acs_schema.json", BASE + "v0.1.0/acs_schema.json")
    assert publish(src, out) == ["v0.1.0/acs_schema.json"]
    assert (out / "v0.1.0" / "acs_schema.json").is_file()


def test_publish_skips_json_without_an_id(tmp_path):
    """An example payload beside a proposal must not stop the deploy."""
    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/a.json", BASE + "v0.1.0/a.json")
    (src / "proposals").mkdir(parents=True, exist_ok=True)
    (src / "proposals" / "example.json").write_text('{"session_id": "abc"}', encoding="utf-8")
    assert publish(src, out) == ["v0.1.0/a.json"]


def test_publish_fails_on_invalid_json(tmp_path):
    src, out = tmp_path / "spec", tmp_path / "out"
    (src / "v0.1.0").mkdir(parents=True)
    (src / "v0.1.0" / "bad.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(SchemaError, match="invalid JSON"):
        publish(src, out)


def test_publish_fails_when_no_schemas_are_found(tmp_path):
    with pytest.raises(SchemaError, match="no schemas found"):
        publish(tmp_path / "empty", tmp_path / "out")


def test_publish_handles_more_than_one_spec_version(tmp_path):
    """Old versions stay published so their $id URIs keep resolving."""
    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/a.json", BASE + "v0.1.0/a.json")
    write_schema(src, "v0.2.0/a.json", BASE + "v0.2.0/a.json")
    assert publish(src, out) == ["v0.1.0/a.json", "v0.2.0/a.json"]


# --- reference closure ----------------------------------------------------

def test_iter_refs_finds_nested_and_listed_refs():
    doc = {"$ref": "a.json", "properties": {"x": {"$ref": "b.json"}}, "anyOf": [{"$ref": "c.json"}]}
    assert sorted(iter_refs(doc)) == ["a.json", "b.json", "c.json"]


def test_resolve_pointer_walks_objects_and_arrays():
    doc = {"$defs": {"S": {"type": "string"}}, "list": [{"a": 1}]}
    assert resolve_pointer(doc, "/$defs/S")
    assert resolve_pointer(doc, "/list/0/a")
    assert not resolve_pointer(doc, "/$defs/Missing")
    assert not resolve_pointer(doc, "/list/9")


def test_publish_resolves_a_parent_relative_ref(tmp_path):
    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/provenance.json", BASE + "v0.1.0/provenance.json")
    write_schema(
        src, "v0.1.0/hooks/session-start.json", BASE + "v0.1.0/hooks/session-start.json",
        {"properties": {"p": {"$ref": "../provenance.json"}}},
    )
    assert len(publish(src, out)) == 2


def test_publish_fails_on_a_dangling_ref(tmp_path):
    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/a.json", BASE + "v0.1.0/a.json",
                 {"properties": {"p": {"$ref": "./missing.json"}}})
    with pytest.raises(SchemaError, match="which no \\$id publishes"):
        publish(src, out)


def test_publish_fails_on_a_cross_file_fragment_that_does_not_exist(tmp_path):
    """Renaming a $defs entry another schema points at is the likeliest real breakage."""
    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/t.json", BASE + "v0.1.0/t.json", {"$defs": {"Renamed": {}}})
    write_schema(src, "v0.1.0/s.json", BASE + "v0.1.0/s.json",
                 {"properties": {"p": {"$ref": "t.json#/$defs/Sig"}}})
    with pytest.raises(SchemaError, match="does not exist in"):
        publish(src, out)


def test_publish_accepts_a_cross_file_fragment_that_exists(tmp_path):
    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/t.json", BASE + "v0.1.0/t.json", {"$defs": {"Sig": {"type": "string"}}})
    write_schema(src, "v0.1.0/s.json", BASE + "v0.1.0/s.json",
                 {"properties": {"p": {"$ref": "t.json#/$defs/Sig"}}})
    assert len(publish(src, out)) == 2


def test_publish_fails_on_a_broken_self_fragment(tmp_path):
    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/a.json", BASE + "v0.1.0/a.json",
                 {"properties": {"p": {"$ref": "#/$defs/Missing"}}})
    with pytest.raises(SchemaError, match="does not exist in"):
        publish(src, out)


def test_publish_ignores_an_external_ref(tmp_path):
    src, out = tmp_path / "spec", tmp_path / "out"
    write_schema(src, "v0.1.0/a.json", BASE + "v0.1.0/a.json",
                 {"properties": {"p": {"$ref": "https://json-schema.org/draft/2020-12/schema"}}})
    assert publish(src, out) == ["v0.1.0/a.json"]


# --- the real tree --------------------------------------------------------

def test_publish_handles_the_real_specification_tree(tmp_path):
    published = publish(REPO / "specification", tmp_path / "out")
    assert "v0.1.0/acs_schema.json" in published
    assert len(published) == len(set(published))
    # No magic count. A count assertion breaks on every legitimate schema addition,
    # and the first hand-bump after a collision would hide the collision.
    assert len(published) >= 44


def test_every_real_schema_is_a_valid_json_schema():
    """Ref closure is not validity. A closed package can still be unusable."""
    from jsonschema import Draft202012Validator

    for path in sorted((REPO / "specification").rglob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and "$id" in doc:
            Draft202012Validator.check_schema(doc)
