"""Determinism, identifier stability and standard conformance."""
import filecmp, json, os, shutil, subprocess, sys
import jsonschema
import pytest
from conftest import ROOT, FIXTURES, EXAMPLE
from helpers import model
from code2design.pipeline import analyze
from code2design.model import TECH_LABEL, CONTROL_KINDS, WEAKNESSES

SCHEMA = json.load(open(os.path.join(ROOT, "schema", "dfd-ir.schema.json")))


def run_cli(args, seed):
    env = dict(os.environ, PYTHONHASHSEED=str(seed), PYTHONPATH=ROOT)
    return subprocess.run([sys.executable, "-m", "code2design"] + args, capture_output=True, text=True, env=env, cwd=ROOT)


def test_byte_identical_across_hash_seeds(tmp_path):
    outs = []
    for seed in (0, 7, 4242):
        out = tmp_path / f"o{seed}"
        r = run_cli(["analyze", EXAMPLE, "--out", str(out), "--name", "orders"], seed)
        assert r.returncode == 0, r.stderr
        outs.append(out)
    for other in outs[1:]:
        cmp = filecmp.dircmp(outs[0], other)
        assert not cmp.diff_files and not cmp.left_only and not cmp.right_only
        for sub in cmp.subdirs.values():
            assert not sub.diff_files and not sub.left_only and not sub.right_only


def _ids(ir):
    return {n["id"] for k in ("processes", "entities", "stores", "boundaries", "flows", "entry_points", "controls", "weaknesses", "schemas", "assets", "threat_agents") for n in ir[k]}


@pytest.mark.parametrize("name", ["flask_app", "nest_app", "go_mux"])
def test_ids_survive_whitespace_edits_and_directory_moves(tmp_path, name):
    base = analyze(os.path.join(FIXTURES, name), name="x")[3]
    moved = tmp_path / "somewhere" / "else"
    shutil.copytree(os.path.join(FIXTURES, name), moved)
    for dp, _, fns in os.walk(moved):
        for fn in fns:
            if fn.endswith((".py", ".ts", ".go", ".java", ".cs")):
                p = os.path.join(dp, fn)
                text = open(p).read()
                open(p, "w").write("\n\n\n" + text.replace("\n\n", "\n\n\n"))   # every line number shifts
    edited = analyze(str(moved), name="x")[3]
    assert _ids(base) == _ids(edited)


def test_schema_valid_and_lint_clean():
    from code2design.lint import lint
    for name in sorted(os.listdir(FIXTURES)) + [EXAMPLE]:
        ir = model(os.path.join(FIXTURES, name) if not os.path.isabs(name) else name)
        jsonschema.Draft202012Validator(SCHEMA).validate(ir)
        assert not [r for r in lint(ir) if r[0] == "error"], name


def test_schema_vocabularies_match_the_model():
    d = SCHEMA["$defs"]
    assert d["technology"]["enum"] == list(TECH_LABEL)
    assert d["control_kind"]["enum"] == list(CONTROL_KINDS)
    assert d["weakness_kind"]["enum"] == list(WEAKNESSES)
    for kind, (cwe, sev, stride, _title) in WEAKNESSES.items():
        assert cwe.startswith("CWE-") and sev in ("high", "medium", "low", "info") and set(stride) <= set("STRIDE"), kind


def test_otm_and_sarif_exports(tmp_path):
    from code2design.export_otm import to_otm
    from code2design.export_sarif import to_sarif
    ir = model(os.path.join(FIXTURES, "flask_app"))
    otm = to_otm(ir)
    ids = {c["id"] for c in otm["components"]}
    assert all(f["source"] in ids and f["destination"] in ids for f in otm["dataflows"])
    assert {t["id"] for t in otm["threats"]} == {w["id"] for w in ir["weaknesses"]}
    otm_schema = os.environ.get("OTM_SCHEMA", "/home/user/iriusrisk/openthreatmodel/otm_schema.json")
    if os.path.exists(otm_schema):
        jsonschema.Draft7Validator(json.load(open(otm_schema))).validate(otm)
    sarif = to_sarif(ir)
    assert sarif["version"] == "2.1.0"
    res = sarif["runs"][0]["results"]
    assert len(res) == len(ir["weaknesses"]) and all(r["ruleId"].startswith("c2d/") for r in res)


def test_mermaid_labels_are_safe_and_unique():
    from code2design.render import View
    ir = model(os.path.join(FIXTURES, "flask_app"))
    v = View(ir)
    text = v.dfd(1, "L1")
    assert "|" not in "".join(l.split('|"')[0] for l in text.splitlines() if "-->" in l)
    assert len(set(v.display.values())) == len(v.display)
    from code2design.render import cell
    assert cell("a|b") == "a\\|b"
