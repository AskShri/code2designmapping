"""Evaluation harness: run the prototype on every sample, check determinism, schema validity, lint,
Mermaid syntax, and write evaluation/<sample>/ plus evaluation/results.json.

Usage: python3 scripts/evaluate.py samples.json
samples.json: [{"name": "...", "path": "/abs/path", "exclude": [...], "expect": {"entities": [...], "stores": [...], "controls": [...], "entry_points_min": N, "notes": "..."}}, ...]
"""
import json, os, shutil, subprocess, sys, time, filecmp, tempfile
from collections import OrderedDict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import jsonschema
from code2design.__main__ import main as c2d_main

SCHEMA = json.load(open(os.path.join(ROOT, "schema", "dfd-ir.schema.json")))
MERMAID_CHECK = os.path.join(ROOT, "scripts", "check-mermaid.js")


def run_one(sample, workdir):
    out1 = os.path.join(workdir, "run1"); out2 = os.path.join(workdir, "run2")
    extra = sum((["--exclude", e] for e in sample.get("exclude", [])), [])
    t0 = time.time()
    c2d_main(["analyze", sample["path"], "--out", out1, "--name", sample["name"]] + extra)
    elapsed = time.time() - t0
    c2d_main(["analyze", sample["path"], "--out", out2, "--name", sample["name"]] + extra)
    diff_files = []
    for dp, _, fns in os.walk(out1):
        for fn in fns:
            a = os.path.join(dp, fn); b = os.path.join(out2, os.path.relpath(a, out1))
            if fn == "report.md":
                ra = [l for l in open(a) if not l.startswith("Commit ")]; rb = [l for l in open(b) if not l.startswith("Commit ")]
                if ra != rb: diff_files.append(fn)
            elif not filecmp.cmp(a, b, shallow=False):
                diff_files.append(os.path.relpath(a, out1))
    ir = json.load(open(os.path.join(out1, "model.ir.json")))
    schema_ok = True; schema_err = ""
    try:
        jsonschema.Draft202012Validator(SCHEMA).validate(ir)
    except jsonschema.ValidationError as e:
        schema_ok = False; schema_err = str(e).splitlines()[0][:200]
    lint_rows = json.load(open(os.path.join(out1, "lint.json")))
    mermaid = subprocess.run(["node", MERMAID_CHECK, os.path.join(out1, "diagrams")], capture_output=True, text=True)
    mm_lines = [l for l in mermaid.stdout.splitlines() if l.endswith(")") or "FAIL" in l]
    mm_fail = [l for l in mm_lines if "FAIL" in l]
    names = lambda k: {n["name"].lower() for n in ir[k]}
    exp = sample.get("expect", {})
    hits, misses = [], []
    for k in ("entities", "stores"):
        for want in exp.get(k, []):
            (hits if any(want.lower() in n for n in names(k)) else misses).append(f"{k[:-1]}:{want}")
    for want in exp.get("controls", []):
        (hits if any(want.lower() in c["name"].lower() for c in ir["controls"]) else misses).append(f"control:{want}")
    ep_want = exp.get("entry_points_min")
    if ep_want is not None:
        (hits if len(ir["entry_points"]) >= ep_want else misses).append(f"entry_points>={ep_want} (got {len(ir['entry_points'])})")
    return OrderedDict(name=sample["name"], path=sample["path"], elapsed=round(elapsed, 2), deterministic=not diff_files, nondeterministic_files=diff_files,
                       schema_ok=schema_ok, schema_err=schema_err, lint_errors=sum(1 for r in lint_rows if r["severity"] == "error"), lint_warnings=sum(1 for r in lint_rows if r["severity"] == "warning"),
                       mermaid_files=len(mm_lines), mermaid_failures=mm_fail, counts={k: len(ir[k]) for k in ("processes", "entities", "stores", "boundaries", "flows", "entry_points", "controls", "weaknesses", "schemas", "assets", "threat_agents", "gaps")},
                       unsupported=[g["detail"] for g in ir["gaps"] if g["kind"] == "unsupported_file"],
                       expect_hits=hits, expect_misses=misses, notes=exp.get("notes", ""), out=out1)


def main():
    samples = json.load(open(sys.argv[1]))
    evaldir = os.path.join(ROOT, "evaluation")
    os.makedirs(evaldir, exist_ok=True)
    results = []
    for s in samples:
        wd = tempfile.mkdtemp(prefix="c2d-", dir=os.environ.get("C2D_TMP"))
        r = run_one(s, wd)
        dest = os.path.join(evaldir, s["name"])
        shutil.rmtree(dest, ignore_errors=True)
        shutil.copytree(r["out"], dest)
        os.remove(os.path.join(dest, "facts.jsonl"))
        flows = sorted(f for f in os.listdir(os.path.join(dest, "diagrams")) if f.startswith("flow-"))
        for f in flows[5:]:
            os.remove(os.path.join(dest, "diagrams", f))
        results.append(r)
        print(f"{r['name']}: det={r['deterministic']} schema={r['schema_ok']} lint_err={r['lint_errors']} mermaid_fail={len(r['mermaid_failures'])} {r['counts']} hits={len(r['expect_hits'])} misses={r['expect_misses']} {r['elapsed']}s")
    json.dump(results, open(os.path.join(evaldir, "results.json"), "w"), indent=2)


if __name__ == "__main__":
    main()
