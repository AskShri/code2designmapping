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


def _norm_ep(label):
    import re as _re
    label = _re.sub(r"[:{]\w+}?", ":param", label.strip())
    label = _re.sub(r"\s+", " ", label)
    method, _, path = label.partition(" ")
    path = path.rstrip("/") or "/"
    return f"{method} {path}"


def score_ground_truth(ir, gt, multi_service):
    """Precision/recall for entry points, stores, entities and handler-to-target reachability edges."""
    nodes = {n["id"]: n for k in ("processes", "entities", "stores") for n in ir[k]}
    procs = {p["id"]: p for p in ir["processes"]}
    ep_of_proc = {e["process"]: e for e in ir["entry_points"]}
    def ep_label(e):
        return _norm_ep(f"grpc {e['path']}" if e["protocol"] == "grpc" else f"{e['method']} {e['path']}")
    def target_label(nid):
        n = nodes[nid]
        if nid.startswith("store"):
            return f"{n['technology']}:{(n.get('logical_name') or '*').lower()}"
        if nid.startswith("ext"):
            return n["name"]
        if nid.startswith("proc"):
            p = n
            while p["level"] > 1 and p.get("parent"):
                p = procs[p["parent"]]
            return f"svc:{p['name'].lower()}"
        return nid
    def match(pred, truth):
        if truth.startswith("svc:"):
            t = truth[4:]
            return (pred.startswith("svc:") and pred[4:] == t) or (not pred.startswith(("svc:", "redis:", "postgres:", "mysql:", "mongodb:")) and t in pred.lower().replace(" ", ""))
        if ":" in truth and not truth.startswith(("GET", "POST", "PUT", "PATCH", "DELETE", "grpc")):
            tech, logical = truth.split(":", 1)
            if ":" not in pred: return False
            ptech, plog = pred.split(":", 1)
            return ptech == tech and (logical == "*" or plog == logical or plog == logical + ":*" or plog.rstrip("s") == logical.rstrip("s"))
        return truth.lower() in pred.lower() if not truth[0].isupper() or truth.split(" ")[0] not in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "grpc") else pred == _norm_ep(truth)
    # predicted sets
    pred_eps = {ep_label(e) for e in ir["entry_points"] if not e.get("infrastructure")}
    pred_infra = {ep_label(e) for e in ir["entry_points"] if e.get("infrastructure")}
    pred_stores = {target_label(s["id"]) for s in ir["stores"]}
    pred_ents = {e["name"] for e in ir["entities"] if e["identity"][-1] == "outbound"}
    inproc = {}
    for f in ir["flows"]:
        if f["protocol"] == "in_process":
            inproc.setdefault(f["source"], set()).add(f["target"])
    pred_edges = set()
    for e in ir["entry_points"]:
        if e.get("infrastructure"):
            continue
        if "reaches" in e:
            for t in e["reaches"]:
                pred_edges.add((ep_label(e), target_label(t)))
            continue
        seen = {e["process"]}; stack = [e["process"]]
        while stack:
            cur = stack.pop()
            for f in ir["flows"]:
                if f["source"] == cur and (f["target"].startswith(("store", "ext")) or (f["target"].startswith("proc") and procs[f["target"]]["level"] == 1)):
                    pred_edges.add((ep_label(e), target_label(f["target"])))
                if f["target"] == cur and f["source"].startswith("store"):
                    pred_edges.add((ep_label(e), target_label(f["source"])))
            for nx in inproc.get(cur, ()):
                if nx not in seen and nx not in ep_of_proc:
                    seen.add(nx); stack.append(nx)
    def pr(preds, truths, m):
        tp_t = sum(1 for t in truths if any(m(p, t) for p in preds))
        tp_p = sum(1 for p in preds if any(m(p, t) for t in truths))
        return OrderedDict(precision=round(tp_p / len(preds), 2) if preds else None, recall=round(tp_t / len(truths), 2) if truths else None, predicted=len(preds), truth=len(truths),
                           missed=sorted(t for t in truths if not any(m(p, t) for p in preds))[:12], spurious=sorted(p for p in preds if not any(m(p, t) for t in truths))[:12])
    res = OrderedDict()
    res["entry_points"] = pr(pred_eps, {_norm_ep(x) for x in gt.get("entry_points", [])}, lambda p, t: p == t)
    res["infrastructure"] = pr(pred_infra, {_norm_ep(x) for x in gt.get("infrastructure", [])}, lambda p, t: p == t)
    res["stores"] = pr(pred_stores, set(gt.get("stores", [])), match)
    res["entities"] = pr(pred_ents, set(gt.get("entities", [])), lambda p, t: t.lower() in p.lower())
    res["edges"] = pr(pred_edges, {(_norm_ep(a), b) for a, b in gt.get("edges", [])}, lambda p, t: p[0] == t[0] and match(p[1], t[1]))
    return res


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
    gt_path = os.path.join(ROOT, "evaluation", "ground-truth", sample["name"] + ".json")
    gt_scores = score_ground_truth(ir, json.load(open(gt_path)), len([b for b in ir["boundaries"]]) > 2) if os.path.exists(gt_path) else None
    return OrderedDict(name=sample["name"], path=sample["path"], elapsed=round(elapsed, 2), deterministic=not diff_files, nondeterministic_files=diff_files, ground_truth=gt_scores,
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
        gts = r.get("ground_truth")
        gtxt = " GT: " + " ".join(f"{k}=P{v['precision']}/R{v['recall']}" for k, v in gts.items() if v["truth"] or v["predicted"]) if gts else ""
        print(f"{r['name']}: det={r['deterministic']} schema={r['schema_ok']} lint_err={r['lint_errors']} mermaid_fail={len(r['mermaid_failures'])} {r['counts']} hits={len(r['expect_hits'])} misses={r['expect_misses']} {r['elapsed']}s{gtxt}")
    json.dump(results, open(os.path.join(evaldir, "results.json"), "w"), indent=2)


if __name__ == "__main__":
    main()
