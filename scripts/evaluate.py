"""Evaluation harness.

For every sample: run the CLI twice in separate processes with different PYTHONHASHSEED values and
compare every output byte for byte; validate the IR against the schema; lint; render-check every
Mermaid diagram; validate the OTM export against the official schema when it is available; score
against hand-written ground truth where it exists.

Usage:  python3 scripts/evaluate.py evaluation/samples.json            full run, writes evaluation/
        python3 scripts/evaluate.py evaluation/samples.json --quick    ground-truth scores only, in process
        python3 scripts/evaluate.py evaluation/samples.json --only name1,name2
"""
import filecmp, json, os, re, shutil, subprocess, sys, tempfile, time
from collections import OrderedDict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import jsonschema  # noqa: E402

SCHEMA = json.load(open(os.path.join(ROOT, "schema", "dfd-ir.schema.json")))
MERMAID_CHECK = os.path.join(ROOT, "scripts", "check-mermaid.js")
OTM_SCHEMA_PATH = os.environ.get("OTM_SCHEMA", "/home/user/iriusrisk/openthreatmodel/otm_schema.json")
METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "grpc", "TASK", "CONSUME")
BLOCKING = ("authn", "authz")


def norm_ep(label):
    """'GET /a/<int:id>/' -> 'GET /a/:param'. Any parameter syntax, no trailing slash."""
    label = re.sub(r"\s+", " ", label.strip())
    method, _, path = label.partition(" ")
    path = re.sub(r"<[^>]+>|\{[^}]+\}|:\w+", ":param", path)
    return f"{method} {path.rstrip('/') or '/'}"


def _singular(s):
    return s[:-1] if s.endswith("s") and not s.endswith("ss") else s


def score_ground_truth(ir, gt):
    """Precision and recall per collection. Returns an ordered dict of result rows."""
    nodes = {n["id"]: n for k in ("processes", "entities", "stores") for n in ir[k]}
    procs = {p["id"]: p for p in ir["processes"]}
    ctl = {c["id"]: c for c in ir["controls"]}

    def ep_label(e):
        return norm_ep(f"grpc {e['path']}" if e["protocol"] == "grpc" else f"{e['method']} {e['path']}")

    def target_label(nid):
        n = nodes[nid]
        if nid.startswith("store"):
            return f"{n['technology']}:{(n.get('logical_name') or '*').lower()}"
        if nid.startswith("ext"):
            return n["name"]
        p = n
        while p["level"] > 1 and p.get("parent"):
            p = procs[p["parent"]]
        return f"svc:{p['name'].lower()}"

    def match(pred, truth):
        if truth.startswith("svc:"):
            return pred.startswith("svc:") and pred[4:] == truth[4:] or (":" not in pred and truth[4:] in pred.lower().replace(" ", ""))
        if re.match(r"^[a-z0-9_*]+:", truth):
            tech, logical = truth.split(":", 1)
            if not re.match(r"^[a-z0-9_]+:", pred) or pred.startswith("svc:"):
                return False
            ptech, plog = pred.split(":", 1)
            if tech != "*" and ptech != tech:
                return False
            return logical == "*" or plog == logical or plog == logical + ":*" or _singular(plog) == _singular(logical)
        return truth.lower() in pred.lower()

    main = [e for e in ir["entry_points"] if not e.get("infrastructure")]
    pred_eps = {ep_label(e) for e in main}
    pred_infra = {ep_label(e) for e in ir["entry_points"] if e.get("infrastructure")}
    pred_auth = {ep_label(e) for e in main if any(ctl[c]["kind"] in BLOCKING and not ctl[c].get("conditional") for c in e["controls"])}
    pred_stores = {target_label(s["id"]) for s in ir["stores"]}
    pred_ents = {e["name"] for e in ir["entities"] if e["identity"][-1] == "outbound"}
    pred_edges = {(ep_label(e), target_label(t)) for e in main for t in e.get("reaches", [])}

    def pr(preds, truths, m):
        hit_t = [t for t in truths if any(m(p, t) for p in preds)]
        hit_p = [p for p in preds if any(m(p, t) for t in truths)]
        return OrderedDict(precision=round(len(hit_p) / len(preds), 2) if preds else None, recall=round(len(hit_t) / len(truths), 2) if truths else None,
                           predicted=len(preds), truth=len(truths),
                           missed=sorted(str(t) for t in truths if t not in hit_t)[:15], spurious=sorted(str(p) for p in preds if p not in hit_p)[:15])
    eq = lambda p, t: p == t  # noqa: E731
    res = OrderedDict()
    res["entry_points"] = pr(pred_eps, {norm_ep(x) for x in gt.get("entry_points", [])}, eq)
    res["infrastructure"] = pr(pred_infra, {norm_ep(x) for x in gt.get("infrastructure", [])}, eq)
    if "authenticated" in gt:
        res["authenticated"] = pr(pred_auth, {norm_ep(x) for x in gt["authenticated"]}, eq)
    res["stores"] = pr(pred_stores, set(gt.get("stores", [])), match)
    res["entities"] = pr(pred_ents, set(gt.get("entities", [])), lambda p, t: t.lower() in p.lower())
    if gt.get("edges"):
        res["edges"] = pr(pred_edges, {(norm_ep(a), b) for a, b in gt.get("edges", [])}, lambda p, t: p[0] == t[0] and match(p[1], t[1]))
    return res


def gt_text(gts):
    return " ".join(f"{k}=P{v['precision']}/R{v['recall']}" for k, v in gts.items() if v["truth"] or v["predicted"]) if gts else ""


def _cli(args, seed):
    env = dict(os.environ, PYTHONHASHSEED=str(seed), PYTHONPATH=ROOT)
    return subprocess.run([sys.executable, "-m", "code2design"] + args, capture_output=True, text=True, env=env, cwd=ROOT)


def _compare(a, b):
    diffs = []
    for dp, _, fns in os.walk(a):
        for fn in fns:
            pa = os.path.join(dp, fn); pb = os.path.join(b, os.path.relpath(pa, a))
            if not os.path.exists(pb) or not filecmp.cmp(pa, pb, shallow=False):
                diffs.append(os.path.relpath(pa, a))
    return sorted(diffs)


def run_one(sample, workdir):
    out1, out2 = os.path.join(workdir, "run1"), os.path.join(workdir, "run2")
    extra = sum((["--exclude", e] for e in sample.get("exclude", [])), [])
    args = ["analyze", sample["path"], "--name", sample["name"]] + extra
    t0 = time.time()
    r1 = _cli(args + ["--out", out1], seed=1)
    elapsed = time.time() - t0
    if r1.returncode not in (0, 1) or not os.path.exists(os.path.join(out1, "model.ir.json")):
        return OrderedDict(name=sample["name"], path=sample["path"], error=(r1.stderr or r1.stdout)[-600:])
    _cli(args + ["--out", out2], seed=4242)
    diff_files = _compare(out1, out2)
    ir = json.load(open(os.path.join(out1, "model.ir.json")))
    errors = sorted(jsonschema.Draft202012Validator(SCHEMA).iter_errors(ir), key=lambda e: list(e.absolute_path))
    schema_err = f"{'/'.join(str(x) for x in errors[0].absolute_path)}: {errors[0].message[:160]}" if errors else ""
    lint_rows = json.load(open(os.path.join(out1, "lint.json")))
    mermaid = subprocess.run(["node", MERMAID_CHECK, os.path.join(out1, "diagrams")], capture_output=True, text=True)
    mm_lines = [l for l in mermaid.stdout.splitlines() if " ok (svg " in l or " FAIL: " in l]
    mm_fail = [l for l in mm_lines if " FAIL: " in l]
    if mermaid.returncode not in (0, 1) or (not mm_lines and any(f.endswith(".mmd") for f in os.listdir(os.path.join(out1, "diagrams")))):
        mm_fail.append(f"checker did not run: {(mermaid.stderr or mermaid.stdout)[-200:]}")
    otm_ok = None
    if os.path.exists(OTM_SCHEMA_PATH):
        otm = json.load(open(os.path.join(out1, "model.otm.json")))
        otm_errors = list(jsonschema.Draft7Validator(json.load(open(OTM_SCHEMA_PATH))).iter_errors(otm))
        otm_ok = not otm_errors
    sarif = json.load(open(os.path.join(out1, "findings.sarif")))
    sarif_ok = sarif.get("version") == "2.1.0" and all("ruleId" in r and r["locations"] for run in sarif["runs"] for r in run["results"])
    names = lambda k: {n["name"].lower() for n in ir[k]}  # noqa: E731
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
    gts = score_ground_truth(ir, json.load(open(gt_path))) if os.path.exists(gt_path) else None
    return OrderedDict(name=sample["name"], path=sample["path"], elapsed=round(elapsed, 2), deterministic=not diff_files, nondeterministic_files=diff_files, ground_truth=gts,
                       schema_ok=not errors, schema_err=schema_err, otm_schema_ok=otm_ok, sarif_ok=sarif_ok,
                       lint_errors=sum(1 for r in lint_rows if r["severity"] == "error"), lint_warnings=sum(1 for r in lint_rows if r["severity"] == "warning"),
                       mermaid_files=len(mm_lines), mermaid_failures=mm_fail,
                       counts={k: len(ir[k]) for k in ("processes", "entities", "stores", "boundaries", "flows", "entry_points", "controls", "weaknesses", "schemas", "assets", "threat_agents", "gaps")},
                       unsupported=[g["detail"] for g in ir["gaps"] if g["kind"] == "unsupported_file"],
                       expect_hits=hits, expect_misses=misses, notes=exp.get("notes", ""), out=out1)


def quick(samples):
    from code2design.pipeline import analyze
    for s in samples:
        gt_path = os.path.join(ROOT, "evaluation", "ground-truth", s["name"] + ".json")
        t0 = time.time()
        try:
            _idx, _facts, _cg, ir = analyze(s["path"], name=s["name"], exclude=s.get("exclude"))
        except Exception as e:  # noqa: BLE001
            import traceback
            print(f"{s['name']}: ERROR {type(e).__name__}: {e}\n{traceback.format_exc()[-900:]}")
            continue
        counts = {k[:3]: len(ir[k]) for k in ("processes", "entities", "stores", "flows", "entry_points", "controls", "weaknesses", "gaps")}
        if not os.path.exists(gt_path):
            print(f"{s['name']}: {counts} {time.time() - t0:.1f}s")
            continue
        gts = score_ground_truth(ir, json.load(open(gt_path)))
        print(f"{s['name']}: {gt_text(gts)}  {time.time() - t0:.1f}s")
        if "--verbose" in sys.argv:
            for k, v in gts.items():
                if v["missed"] or v["spurious"]:
                    print(f"   {k}: missed={v['missed']} spurious={v['spurious']}")


def main():
    samples = json.load(open(sys.argv[1]))
    if "--only" in sys.argv:
        want = set(sys.argv[sys.argv.index("--only") + 1].split(","))
        samples = [s for s in samples if s["name"] in want]
    if "--quick" in sys.argv:
        return quick(samples)
    evaldir = os.path.join(ROOT, "evaluation")
    results = []
    for s in samples:
        wd = tempfile.mkdtemp(prefix="c2d-", dir=os.environ.get("C2D_TMP"))
        r = run_one(s, wd)
        results.append(r)
        if r.get("error"):
            print(f"{r['name']}: ERROR {r['error']}")
            continue
        dest = os.path.join(evaldir, s["name"])
        keep = {fn: open(os.path.join(dest, fn)).read() for fn in ("design-delta.md",) if os.path.exists(os.path.join(dest, fn))}
        shutil.rmtree(dest, ignore_errors=True)
        shutil.copytree(r["out"], dest)
        for fn, text in keep.items():          # hand-produced artifacts that the run does not regenerate
            open(os.path.join(dest, fn), "w").write(text)
        os.remove(os.path.join(dest, "facts.jsonl"))
        flows = sorted(f for f in os.listdir(os.path.join(dest, "diagrams")) if f.startswith("flow-"))
        for f in flows[5:]:
            os.remove(os.path.join(dest, "diagrams", f))
        r.pop("out")
        print(f"{r['name']}: det={r['deterministic']} schema={r['schema_ok']} otm={r['otm_schema_ok']} sarif={r['sarif_ok']} lint_err={r['lint_errors']} mermaid={r['mermaid_files']}/{len(r['mermaid_failures'])}fail "
              f"misses={r['expect_misses']} {r['elapsed']}s GT: {gt_text(r['ground_truth'])}")
    if "--only" not in sys.argv:
        json.dump(results, open(os.path.join(evaldir, "results.json"), "w"), indent=2)


if __name__ == "__main__":
    main()
