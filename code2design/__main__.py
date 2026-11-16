"""code2design: code -> evidence-backed data-flow design.

  python -m code2design analyze <repo> [--out DIR] [--name NAME] [--include GLOB] [--exclude GLOB] [--overrides FILE] [--repo-url URL]
  python -m code2design diff <base.ir.json> <head.ir.json> [--title T]
  python -m code2design verify <ir.json> --repo <repo>
  python -m code2design export <ir.json> --format otm|sarif [--repo-url URL]
  python -m code2design lint <ir.json>
"""
import argparse, json, os, re, sys
from collections import OrderedDict
from . import __version__

MAX_FLOW_DIAGRAMS = 40


def _write(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _json(path, obj):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2)
        fh.write("\n")


def write_outputs(out, idx, facts, ir, rows, repo_url=None):
    from .render import View, flow_diagram_order
    from .export_otm import to_otm
    from .export_sarif import to_sarif
    diag = os.path.join(out, "diagrams")
    os.makedirs(diag, exist_ok=True)
    for fn in os.listdir(diag):                       # a re-run must not leave diagrams of deleted elements
        if re.fullmatch(r"(dfd-l[01]|dfd-l2-[a-z2-7]{10}|flow-[a-z2-7]{10})\.mmd", fn):
            os.remove(os.path.join(diag, fn))
    with open(os.path.join(out, "facts.jsonl"), "w", encoding="utf-8") as fh:
        for f in facts.facts:
            fh.write(json.dumps(f) + "\n")
    _json(os.path.join(out, "model.ir.json"), ir)
    name = ir["provenance"]["generated_from"]
    v = View(ir)
    _write(os.path.join(diag, "dfd-l0.mmd"), v.dfd(0, f"L0 context: {name}"))
    _write(os.path.join(diag, "dfd-l1.mmd"), v.dfd(1, f"L1: {name}"))
    for p in ir["processes"]:
        if p["level"] == 1 and any(c.get("parent") == p["id"] for c in ir["processes"]):
            _write(os.path.join(diag, f"dfd-l2-{p['id'].split(':')[1]}.mmd"), v.dfd(2, f"L2: {p['name']}", focus=p["id"]))
    for ep in flow_diagram_order(ir)[:MAX_FLOW_DIAGRAMS]:
        _write(os.path.join(diag, f"flow-{ep['id'].split(':')[1]}.mmd"), v.sequence(ep))
    _write(os.path.join(out, "stride-table.md"), v.stride())
    _write(os.path.join(out, "traceability-matrix.md"), v.matrix())
    _write(os.path.join(out, "report.md"), v.report(idx, facts, rows))
    _json(os.path.join(out, "lint.json"), [OrderedDict(severity=s, rule=r, id=i, message=m) for s, r, i, m in rows])
    _json(os.path.join(out, "model.otm.json"), to_otm(ir, repo_url))
    _json(os.path.join(out, "findings.sarif"), to_sarif(ir, repo_url))


def analyze(args):
    from .pipeline import analyze as run
    from .lint import lint
    from . import overrides as ov
    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print(f"code2design: {args.path} is not a directory", file=sys.stderr)
        return 2
    idx, facts, _cg, ir = run(root, name=args.name, include=args.include or None, exclude=args.exclude or None)
    ov_path = args.overrides or os.path.join(root, ".code2design", "overrides.yaml")
    loaded, ov_gaps = ov.load(ov_path)
    if loaded:
        ir = ov.apply(ir, loaded, os.path.relpath(ov_path, root).replace(os.sep, "/"))
    ir["gaps"] = ir["gaps"] + ov_gaps
    rows = lint(ir)
    out = args.out or os.path.join(root, ".code2design")
    write_outputs(out, idx, facts, ir, rows, args.repo_url)
    errors = sum(1 for r in rows if r[0] == "error")
    warnings = sum(1 for r in rows if r[0] == "warning")
    print(f"{ir['provenance']['generated_from']}: {len(ir['processes'])} processes, {len(ir['entities'])} entities, {len(ir['stores'])} stores, {len(ir['flows'])} flows, "
          f"{len(ir['entry_points'])} entry points, {len(ir['controls'])} controls, {len(ir['weaknesses'])} weaknesses, {len(ir['gaps'])} gaps; lint: {errors} errors, {warnings} warnings -> {out}")
    return 1 if errors else 0


def verify(args):
    """Re-open every evidence span and compare its content hash; report what changed or vanished."""
    from .model import span_hash
    ir = json.load(open(args.ir))
    changed, missing, ok = [], [], 0
    cache = {}
    for k in ("processes", "entities", "stores", "boundaries", "flows", "entry_points", "controls", "weaknesses", "schemas", "assets", "threat_agents"):
        for n in ir[k]:
            label = n.get("name") or (f"{n['method']} {n['path']}" if "method" in n else n["id"])
            for e in n.get("evidence", []):
                if e["path"] == ".":
                    continue
                full = os.path.join(args.repo, e["path"])
                if full not in cache:
                    cache[full] = open(full, encoding="utf-8", errors="replace").read().splitlines() if os.path.exists(full) else None
                lines = cache[full]
                if lines is None:
                    missing.append((k, label, e["path"]))
                elif span_hash(lines[e["start_line"] - 1:e["end_line"]]) != e.get("content_hash"):
                    changed.append((k, label, f"{e['path']}:{e['start_line']}-{e['end_line']}"))
                else:
                    ok += 1
    print(f"## Evidence verification\n\n{ok} spans unchanged, {len(changed)} changed, {len(missing)} files missing.\n")
    for k, nm, where in changed[:200]:
        print(f"- changed: {k[:-1]} {nm} at {where}")
    for k, nm, where in missing[:200]:
        print(f"- missing: {k[:-1]} {nm} ({where})")
    return 1 if (changed or missing) else 0


def _load_ir(path):
    from . import IR_VERSION
    ir = json.load(open(path))
    if not isinstance(ir, dict) or ir.get("version") != IR_VERSION:
        sys.exit(f"code2design: {path} is IR version {ir.get('version') if isinstance(ir, dict) else '?'}; this tool reads IR {IR_VERSION}. Re-run analyze.")
    return ir


def main(argv=None):
    ap = argparse.ArgumentParser(prog="code2design", description="Code to evidence-backed data-flow design (DFD, STRIDE, OTM, SARIF).")
    ap.add_argument("--version", action="version", version=f"code2design {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="analyze a repository and write the model and its views")
    a.add_argument("path"); a.add_argument("--out"); a.add_argument("--name"); a.add_argument("--include", action="append"); a.add_argument("--exclude", action="append")
    a.add_argument("--overrides"); a.add_argument("--repo-url")
    v = sub.add_parser("verify", help="check that every evidence span still matches the code")
    v.add_argument("ir"); v.add_argument("--repo", required=True)
    x = sub.add_parser("export", help="export a model as OTM or SARIF")
    x.add_argument("ir"); x.add_argument("--format", default="otm", choices=["otm", "sarif"]); x.add_argument("--repo-url")
    d = sub.add_parser("diff", help="design delta between two models (Markdown, for a pull request)")
    d.add_argument("base"); d.add_argument("head"); d.add_argument("--title", default="Design delta")
    l = sub.add_parser("lint", help="lint a model")
    l.add_argument("ir")
    args = ap.parse_args(argv)
    if args.cmd == "analyze":
        return analyze(args)
    if args.cmd == "diff":
        from .diff import markdown
        print(markdown(_load_ir(args.base), _load_ir(args.head), args.title), end="")
        return 0
    if args.cmd == "verify":
        return verify(args)
    if args.cmd == "export":
        ir = _load_ir(args.ir)
        if args.format == "otm":
            from .export_otm import to_otm
            print(json.dumps(to_otm(ir, args.repo_url), indent=2))
        else:
            from .export_sarif import to_sarif
            print(json.dumps(to_sarif(ir, args.repo_url), indent=2))
        return 0
    if args.cmd == "lint":
        from .lint import lint
        rows = lint(_load_ir(args.ir))
        for s, r, i, m in rows:
            print(f"{s:8} {r:32} {i:18} {m}")
        return 1 if any(s == "error" for s, *_ in rows) else 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
