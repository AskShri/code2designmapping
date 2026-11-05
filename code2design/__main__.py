"""CLI: python -m code2design analyze <path> [--out DIR] [--name NAME] [--exclude GLOB ...]
         python -m code2design diff <base.ir.json> <head.ir.json>
         python -m code2design lint <ir.json>"""
import argparse, json, os, sys, time
from collections import OrderedDict


def analyze(args):
    from .index import RepoIndex
    from .model import FactStore
    from .detectors import ALL
    from .synth import synthesize
    from .lint import lint
    from .render import View
    t0 = time.time()
    root = os.path.abspath(args.path)
    idx = RepoIndex(root, include=args.include or None, exclude=args.exclude or None)
    facts = FactStore()
    for det in ALL:
        det(idx, facts)
    name = args.name or os.path.basename(root.rstrip("/"))
    ir = synthesize(idx, facts, name=name, scope={"include": args.include or ["**"], "exclude": args.exclude or []})
    rows = lint(ir)
    out = args.out or os.path.join(root, ".code2design")
    os.makedirs(os.path.join(out, "diagrams"), exist_ok=True)
    with open(os.path.join(out, "facts.jsonl"), "w") as fh:
        for f in facts.facts:
            fh.write(json.dumps(f) + "\n")
    with open(os.path.join(out, "model.ir.json"), "w") as fh:
        json.dump(ir, fh, indent=2); fh.write("\n")
    v = View(ir)
    open(os.path.join(out, "diagrams", "dfd-l0.mmd"), "w").write(v.dfd(0, f"L0 context: {name}"))
    open(os.path.join(out, "diagrams", "dfd-l1.mmd"), "w").write(v.dfd(1, f"L1: {name}"))
    l1s = [p for p in ir["processes"] if p["level"] == 1]
    for p in l1s:
        if any(c["parent"] == p["id"] for c in ir["processes"] if c.get("parent")):
            open(os.path.join(out, "diagrams", f"dfd-l2-{p['id'].split(':')[1]}.mmd"), "w").write(v.dfd(2, f"L2: {p['name']}", focus=p["id"]))
    for ep in ir["entry_points"][:40]:
        open(os.path.join(out, "diagrams", f"flow-{ep['id'].split(':')[1]}.mmd"), "w").write(v.sequence(ep))
    open(os.path.join(out, "stride-table.md"), "w").write(v.stride())
    open(os.path.join(out, "traceability-matrix.md"), "w").write(v.matrix())
    open(os.path.join(out, "report.md"), "w").write(v.report(idx, facts, rows, time.time() - t0))
    with open(os.path.join(out, "lint.json"), "w") as fh:
        json.dump([OrderedDict(severity=s, rule=r, id=i, message=m) for s, r, i, m in rows], fh, indent=2); fh.write("\n")
    errors = [r for r in rows if r[0] == "error"]
    print(f"{name}: {len(ir['processes'])} processes, {len(ir['entities'])} entities, {len(ir['stores'])} stores, {len(ir['flows'])} flows, {len(ir['entry_points'])} entry points, {len(ir['controls'])} controls, {len(ir['weaknesses'])} weaknesses, {len(ir['gaps'])} gaps; lint: {len(errors)} errors, {sum(1 for r in rows if r[0] == 'warning')} warnings; {time.time() - t0:.1f}s -> {out}")
    return 1 if errors else 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="code2design")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze"); a.add_argument("path"); a.add_argument("--out"); a.add_argument("--name"); a.add_argument("--include", action="append"); a.add_argument("--exclude", action="append")
    d = sub.add_parser("diff"); d.add_argument("base"); d.add_argument("head"); d.add_argument("--title", default="Design delta")
    l = sub.add_parser("lint"); l.add_argument("ir")
    args = ap.parse_args(argv)
    if args.cmd == "analyze":
        return analyze(args)
    if args.cmd == "diff":
        from .diff import markdown
        print(markdown(json.load(open(args.base)), json.load(open(args.head)), args.title)); return 0
    if args.cmd == "lint":
        from .lint import lint
        rows = lint(json.load(open(args.ir)))
        for s, r, i, m in rows: print(f"{s:8} {r:28} {i:18} {m}")
        return 1 if any(s == "error" for s, *_ in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
