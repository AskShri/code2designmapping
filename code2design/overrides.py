"""Human overrides: .code2design/overrides.yaml, applied after synthesis.

Every entry names an author; an optional expiry date turns the entry into a warning after that
date. Targets are IDs or exact (case-insensitive) element names. Entries that match nothing become
`override_target_missing` gaps so stale annotations are visible.

rename:            [{target, to, author}]
suppress:          [{target, reason, author, expires?}]
set_attribute:     [{target, authentication?, encryption?, encryption_at_rest?, author}]
set_data_class:    [{target, value, author}]            # flow payload or store data class
add_boundary:      [{name, kind, contains: [targets], author}]
add_asset:         [{name, kind, data_classes, held_by: [targets], processed_by: [targets], author}]
add_threat_agent:  [{name, access, entry: [targets], passes_controls?, goals?, location?, author}]
mark_infrastructure: [{target, author}]                 # entry point
"""
import datetime, os
from collections import OrderedDict
import yaml
from .model import sid, span_hash

COLLECTIONS = ("processes", "entities", "stores", "boundaries", "flows", "entry_points", "controls", "weaknesses", "schemas", "assets", "threat_agents")


def load(path):
    if not os.path.exists(path):
        return None, []
    text = open(path, encoding="utf-8").read()
    try:
        doc = yaml.safe_load(text) or {}
    except yaml.YAMLError as e:
        return None, [OrderedDict(kind="unresolved", path=path, detail=f"overrides file could not be parsed: {e}")]
    return (doc, text.splitlines()), []


def apply(ir, overrides, rel_path):
    doc, lines = overrides
    gaps = []
    today = datetime.date.today()
    index = {}
    for k in COLLECTIONS:
        for n in ir[k]:
            index[n["id"]] = (k, n)
    by_name = {}
    for k in COLLECTIONS:
        for n in ir[k]:
            if n.get("name"):
                by_name.setdefault(n["name"].lower(), []).append((k, n))
            if k == "entry_points":
                by_name.setdefault(f"{n['method']} {n['path']}".lower(), []).append((k, n))

    def ev(entry):
        needle = str(entry.get("target") or entry.get("name") or "")
        line = next((i for i, l in enumerate(lines, 1) if needle and needle in l), 1)
        return OrderedDict(path=rel_path, start_line=line, end_line=line, detector="overrides@0.3", content_hash=span_hash(lines[line - 1:line] or [""]))

    def resolve(target):
        if target in index:
            return [index[target]]
        return by_name.get(str(target).lower(), [])

    def check(entry, op):
        if not entry.get("author"):
            gaps.append(OrderedDict(kind="unresolved", path=rel_path, detail=f"{op} override for '{entry.get('target', entry.get('name'))}' has no author; applied anyway"))
        exp = entry.get("expires")
        if exp:
            exp_d = exp if isinstance(exp, datetime.date) else datetime.date.fromisoformat(str(exp))
            if exp_d < today:
                gaps.append(OrderedDict(kind="override_target_missing", path=rel_path, detail=f"{op} override for '{entry.get('target', entry.get('name'))}' expired on {exp_d}; applied, needs re-confirmation"))

    def missing(entry, op):
        gaps.append(OrderedDict(kind="override_target_missing", path=rel_path, detail=f"{op} override targets '{entry.get('target')}' which no longer exists in the model"))

    for e in doc.get("rename") or []:
        check(e, "rename"); hits = resolve(e.get("target"))
        if not hits: missing(e, "rename"); continue
        for k, n in hits:
            n["display_name" if k == "processes" else "name"] = str(e["to"]); n["origin"] = "declared"; n["evidence"] = n["evidence"] + [ev(e)]
    for e in doc.get("set_attribute") or []:
        check(e, "set_attribute"); hits = resolve(e.get("target"))
        if not hits: missing(e, "set_attribute"); continue
        for k, n in hits:
            for attr in ("authentication", "encryption", "encryption_at_rest"):
                if attr in e and attr in n:
                    n[attr] = e[attr]; n["origin"] = "declared"; n["evidence"] = n["evidence"] + [ev(e)]
    for e in doc.get("set_data_class") or []:
        check(e, "set_data_class"); hits = resolve(e.get("target"))
        if not hits: missing(e, "set_data_class"); continue
        for k, n in hits:
            if k == "flows":
                n.setdefault("payload", OrderedDict(name="declared", data_classes=[]))["data_classes"] = sorted(set(n["payload"]["data_classes"]) | {e["value"]})
            elif k == "stores":
                n["data_classes"] = sorted(set(n["data_classes"]) | {e["value"]})
            n["origin"] = "declared"; n["evidence"] = n["evidence"] + [ev(e)]
    for e in doc.get("mark_infrastructure") or []:
        check(e, "mark_infrastructure"); hits = resolve(e.get("target"))
        if not hits: missing(e, "mark_infrastructure"); continue
        for k, n in hits:
            if k == "entry_points": n["infrastructure"] = True
    for e in doc.get("add_boundary") or []:
        check(e, "add_boundary")
        contains = [n["id"] for t in e.get("contains", []) for k, n in resolve(t)]
        if not contains: missing(OrderedDict(target=", ".join(map(str, e.get("contains", [])))), "add_boundary"); continue
        bid = sid("bnd", "boundary", e.get("kind", "network_segment"), e["name"])
        ir["boundaries"].append(OrderedDict(id=bid, identity=["boundary", e.get("kind", "network_segment"), e["name"]], origin="declared", name=e["name"], kind=e.get("kind", "network_segment"), contains=sorted(set(contains)), evidence=[ev(e)]))
    for e in doc.get("add_asset") or []:
        check(e, "add_asset")
        held = sorted({n["id"] for t in e.get("held_by", []) for k, n in resolve(t)}); proc = sorted({n["id"] for t in e.get("processed_by", []) for k, n in resolve(t)})
        aid = sid("asset", "asset", e.get("kind", "data"), e["name"])
        ir["assets"].append(OrderedDict(id=aid, identity=["asset", e.get("kind", "data"), e["name"]], origin="declared", name=e["name"], kind=e.get("kind", "data"), data_classes=list(e.get("data_classes", ["internal"])), held_by=held, processed_by=proc, evidence=[ev(e)]))
    for e in doc.get("add_threat_agent") or []:
        check(e, "add_threat_agent")
        entry = sorted({n["id"] for t in e.get("entry", []) for k, n in resolve(t)})
        if not entry: missing(OrderedDict(target=", ".join(map(str, e.get("entry", [])))), "add_threat_agent"); continue
        aid = sid("agent", "agent", e.get("access", "anonymous"), e["name"])
        ag = OrderedDict(id=aid, identity=["agent", e.get("access", "anonymous"), e["name"]], origin="declared", name=e["name"], access=e.get("access", "anonymous"), entry=entry, passes_controls=list(e.get("passes_controls", [])), goals=list(e.get("goals", [])), evidence=[ev(e)])
        loc = resolve(e["location"]) if e.get("location") else []
        if loc: ag["location"] = loc[0][1]["id"]
        ir["threat_agents"].append(ag)
    # suppress last so the other ops can still target the same elements
    suppressed = set()
    for e in doc.get("suppress") or []:
        check(e, "suppress"); hits = resolve(e.get("target"))
        if not hits: missing(e, "suppress"); continue
        for k, n in hits:
            suppressed.add(n["id"])
    if suppressed:
        for k in COLLECTIONS:
            ir[k] = [n for n in ir[k] if n["id"] not in suppressed]
        ir["flows"] = [f for f in ir["flows"] if f["source"] not in suppressed and f["target"] not in suppressed]
        for b in ir["boundaries"]:
            b["contains"] = [x for x in b["contains"] if x not in suppressed]
        for a in ir["assets"]:
            a["held_by"] = [x for x in a["held_by"] if x not in suppressed]; a["processed_by"] = [x for x in a["processed_by"] if x not in suppressed]
        ir["threat_agents"] = [t for t in ir["threat_agents"] if any(x not in suppressed for x in t["entry"])]
        for t in ir["threat_agents"]:
            t["entry"] = [x for x in t["entry"] if x not in suppressed]
        for c in ir["controls"]:
            c["applies_to"] = [x for x in c["applies_to"] if x not in suppressed]
    from .model import sorted_by_id
    for k in COLLECTIONS:
        ir[k] = sorted_by_id(ir[k])
    ir["gaps"] = ir["gaps"] + gaps
    ir["provenance"]["overrides_file"] = rel_path
    return ir
