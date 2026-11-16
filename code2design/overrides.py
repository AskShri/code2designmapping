"""Human overrides: .code2design/overrides.yaml, applied after synthesis.

Every entry names an author; an optional `expires` date turns it into a gap after that date. Targets
are IDs, exact (case-insensitive) element names, or "METHOD /path" for entry points. Entries that
match nothing become `override_target_missing` gaps, so stale annotations are visible.

rename:              [{target, to, author}]
suppress:            [{target, reason, author, expires?}]
set_attribute:       [{target, authentication?, encryption?, encryption_at_rest?, exposure?, author}]
set_data_class:      [{target, value, author}]            # flow payload or store data class
add_boundary:        [{name, kind, contains: [targets], author}]
add_asset:           [{name, kind, data_classes, held_by: [targets], processed_by: [targets], author}]
add_threat_agent:    [{name, access, entry: [targets], passes_controls?, goals?, location?, author}]
mark_infrastructure: [{target, author}]                   # entry point
"""
import datetime, os
from collections import OrderedDict
import yaml
from .model import sid, span_hash, sorted_by_id

COLLECTIONS = ("processes", "entities", "stores", "boundaries", "flows", "entry_points", "controls", "weaknesses", "schemas", "assets", "threat_agents")
DET = "overrides@0.5"


def load(path):
    if not os.path.exists(path):
        return None, []
    text = open(path, encoding="utf-8").read()
    try:
        doc = yaml.safe_load(text) or {}
    except yaml.YAMLError as e:
        return None, [OrderedDict(kind="unresolved", path=path, detail=f"overrides file could not be parsed: {e}")]
    if not isinstance(doc, dict):
        return None, [OrderedDict(kind="unresolved", path=path, detail="overrides file must be a mapping of operation -> list")]
    return (doc, text.splitlines()), []


def recompute_crossings(ir):
    bnd_of = {}
    for b in ir["boundaries"]:
        for x in b["contains"]:
            bnd_of.setdefault(x, set()).add(b["id"])
    for f in ir["flows"]:
        f["crosses_boundary"] = sorted(bnd_of.get(f["source"], set()) ^ bnd_of.get(f["target"], set()))


def apply(ir, overrides, rel_path, today=None):
    doc, lines = overrides
    gaps = []
    today = today or datetime.date.today()
    index, by_name = {}, {}
    for k in COLLECTIONS:
        for n in ir[k]:
            index[n["id"]] = (k, n)
            if n.get("name"):
                by_name.setdefault(n["name"].lower(), []).append((k, n))
            if k == "entry_points":
                by_name.setdefault(f"{n['method']} {n['path']}".lower(), []).append((k, n))

    def ev(entry):
        needle = str(entry.get("target") or entry.get("name") or "")
        line = next((i for i, l in enumerate(lines, 1) if needle and needle in l), 1)
        return OrderedDict(path=rel_path, start_line=line, end_line=line, detector=DET, content_hash=span_hash(lines[line - 1:line] or [""]))

    def resolve(target):
        if not isinstance(target, (str, int)):
            return []
        if target in index:
            return [index[target]]
        return by_name.get(str(target).lower(), [])

    def check(entry, op):
        if not entry.get("author"):
            gaps.append(OrderedDict(kind="unresolved", path=rel_path, detail=f"{op} override for '{entry.get('target', entry.get('name'))}' has no author; applied anyway"))
        exp = entry.get("expires")
        if exp:
            try:
                exp_d = exp.date() if isinstance(exp, datetime.datetime) else exp if isinstance(exp, datetime.date) else datetime.date.fromisoformat(str(exp))
            except ValueError:
                gaps.append(OrderedDict(kind="unresolved", path=rel_path, detail=f"{op} override has an unreadable expiry '{exp}'"))
                return
            if exp_d < today:
                gaps.append(OrderedDict(kind="override_target_missing", path=rel_path, detail=f"{op} override for '{entry.get('target', entry.get('name'))}' expired on {exp_d}; applied, needs re-confirmation"))

    def missing(entry, op):
        gaps.append(OrderedDict(kind="override_target_missing", path=rel_path, detail=f"{op} override targets '{entry.get('target')}' which does not exist in the model"))

    def declare(n, entry):
        n["origin"] = "declared"
        n.pop("confidence", None); n.pop("rationale", None)
        n["evidence"] = n["evidence"] + [ev(entry)]

    def ops(name):
        v = doc.get(name) or []
        good = [e for e in v if isinstance(e, dict)] if isinstance(v, list) else []
        if not isinstance(v, list) or len(good) != len(v):
            gaps.append(OrderedDict(kind="unresolved", path=rel_path, detail=f"{name}: entries must be mappings; malformed entries were ignored"))
        return good

    for e in ops("rename"):
        check(e, "rename")
        hits = resolve(e.get("target"))
        if not hits:
            missing(e, "rename"); continue
        for _k, n in hits:
            n.setdefault("code_name", n["name"])
            n["name"] = str(e["to"])
            declare(n, e)
    for e in ops("set_attribute"):
        check(e, "set_attribute")
        hits = resolve(e.get("target"))
        if not hits:
            missing(e, "set_attribute"); continue
        for _k, n in hits:
            for attr in ("authentication", "encryption", "encryption_at_rest", "exposure"):
                if attr in e and attr in n:
                    n[attr] = e[attr]
            declare(n, e)
    for e in ops("set_data_class"):
        check(e, "set_data_class")
        hits = resolve(e.get("target"))
        if not hits:
            missing(e, "set_data_class"); continue
        for k, n in hits:
            if k == "flows":
                payload = n.setdefault("payload", OrderedDict(name="declared", data_classes=[]))
                payload["data_classes"] = sorted(set(payload.get("data_classes", [])) | {e["value"]})
            elif k == "stores":
                n["data_classes"] = sorted(set(n["data_classes"]) | {e["value"]})
            else:
                missing(e, "set_data_class"); continue
            declare(n, e)
    for e in ops("mark_infrastructure"):
        check(e, "mark_infrastructure")
        hits = [(k, n) for k, n in resolve(e.get("target")) if k == "entry_points"]
        if not hits:
            missing(e, "mark_infrastructure"); continue
        for _k, n in hits:
            n["infrastructure"] = True
    added_boundary = False
    for e in ops("add_boundary"):
        check(e, "add_boundary")
        contains = sorted({n["id"] for t in e.get("contains", []) for _k, n in resolve(t) if n["id"].startswith(("proc:", "store:", "ext:"))})
        if not contains:
            missing(OrderedDict(target=", ".join(map(str, e.get("contains", [])))), "add_boundary"); continue
        kind = e.get("kind", "network_segment")
        bid = sid("bnd", "boundary", kind, e["name"])
        ir["boundaries"] = [b for b in ir["boundaries"] if b["id"] != bid]
        ir["boundaries"].append(OrderedDict(id=bid, identity=["boundary", kind, e["name"]], origin="declared", name=e["name"], kind=kind, contains=contains, evidence=[ev(e)]))
        added_boundary = True
    for e in ops("add_asset"):
        check(e, "add_asset")
        held = sorted({n["id"] for t in e.get("held_by", []) for _k, n in resolve(t)})
        proc = sorted({n["id"] for t in e.get("processed_by", []) for _k, n in resolve(t)})
        if not held and not proc:
            missing(OrderedDict(target=e.get("name")), "add_asset"); continue
        kind = e.get("kind", "data")
        aid = sid("asset", "asset", kind, e["name"])
        ir["assets"] = [a for a in ir["assets"] if a["id"] != aid]
        ir["assets"].append(OrderedDict(id=aid, identity=["asset", kind, e["name"]], origin="declared", name=e["name"], kind=kind, data_classes=[str(c) for c in (e.get("data_classes") if isinstance(e.get("data_classes"), list) else [])] or ["internal"], held_by=held, processed_by=proc, evidence=[ev(e)]))
    for e in ops("add_threat_agent"):
        check(e, "add_threat_agent")
        entry = sorted({n["id"] for t in e.get("entry", []) for _k, n in resolve(t)})
        if not entry:
            missing(OrderedDict(target=", ".join(map(str, e.get("entry", [])))), "add_threat_agent"); continue
        access = e.get("access", "anonymous")
        aid = sid("agent", "agent", access, e["name"])
        ag = OrderedDict(id=aid, identity=["agent", access, e["name"]], origin="declared", name=e["name"], access=access)
        loc = [n for k, n in resolve(e["location"]) if k == "boundaries"] if e.get("location") else []
        if loc:
            ag["location"] = loc[0]["id"]
        ag.update(entry=entry, passes_controls=list(e.get("passes_controls", [])), goals=list(e.get("goals", [])), evidence=[ev(e)])
        ir["threat_agents"] = [t for t in ir["threat_agents"] if t["id"] != aid] + [ag]
    # suppress last, so the other operations can still name the same elements
    suppressed = set()
    for e in ops("suppress"):
        check(e, "suppress")
        hits = resolve(e.get("target"))
        if not hits:
            missing(e, "suppress"); continue
        for _k, n in hits:
            suppressed.add(n["id"])
            if n["id"].startswith("ep:"):
                suppressed.add(n["process"]) if not any(x["process"] == n["process"] and x["id"] != n["id"] for x in ir["entry_points"]) else None
    if suppressed:
        _remove(ir, suppressed)
    if added_boundary or suppressed:
        recompute_crossings(ir)
    for k in COLLECTIONS:
        ir[k] = sorted_by_id(ir[k])
    ir["gaps"] = _answered_removed(ir) + gaps
    ir["provenance"]["overrides_file"] = rel_path
    return ir


def _answered_removed(ir):
    """Drop the questions an override has answered (encryption at rest of a store, link attributes)."""
    known_rest = {s["name"] for s in ir["stores"] if s["encryption_at_rest"] != "unknown"}
    names = {n["id"]: n["name"] for k in ("processes", "entities", "stores") for n in ir[k]}
    open_links = set()
    for f in ir["flows"]:
        if f["protocol"] != "in_process" and (f["authentication"] == "unknown" or f["encryption"] == "unknown"):
            for end in (f["source"], f["target"]):
                if not end.startswith("proc:"):
                    open_links.add(names.get(end))
    out = []
    for g in ir["gaps"]:
        d = g["detail"]
        if d.startswith("Question: is ") and " encrypted at rest?" in d and d[len("Question: is "):d.index(" encrypted at rest?")] in known_rest:
            continue
        if d.startswith("Question: what is the ") and " of the link to " in d and d.split(" of the link to ", 1)[1].rstrip("?") not in open_links:
            continue
        out.append(g)
    return out


def _remove(ir, gone):
    """Remove elements and every reference to them, then anything left without a reason to exist."""
    procs = {p["id"]: p for p in ir["processes"]}
    changed = True
    while changed:                       # children of a suppressed process go with it
        changed = False
        for p in procs.values():
            if p["id"] not in gone and p.get("parent") in gone:
                gone.add(p["id"]); changed = True
    for k in COLLECTIONS:
        ir[k] = [n for n in ir[k] if n["id"] not in gone]
    ir["flows"] = [f for f in ir["flows"] if f["source"] not in gone and f["target"] not in gone]
    ir["entry_points"] = [e for e in ir["entry_points"] if e["process"] not in gone]
    live_eps = {e["id"] for e in ir["entry_points"]}
    for f in ir["flows"]:
        f["controls"] = [c for c in f["controls"] if c not in gone]
        f["crosses_boundary"] = [b for b in f["crosses_boundary"] if b not in gone]
    for e in ir["entry_points"]:
        e["controls"] = [c for c in e["controls"] if c not in gone]
        e["reaches"] = [x for x in e.get("reaches", []) if x not in gone]
        e["call_chain"] = [x for x in e.get("call_chain", []) if x not in gone]
    for b in ir["boundaries"]:
        b["contains"] = [x for x in b["contains"] if x not in gone]
    ir["boundaries"] = [b for b in ir["boundaries"] if b["contains"]]
    live_b = {b["id"] for b in ir["boundaries"]}
    for f in ir["flows"]:
        f["crosses_boundary"] = [b for b in f["crosses_boundary"] if b in live_b]
    for a in ir["assets"]:
        a["held_by"] = [x for x in a["held_by"] if x not in gone]
        a["processed_by"] = [x for x in a["processed_by"] if x not in gone]
    ir["assets"] = [a for a in ir["assets"] if a["held_by"] or a["processed_by"]]
    for t in ir["threat_agents"]:
        t["entry"] = [x for x in t["entry"] if x not in gone]
        if t.get("location") and t["location"] not in live_b:
            del t["location"]
    ir["threat_agents"] = [t for t in ir["threat_agents"] if t["entry"]]
    for c in ir["controls"]:
        c["applies_to"] = [x for x in c["applies_to"] if x in live_eps]
    for w in ir["weaknesses"]:
        w["applies_to"] = [x for x in w["applies_to"] if x not in gone and (not x.startswith("ep:") or x in live_eps)]
    ir["weaknesses"] = [w for w in ir["weaknesses"] if w["applies_to"]]
