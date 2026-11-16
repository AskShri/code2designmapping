"""DFD lint. Structural rules are errors (the IR is inconsistent and the run fails); security rules
are warnings or info (the design has a question the team should answer)."""
from .model import BLOCKING_KINDS, SENSITIVE_CLASSES

COLLECTIONS = ("processes", "entities", "stores", "boundaries", "flows", "entry_points", "controls", "weaknesses", "schemas", "assets", "threat_agents")
WEAKNESS_LINT = {"high": "warning", "medium": "warning", "low": "info", "info": None}


def lint(ir):
    out = []
    ids = {n["id"]: n for k in COLLECTIONS for n in ir[k]}
    procs = {p["id"]: p for p in ir["processes"]}

    def ref(owner, field, target, allowed):
        if target not in ids or not target.startswith(allowed):
            out.append(("error", "dangling-reference", owner["id"], f"{field} of {owner.get('name') or owner['id']} points to missing {target}"))

    def kind(i):
        return i.split(":")[0]
    for k in COLLECTIONS:
        for n in ir[k]:
            if k != "schemas" and not n.get("evidence"):
                out.append(("error", "no-evidence", n["id"], f"{k[:-1]} {n.get('name', n['id'])} has no evidence"))
            if n.get("origin") == "inferred" and "confidence" not in n:
                out.append(("error", "inferred-without-confidence", n["id"], "inferred element lacks confidence"))
    for p in ir["processes"]:
        if p.get("parent"):
            ref(p, "parent", p["parent"], "proc:")
            if p["parent"] in procs and procs[p["parent"]]["level"] >= p["level"]:
                out.append(("error", "level-order", p["id"], f"process {p['name']} (L{p['level']}) has a parent at L{procs[p['parent']]['level']}"))
        elif p["level"] != 0:
            out.append(("error", "orphan-process", p["id"], f"process {p['name']} at L{p['level']} has no parent"))
    for f in ir["flows"]:
        if f["source"] not in ids or f["target"] not in ids:
            out.append(("error", "dangling-flow", f["id"], "flow endpoint missing"))
            continue
        for c in f["controls"]:
            ref(f, "controls", c, "ctl:")
        for b in f["crosses_boundary"]:
            ref(f, "crosses_boundary", b, "bnd:")
        ks = (kind(f["source"]), kind(f["target"]))
        if ks == ("store", "store"):
            out.append(("error", "store-to-store", f["id"], "a process must mediate between stores"))
        if ks == ("ext", "ext"):
            out.append(("error", "entity-to-entity", f["id"], "a process must mediate between external entities"))
        names = f"{ids[f['source']].get('name')} -> {ids[f['target']].get('name')}"
        if f["crosses_boundary"] and kind(f["source"]) == "ext" and not any(ids[c]["kind"] in BLOCKING_KINDS for c in f["controls"] if c in ids):
            out.append(("warning", "unauthenticated-crossing", f["id"], f"inbound flow crosses a boundary without authentication: {names}"))
        if f["crosses_boundary"] and f["protocol"] != "in_process" and (f["authentication"] == "unknown" or f["encryption"] == "unknown") and not (kind(f["source"]) == "ext" and f["authentication"] != "unknown"):
            out.append(("info", "unknown-link-attributes", f["id"], f"{names}: authentication={f['authentication']}, encryption={f['encryption']}"))
        if f.get("payload") and any(c in f["payload"].get("data_classes", []) for c in SENSITIVE_CLASSES) and f["encryption"] == "none" and f["protocol"] != "in_process":
            out.append(("warning", "sensitive-over-plaintext", f["id"], f"{', '.join(f['payload']['data_classes'])} over {f['protocol']} with encryption=none: {names}"))
    deg_in, deg_out = {}, {}
    for f in ir["flows"]:
        deg_out[f["source"]] = deg_out.get(f["source"], 0) + 1
        deg_in[f["target"]] = deg_in.get(f["target"], 0) + 1
    for p in ir["processes"]:
        if p["level"] == 2 and (deg_in.get(p["id"], 0) == 0) != (deg_out.get(p["id"], 0) == 0):
            out.append(("info", "black-hole-or-miracle", p["id"], f"process {p['name']} has only {'inputs' if deg_in.get(p['id']) else 'outputs'}; a detector may be missing"))
    for b in ir["boundaries"]:
        for x in b["contains"]:
            ref(b, "contains", x, ("proc:", "store:", "ext:"))
    for a in ir["assets"]:
        for x in a["held_by"] + a["processed_by"]:
            ref(a, "held_by/processed_by", x, ("proc:", "store:", "ext:"))
    for t in ir["threat_agents"]:
        for x in t["entry"]:
            ref(t, "entry", x, ("proc:", "store:", "ext:"))
        if t.get("location"):
            ref(t, "location", t["location"], "bnd:")
    for ep in ir["entry_points"]:
        ref(ep, "process", ep["process"], "proc:")
        for c in ep["controls"]:
            ref(ep, "controls", c, "ctl:")
        for x in ep.get("reaches", []) + ep.get("call_chain", []):
            ref(ep, "reaches/call_chain", x, ("proc:", "store:", "ext:"))
    for c in ir["controls"]:
        for x in c["applies_to"]:
            ref(c, "applies_to", x, "ep:")
    for w in ir["weaknesses"]:
        for x in w["applies_to"]:
            ref(w, "applies_to", x, ("proc:", "store:", "ext:", "ep:"))
        sev = WEAKNESS_LINT.get(w["severity"])
        if sev:
            ev = w["evidence"][0]
            out.append((sev, f"weakness-{w['kind'].replace('_', '-')}", w["id"], f"{w['cwe']} {w['name']} ({ev['path']}:{ev['start_line']})"))
    order = {"error": 0, "warning": 1, "info": 2}
    return sorted(set(out), key=lambda r: (order[r[0]], r[1], r[2], r[3]))
