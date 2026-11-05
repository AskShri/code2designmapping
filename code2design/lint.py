"""DFD lint: structural rules (errors veto the run) and security rules (warnings)."""


def lint(ir):
    out = []
    ids = {}
    for k in ("processes", "entities", "stores", "boundaries", "flows", "entry_points", "controls", "weaknesses", "schemas", "assets", "threat_agents"):
        for n in ir[k]:
            ids[n["id"]] = n
    kinds = lambda i: i.split(":")[0]
    for k in ("processes", "entities", "stores", "flows", "boundaries", "controls", "weaknesses"):
        for n in ir[k]:
            if not n.get("evidence"):
                out.append(("error", "no-evidence", n["id"], f"{k[:-1]} {n.get('name', n['id'])} has no evidence"))
            if n.get("origin") == "inferred" and "confidence" not in n:
                out.append(("error", "inferred-without-confidence", n["id"], "inferred element lacks confidence"))
    procs = {p["id"] for p in ir["processes"]}
    for f in ir["flows"]:
        if f["source"] not in ids or f["target"] not in ids:
            out.append(("error", "dangling-flow", f["id"], "flow endpoint missing")); continue
        ks = (kinds(f["source"]), kinds(f["target"]))
        if ks == ("store", "store"):
            out.append(("error", "store-to-store", f["id"], "a process must mediate between stores"))
        if ks == ("ext", "ext"):
            out.append(("error", "entity-to-entity", f["id"], "a process must mediate between external entities"))
        if f["crosses_boundary"] and not f["controls"] and kinds(f["source"]) == "ext":
            out.append(("warning", "uncontrolled-crossing", f["id"], f"inbound flow crosses a boundary with no control: {ids[f['source']]['name']} -> {ids[f['target']]['name']}"))
        if f["crosses_boundary"] and f["protocol"] != "in_process" and (f["authentication"] == "unknown" or f["encryption"] == "unknown") and not (kinds(f["source"]) == "ext" and f["authentication"] != "unknown"):
            out.append(("warning", "unknown-link-attributes", f["id"], f"{ids[f['source']]['name']} -> {ids[f['target']]['name']}: authentication={f['authentication']}, encryption={f['encryption']}"))
        if f.get("payload") and any(c in f["payload"]["data_classes"] for c in ("pii", "financial", "credential", "secret", "health")) and f["encryption"] == "none" and f["protocol"] != "in_process":
            out.append(("warning", "sensitive-over-plaintext", f["id"], f"{', '.join(f['payload']['data_classes'])} over {f['protocol']} with encryption=none"))
    deg_in, deg_out = {}, {}
    for f in ir["flows"]:
        deg_out[f["source"]] = deg_out.get(f["source"], 0) + 1; deg_in[f["target"]] = deg_in.get(f["target"], 0) + 1
    for p in ir["processes"]:
        if p["level"] == 2 and (deg_in.get(p["id"], 0) == 0) != (deg_out.get(p["id"], 0) == 0):
            out.append(("info", "black-hole-or-miracle", p["id"], f"process {p['name']} has only {'inputs' if deg_in.get(p['id']) else 'outputs'}; a detector may be missing"))
    for b in ir["boundaries"]:
        for x in b["contains"]:
            if x not in ids:
                out.append(("error", "boundary-member-missing", b["id"], f"boundary {b['name']} lists unknown member {x}"))
    for a in ir["assets"]:
        for x in a["held_by"] + a["processed_by"]:
            if x not in ids:
                out.append(("error", "asset-ref-missing", a["id"], f"asset {a['name']} references unknown {x}"))
    for t in ir["threat_agents"]:
        for x in t["entry"]:
            if x not in ids:
                out.append(("error", "agent-entry-missing", t["id"], f"agent {t['name']} starts at unknown {x}"))
    for ep in ir["entry_points"]:
        if ep["process"] not in procs:
            out.append(("error", "entry-point-process-missing", ep["id"], "entry point process missing"))
    for w in ir["weaknesses"]:
        if w["kind"] in ("plaintext_credentials", "tls_verification_disabled"):
            out.append(("warning", "weakness", w["id"], f"{w['kind']}: {w['name']} ({w['evidence'][0]['path']}:{w['evidence'][0]['start_line']})"))
    sev_order = {"error": 0, "warning": 1, "info": 2}
    return sorted(out, key=lambda r: (sev_order[r[0]], r[1], r[2]))
