"""Design delta between two IRs, by stable ID."""
import json


def _strip(n):
    return {k: v for k, v in n.items() if k not in ("evidence", "confidence", "rationale")}


def diff(base, head):
    out = {"added": [], "removed": [], "changed": []}
    names = {}
    for ir in (base, head):
        for k in ("processes", "entities", "stores", "boundaries", "flows", "entry_points", "controls", "weaknesses", "assets", "threat_agents"):
            for n in ir[k]:
                names[n["id"]] = (k, n)
    for k in ("processes", "entities", "stores", "boundaries", "flows", "entry_points", "controls", "weaknesses", "assets", "threat_agents"):
        b = {n["id"]: n for n in base[k]}; h = {n["id"]: n for n in head[k]}
        for i in sorted(set(h) - set(b)): out["added"].append((k, h[i]))
        for i in sorted(set(b) - set(h)): out["removed"].append((k, b[i]))
        for i in sorted(set(b) & set(h)):
            if json.dumps(_strip(b[i]), sort_keys=True) != json.dumps(_strip(h[i]), sort_keys=True):
                out["changed"].append((k, b[i], h[i]))
    return out, names


def describe(k, n, names):
    def nm(i):
        return names[i][1].get("name") or names[i][1].get("path") or i if i in names else i
    if k == "flows":
        return f"Flow: {nm(n['source'])} -> {nm(n['target'])} {n['protocol']}" + (f" ({', '.join(n['payload']['data_classes'])})" if n.get("payload") else "") + (f" crosses {len(n['crosses_boundary'])} boundary, controls: {', '.join(nm(c) for c in n['controls']) or 'none'}" if n.get("crosses_boundary") else "")
    if k == "entry_points":
        return f"Entry point: {n['method']} {n['path']} controls: {', '.join(nm(c) for c in n['controls']) or 'none'}"
    singular = {"processes": "Process", "entities": "External entity", "stores": "Data store", "boundaries": "Boundary", "controls": "Control", "weaknesses": "Weakness", "assets": "Asset", "threat_agents": "Threat agent"}
    return f"{singular.get(k, k)}: {n.get('name', n['id'])}"


def severity(k, n, names):
    if k == "weaknesses": return 0
    if k == "flows" and n["target"].startswith("ext") and any(c in (n.get("payload") or {}).get("data_classes", []) for c in ("pii", "financial", "credential", "secret")): return 0
    if k in ("entities", "stores"): return 1
    if k == "flows" and n.get("crosses_boundary") and not n.get("controls"): return 1
    if k == "entry_points": return 1
    if k == "controls": return 1
    return 2


def markdown(base, head, title="Design delta"):
    d, names = diff(base, head)
    out = [f"## {title}", ""]
    for section, label in (("added", "New"), ("removed", "Removed")):
        items = sorted(d[section], key=lambda kn: (severity(kn[0], kn[1], names), kn[0], kn[1]["id"]))
        out.append(f"### {label} ({len(items)})"); out.append("")
        for k, n in items[:60]:
            ev = n["evidence"][0] if n.get("evidence") else {}
            out.append(f"- {'+' if section == 'added' else '-'} {describe(k, n, names)}  ({ev.get('path', '')}:{ev.get('start_line', '')})")
        if len(items) > 60: out.append(f"- ... {len(items) - 60} more")
        out.append("")
    out.append(f"### Changed ({len(d['changed'])})"); out.append("")
    for k, b, h in d["changed"][:60]:
        fields = [f for f in set(b) | set(h) if f not in ("evidence", "confidence", "rationale") and json.dumps(b.get(f), sort_keys=True) != json.dumps(h.get(f), sort_keys=True)]
        out.append(f"- ~ {describe(k, h, names)}: {', '.join(sorted(fields))} changed")
    out.append("")
    same = sum(len(base[k]) for k in ("processes", "entities", "stores", "flows")) - len([1 for k, n in d["removed"] if k in ("processes", "entities", "stores", "flows")]) - len([1 for k, b, h in d["changed"] if k in ("processes", "entities", "stores", "flows")])
    out.append(f"Unchanged: {same} elements and flows.")
    return "\n".join(out) + "\n"
