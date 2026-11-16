"""Design delta between two IRs, matched by stable ID. Written for a pull-request comment: the
security-relevant changes first, each with the file and line that caused it."""
import json
from .model import BLOCKING_KINDS, SENSITIVE_CLASSES

COLLECTIONS = ("processes", "entities", "stores", "boundaries", "flows", "entry_points", "controls", "weaknesses", "schemas", "assets", "threat_agents")
VOLATILE = ("evidence", "confidence", "rationale")


def _strip(n):
    return {k: v for k, v in n.items() if k not in VOLATILE}


def diff(base, head):
    out = {"added": [], "removed": [], "changed": []}
    names = {}
    for ir in (base, head):
        for k in COLLECTIONS:
            for n in ir.get(k, []):
                names[n["id"]] = (k, n)
    for k in COLLECTIONS:
        b = {n["id"]: n for n in base.get(k, [])}
        h = {n["id"]: n for n in head.get(k, [])}
        for i in sorted(set(h) - set(b)):
            out["added"].append((k, h[i]))
        for i in sorted(set(b) - set(h)):
            out["removed"].append((k, b[i]))
        for i in sorted(set(b) & set(h)):
            if json.dumps(_strip(b[i]), sort_keys=True) != json.dumps(_strip(h[i]), sort_keys=True):
                out["changed"].append((k, b[i], h[i]))
    return out, names


def _nm(i, names):
    if i not in names:
        return i
    n = names[i][1]
    if names[i][0] == "entry_points":
        return f"{n['method']} {n['path']}"
    return n.get("name") or i


def describe(k, n, names):
    nm = lambda i: _nm(i, names)  # noqa: E731
    if k == "flows":
        s = f"Flow: {nm(n['source'])} -> {nm(n['target'])} ({n['protocol']})"
        if n.get("payload"):
            s += f" carrying {', '.join(n['payload'].get('data_classes', []))}"
        if n.get("crosses_boundary"):
            s += f", crosses {len(n['crosses_boundary'])} boundary, controls: {', '.join(nm(c) for c in n['controls']) or 'none'}"
        return s + (" [inferred]" if n.get("origin") == "inferred" else "")
    if k == "entry_points":
        return f"Entry point: {n['method']} {n['path']} ({n.get('exposure', 'unknown')}), controls: {', '.join(nm(c) for c in n['controls']) or 'none'}"
    if k == "weaknesses":
        return f"Weakness ({n['severity']}, {n['cwe']}): {n['name']}"
    if k == "schemas":
        return f"Schema: {n['name']} ({len(n['fields'])} fields: {', '.join(sorted({f['data_class'] for f in n['fields']}))})"
    singular = {"processes": "Process", "entities": "External entity", "stores": "Data store", "boundaries": "Boundary", "controls": "Control", "assets": "Asset", "threat_agents": "Threat agent"}
    return f"{singular.get(k, k)}: {n.get('name', n['id'])}"


def _list_delta(b, h, names):
    add = [x for x in h if x not in b]
    rem = [x for x in b if x not in h]
    return ", ".join([f"+{_nm(x, names)}" for x in add] + [f"-{_nm(x, names)}" for x in rem])


def describe_change(k, b, h, names):
    parts = []
    for f in sorted(set(b) | set(h)):
        if f in VOLATILE or f in ("identity", "id") or json.dumps(b.get(f), sort_keys=True) == json.dumps(h.get(f), sort_keys=True):
            continue
        bv, hv = b.get(f), h.get(f)
        if isinstance(bv, list) and isinstance(hv, list) and all(isinstance(x, str) for x in bv + hv):
            parts.append(f"{f} {_list_delta(bv, hv, names)}")
        elif f == "fields":
            bf, hf = {x["name"]: x for x in bv or []}, {x["name"]: x for x in hv or []}
            parts.append("fields " + ", ".join([f"+{x} ({hf[x]['data_class']})" for x in sorted(set(hf) - set(bf))] + [f"-{x}" for x in sorted(set(bf) - set(hf))] +
                                                [f"{x}: {bf[x]['data_class']} -> {hf[x]['data_class']}" for x in sorted(set(bf) & set(hf)) if bf[x] != hf[x]]))
        elif isinstance(bv, (str, int, float, bool)) or isinstance(hv, (str, int, float, bool)) or bv is None or hv is None:
            parts.append(f"{f}: {bv} -> {hv}")
        else:
            parts.append(f"{f} changed")
    return "; ".join(parts)


def severity(k, n, names, change=None):
    """0 = security-relevant, 1 = attack surface or data, 2 = structure."""
    if k == "weaknesses":
        return 0 if n["severity"] in ("high", "medium") else 1
    if k == "flows" and n["target"].startswith("ext:") and any(c in SENSITIVE_CLASSES for c in (n.get("payload") or {}).get("data_classes", [])):
        return 0
    if k == "entry_points":
        ctl = [names[c][1]["kind"] for c in n["controls"] if c in names]
        if n.get("exposure") == "public" and not any(c in BLOCKING_KINDS for c in ctl):
            return 0
        if change and "controls" in change:
            return 0
        return 1
    if k in ("entities", "stores", "controls", "assets", "threat_agents", "boundaries"):
        return 1
    if k == "flows" and n.get("crosses_boundary"):
        return 1
    if k == "schemas" and change and "data_class" in change or k == "schemas" and any(f["data_class"] in SENSITIVE_CLASSES for f in n.get("fields", [])):
        return 1
    return 2


def markdown(base, head, title="Design delta"):
    d, names = diff(base, head)
    out = [f"## {title}", ""]
    for section, label, sign in (("added", "New", "+"), ("removed", "Removed", "-")):
        items = sorted(d[section], key=lambda kn: (severity(kn[0], kn[1], names), kn[0], kn[1]["id"]))
        out += [f"### {label} ({len(items)})", ""]
        for k, n in items[:60]:
            ev = n["evidence"][0] if n.get("evidence") else {}
            mark = "**" if severity(k, n, names) == 0 else ""
            out.append(f"- {sign} {mark}{describe(k, n, names)}{mark}" + (f"  ({ev.get('path')}:{ev.get('start_line')})" if ev else ""))
        if len(items) > 60:
            out.append(f"- ... {len(items) - 60} more")
        out.append("")
    changed = sorted(((severity(k, h, names, describe_change(k, b, h, names)), k, b, h) for k, b, h in d["changed"]), key=lambda x: (x[0], x[1], x[3]["id"]))
    out += [f"### Changed ({len(changed)})", ""]
    for sev, k, b, h in changed[:60]:
        ev = h["evidence"][0] if h.get("evidence") else {}
        mark = "**" if sev == 0 else ""
        out.append(f"- ~ {mark}{describe(k, h, names)}{mark}: {describe_change(k, b, h, names)}" + (f"  ({ev.get('path')}:{ev.get('start_line')})" if ev else ""))
    if len(changed) > 60:
        out.append(f"- ... {len(changed) - 60} more")
    out.append("")
    touched = {n["id"] for _k, n in d["removed"]} | {b["id"] for _k, b, _h in d["changed"]}
    same = sum(1 for k in ("processes", "entities", "stores", "flows") for n in base.get(k, []) if n["id"] not in touched)
    out.append(f"Unchanged: {same} elements and flows.")
    return "\n".join(out) + "\n"
