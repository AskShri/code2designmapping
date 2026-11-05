"""Renderers: Mermaid DFDs (leveled, budgeted), sequence diagrams per entry point, STRIDE table,
control-path traceability matrix, and the coverage report. All read only the IR."""
import re
from collections import OrderedDict, deque

NODE_BUDGET = 25
EDGE_BUDGET = 40


def _mm(x):
    return x.replace(":", "_")


def _label(s):
    s = " ".join(str(s).split())
    return s.replace('"', "'").replace("[", "(").replace("]", ")").replace(";", ",").replace("#", "").replace("%%", "")[:60]


def _seq_text(s):
    """Text safe inside a sequenceDiagram participant alias or message."""
    s = " ".join(str(s).split())
    return s.replace(";", ",").replace(":", " -").replace("#", "").replace("%%", "")[:60]


class View:
    def __init__(self, ir):
        self.ir = ir
        self.procs = {p["id"]: p for p in ir["processes"]}
        self.nodes = {**self.procs, **{e["id"]: e for e in ir["entities"]}, **{s["id"]: s for s in ir["stores"]}}
        self.stores = {s["id"] for s in ir["stores"]}
        self.ents = {e["id"] for e in ir["entities"]}
        self.sch = {s["id"]: s for s in ir["schemas"]}
        self.ctl = {c["id"]: c for c in ir["controls"]}
        self.bnames = {b["id"]: b["name"] for b in ir["boundaries"]}
        self.children = {}
        for p in self.procs.values():
            if p.get("parent"):
                self.children.setdefault(p["parent"], []).append(p["id"])

    def ancestor_at(self, pid, level):
        p = self.procs[pid]
        while p["level"] > level and p.get("parent"):
            p = self.procs[p["parent"]]
        return p["id"]

    def mm_node(self, nid, label=None):
        n = self.nodes[nid]; lab = _label(label or n["name"])
        if nid.startswith("proc"): return f'{_mm(nid)}(["{lab}"])'
        if nid.startswith("store"): return f'{_mm(nid)}[("{lab}")]'
        return f'{_mm(nid)}["{lab}"]'

    def edge_label(self, f):
        p = f.get("payload") or {}
        name = p.get("name") or (self.sch[p["schema_ref"]]["name"] if p.get("schema_ref") in self.sch else "")
        dc = ",".join(c for c in p.get("data_classes", []) if c not in ("internal", "public"))
        lbl = f'{f["protocol"]}: {name}'.rstrip(": ") + (f" ({dc})" if dc else "")
        return _label(lbl)

    # ---------------------------------------------------------------- DFD
    def dfd(self, level, title, focus=None):
        """Roll flows up to `level`. With focus=<L1 id>, show that process's L2 children and their neighbours."""
        rolled = OrderedDict()
        for f in self.ir["flows"]:
            s = self.ancestor_at(f["source"], level) if f["source"].startswith("proc") else f["source"]
            t = self.ancestor_at(f["target"], level) if f["target"].startswith("proc") else f["target"]
            if focus:
                in_focus = lambda x: x.startswith("proc") and self.ancestor_at(x, 1) == focus
                if not (in_focus(s) or in_focus(t)):
                    continue
                if s.startswith("proc") and not in_focus(s): s = self.ancestor_at(s, 1)
                if t.startswith("proc") and not in_focus(t): t = self.ancestor_at(t, 1)
            if s == t:
                continue
            rolled.setdefault((s, t), []).append(f)
        shown = {s for (s, t) in rolled} | {t for (s, t) in rolled}
        collapsed_note = []
        # budget: collapse lowest-degree entities / stores into summary nodes
        if len(shown) > NODE_BUDGET:
            deg = {}
            for (s, t) in rolled:
                deg[s] = deg.get(s, 0) + 1; deg[t] = deg.get(t, 0) + 1
            for group, label in ((self.ents, "other external services"), (self.stores, "other data stores")):
                members = sorted((x for x in shown if x in group), key=lambda x: (deg.get(x, 0), x))
                while len(shown) > NODE_BUDGET and len(members) > 3:
                    victim = members.pop(0)
                    summary = f"{'ext' if group is self.ents else 'store'}:summary"
                    for key in list(rolled):
                        if victim in key:
                            fs = rolled.pop(key)
                            nk = tuple(summary if k == victim else k for k in key)
                            rolled.setdefault(nk, []).extend(fs)
                    shown.discard(victim); shown.add(summary)
                    collapsed_note.append((summary, label, victim))
            # then collapse L2 processes into their parent if still too big
            if len(shown) > NODE_BUDGET and level == 2:
                pass
        out = [f"%% {title}", "flowchart LR"]
        summary_counts = {}
        for summary, label, _ in collapsed_note:
            summary_counts[summary] = summary_counts.get(summary, 0) + 1
        placed = set()
        for b in self.ir["boundaries"]:
            members = [m for m in b["contains"] if m in shown and m not in placed]
            if not members:
                continue
            out.append(f'  subgraph {_mm(b["id"])}["{_label(b["name"])}"]')
            for m in sorted(members):
                out.append("    " + self._node_with_count(m, level)); placed.add(m)
            out.append("  end")
        for m in sorted(shown - placed):
            if m in summary_counts:
                lab = ("other external services" if m.startswith("ext") else "other data stores") + f" (+{summary_counts[m]})"
                out.append(f'  {_mm(m)}{"[" if m.startswith("ext") else "[("}"{lab}"{"]" if m.startswith("ext") else ")]"}')
            else:
                out.append("  " + self._node_with_count(m, level))
        edges = sorted(rolled.items())
        if len(edges) > EDGE_BUDGET:
            edges = sorted(edges, key=lambda kv: (-len(kv[1]), kv[0]))[:EDGE_BUDGET]
            edges = sorted(edges)
            out.append(f"  %% {len(rolled) - EDGE_BUDGET} lower-weight edges omitted (edge budget {EDGE_BUDGET})")
        for (s, t), fs in edges:
            labels = sorted({self.edge_label(f) for f in fs})[:3]
            lab = "<br/>".join(labels) + ("<br/>..." if len({self.edge_label(f) for f in fs}) > 3 else "")
            dashed = all(f["origin"] == "inferred" for f in fs)
            out.append(f'  {_mm(s)} {"-.->" if dashed else "-->"}|"{lab}"| {_mm(t)}')
        for n in sorted(shown):
            if n in self.nodes and self.nodes[n]["origin"] == "inferred":
                out.append(f"  style {_mm(n)} stroke-dasharray: 5 5")
        for b in self.ir["boundaries"]:
            if any(m in shown for m in b["contains"]):
                out.append(f"  style {_mm(b['id'])} stroke-dasharray: 8 4,fill:none")
        out += ['  subgraph legend["Legend"]', '    lg_e["External entity"]', '    lg_p(["Process"])', '    lg_s[("Data store")]', "  end", "  style legend stroke-dasharray: 8 4,fill:none"]
        return "\n".join(out) + "\n"

    def _node_with_count(self, nid, level):
        if nid.startswith("proc") and self.procs[nid]["level"] < 2 and self.children.get(nid):
            hidden = sum(1 for c in self.children[nid])
            return self.mm_node(nid, f'{self.procs[nid]["name"]} (+{hidden})')
        return self.mm_node(nid)

    # ---------------------------------------------------------------- sequence
    def sequence(self, ep):
        out = [f"%% Control flow: {ep['method']} {ep['path']}", "sequenceDiagram", "  autonumber"]
        client = next((f["source"] for f in self.ir["flows"] if f["target"] == ep["process"] and f["source"] in self.ents), None)
        parts = [client] if client else []
        for c in ep["controls"]:
            parts.append(c)
        lines = []
        seen = set(parts)
        budget = [14]
        def walk(pid, depth):
            if pid not in seen:
                seen.add(pid); parts.append(pid)
            outgoing = [f for f in self.ir["flows"] if f["source"] == pid and f["target"] != client]
            reads = [f for f in self.ir["flows"] if f["target"] == pid and f["source"] in self.stores]
            for f in sorted(outgoing + reads, key=lambda f: (f["evidence"][0]["path"], f["evidence"][0]["start_line"], f["id"])):
                if budget[0] <= 0:
                    return
                if f["target"] == pid:
                    if f["source"] not in seen: seen.add(f["source"]); parts.append(f["source"])
                    lines.append(f'  {_mm(f["source"])}-->>{_mm(pid)}: {self.edge_label(f)}'); budget[0] -= 1; continue
                if f["target"] not in seen:
                    seen.add(f["target"]); parts.append(f["target"])
                lines.append(f'  {_mm(pid)}->>{_mm(f["target"])}: {self.edge_label(f)}'); budget[0] -= 1
                if f["target"].startswith("proc") and depth < 4:
                    walk(f["target"], depth + 1)
                if f["direction"] == "request_response":
                    lines.append(f'  {_mm(f["target"])}-->>{_mm(pid)}: response')
        walk(ep["process"], 0)
        for p in parts:
            name = self.ctl[p]["name"] if p in self.ctl else self.nodes[p]["name"]
            out.append(f"  participant {_mm(p)} as {_seq_text(name)}")
        prev = _mm(client) if client else None
        for c in ep["controls"]:
            if prev: out.append(f"  {prev}->>{_mm(c)}: {_seq_text(ep['method'] + ' ' + ep['path'])} ({self.ctl[c]['kind']})")
            prev = _mm(c)
        if prev: out.append(f"  {prev}->>{_mm(ep['process'])}: dispatch")
        out += lines
        if client: out.append(f"  {_mm(ep['process'])}-->>{_mm(client)}: response")
        return "\n".join(out) + "\n"

    # ---------------------------------------------------------------- STRIDE
    def stride(self):
        S = {"ext": "S R", "proc": "S T R I D E", "store": "T R I D", "flow": "T I D"}
        rows = []
        for e in self.ir["entities"]:
            if e["identity"][-1] == "inbound":
                hint = "inbound caller; verify authentication on every entry point"
            else:
                hint = "outbound dependency; confirm credential storage, TLS and timeouts" + (" (LLM API: check what data is sent)" if e.get("kind") == "llm_api" else "")
            rows.append((1, f'| {e["name"]} | External entity | {S["ext"]} | - | - | - | {hint} |'))
        for s in self.ir["stores"]:
            inb = ", ".join(b["name"] for b in self.ir["boundaries"] if s["id"] in b["contains"]) or "no boundary"
            rows.append((1 if s["data_classes"] else 2, f'| {s["name"]} | Data store | {S["store"]} | {", ".join(s["data_classes"]) or "-"} | in {inb} | encryption at rest: {s["encryption_at_rest"]} | {"holds sensitive data; confirm encryption at rest, access control and retention" if s["data_classes"] else ""} |'))
        for w in self.ir["weaknesses"]:
            rows.append((0, f'| {_label(w["name"])} | Weakness | - | - | - | - | {w["kind"]} at {w["evidence"][0]["path"]}:{w["evidence"][0]["start_line"]} |'))
        for f in self.ir["flows"]:
            if f["protocol"] == "in_process":
                continue
            dc = ", ".join((f.get("payload") or {}).get("data_classes", []))
            hints = []
            if f["target"] in self.ents and any(c in dc for c in ("pii", "financial", "credential", "secret", "health")):
                hints.append("EXIT POINT: sensitive data leaves the system" + (" to an LLM API" if self.nodes[f["target"]].get("kind") == "llm_api" else ""))
            if f["crosses_boundary"] and not f["controls"] and f["source"] in self.ents:
                hints.append("inbound crossing with no control")
            if f["crosses_boundary"] and (f["authentication"] == "unknown" or f["encryption"] == "unknown"):
                hints.append(f"authentication={f['authentication']}, encryption={f['encryption']}: question for the team")
            rows.append((0 if hints and hints[0].startswith("EXIT") else (1 if hints else 2), f'| {_label(self.nodes[f["source"]]["name"])} -> {_label(self.nodes[f["target"]]["name"])} | Data flow | {S["flow"]} | {dc or "-"} | {", ".join(self.bnames[b] for b in f["crosses_boundary"]) or "-"} | {", ".join(self.ctl[c]["name"] for c in f["controls"]) or "none"} | {"; ".join(hints)} |'))
        for p in self.ir["processes"]:
            if p["level"] != 2:
                continue
            eps = [x for x in self.ir["entry_points"] if x["process"] == p["id"]]
            c = ", ".join(self.ctl[x]["name"] for e in eps for x in e["controls"]) if eps else "n/a (internal)"
            rows.append((2, f'| {_label(p["name"])} | Process | {S["proc"]} | - | - | {c or "none"} | {"entry point" if eps else ""} |'))
        head = ["# STRIDE per element", "", "Rows are ordered by priority hint (exit points and weaknesses first).", "",
                "| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls | Priority hint |", "|---|---|---|---|---|---|---|"]
        body = [r for _, r in sorted(rows, key=lambda x: x[0])]
        assets = ["", "## Data assets", "", "| Data class | Processed by | Stored in | Leaves the system via |", "|---|---|---|---|"]
        for a in self.ir["assets"]:
            if a["kind"] != "data":
                continue
            cls = a["data_classes"][0]
            exits = sorted({self.nodes[f["target"]]["name"] for f in self.ir["flows"] if f["target"] in self.ents and cls in (f.get("payload") or {}).get("data_classes", [])})
            assets.append(f'| {cls} | {", ".join(_label(self.nodes[x]["name"]) for x in a["processed_by"][:8]) or "-"}{" ..." if len(a["processed_by"]) > 8 else ""} | {", ".join(_label(self.nodes[x]["name"]) for x in a["held_by"]) or "-"} | {", ".join(exits) or "-"} |')
        return "\n".join(head + body + assets) + "\n"

    # ---------------------------------------------------------------- traceability matrix
    def matrix(self):
        adj = {}
        for f in self.ir["flows"]:
            adj.setdefault(f["source"], []).append((f["target"], f)); adj.setdefault(f["target"], []).append((f["source"], f))
        for k in adj:
            adj[k].sort(key=lambda x: (x[0], x[1]["id"]))
        def sp(starts, goals):
            q = deque((s, [s], []) for s in sorted(starts)); seen = set(starts)
            while q:
                cur, path, fl = q.popleft()
                if cur in goals: return path, fl
                for nx, f in adj.get(cur, []):
                    if nx in seen: continue
                    seen.add(nx); q.append((nx, path + [nx], fl + [f]))
            return None, None
        rows = []
        for ag in self.ir["threat_agents"]:
            for a in self.ir["assets"]:
                path, fl = sp(set(ag["entry"]), set(a["held_by"]))
                if path is None: path, fl = sp(set(ag["entry"]), set(a["processed_by"]))
                if path is None:
                    rows.append((3, ag, a, "no path", "-", "-", "unreachable from this agent")); continue
                crossed = [self.ctl[c]["name"] for f in fl for c in f["controls"]]
                eff = [self.ctl[c]["name"] for f in fl for c in f["controls"] if self.ctl[c]["kind"] not in ag.get("passes_controls", [])]
                unknown = [f for f in fl if f["protocol"] != "in_process" and (f["authentication"] == "unknown" or f["encryption"] == "unknown")]
                if len(path) == 1: verdict, rank = "agent starts at the asset holder: no control can apply", 0
                elif not eff: verdict, rank = "NO EFFECTIVE CONTROL on the path: potential attack path", 0
                elif unknown: verdict, rank = "controlled at entry; " + "; ".join(f'{_label(self.nodes[f["source"]]["name"])} -> {_label(self.nodes[f["target"]]["name"])}: unknown ' + " and ".join(k for k in ("authentication", "encryption") if f[k] == "unknown") for f in unknown[:2]), 1
                else: verdict, rank = "controlled", 2
                shown = _label(self.nodes[path[0]]["name"]) + " (inside)" if len(path) == 1 else " -> ".join(_label(self.nodes[x]["name"]) for x in path)
                rows.append((rank, ag, a, shown, ", ".join(dict.fromkeys(crossed)) or "none", ", ".join(dict.fromkeys(eff)) or "none", verdict))
        rows.sort(key=lambda r: (r[0], r[1]["id"], r[2]["id"]))
        out = ["# Control-path traceability matrix", "", "One row per (threat agent, asset) pair: shortest route over the data flows from where the agent starts to an element holding (else processing) the asset, the controls crossed, the controls effective against that agent, and a verdict. Worst first.", "",
               "| Threat agent | Asset | Shortest path | Controls crossed | Effective controls | Verdict |", "|---|---|---|---|---|---|"]
        for _, ag, a, path, cr, ef, v in rows:
            out.append(f'| {_label(ag["name"])} | {_label(a["name"])} | {path} | {cr} | {ef} | {v} |')
        out += ["", "## Threat agent profiles", "", "| Agent | Access | Location | Starts at | Passes | Goals | Origin |", "|---|---|---|---|---|---|---|"]
        for ag in self.ir["threat_agents"]:
            out.append(f'| {_label(ag["name"])} | {ag["access"]} | {self.bnames.get(ag.get("location"), "outside all boundaries")} | {", ".join(_label(self.nodes[x]["name"]) for x in ag["entry"][:5])}{" ..." if len(ag["entry"]) > 5 else ""} | {", ".join(ag.get("passes_controls", [])) or "-"} | {"; ".join(ag["goals"])} | {ag["origin"]} |')
        out += ["", "## Assets", "", "| Asset | Kind | Data classes | Held by | Processed by |", "|---|---|---|---|---|"]
        for a in self.ir["assets"]:
            out.append(f'| {_label(a["name"])} | {a["kind"]} | {", ".join(a["data_classes"])} | {", ".join(_label(self.nodes[x]["name"]) for x in a["held_by"][:8]) or "-"} | {", ".join(_label(self.nodes[x]["name"]) for x in a["processed_by"][:8]) or "-"}{" ..." if len(a["processed_by"]) > 8 else ""} |')
        return "\n".join(out) + "\n"

    # ---------------------------------------------------------------- report
    def report(self, idx, facts, lint_rows, elapsed):
        ir = self.ir
        out = [f"# code2design report: {ir['provenance']['generated_from']}", "", f"Commit `{ir['provenance']['commit'][:12]}`, tool {ir['provenance']['tool_version']}, {elapsed:.1f}s.", "", "## Coverage", ""]
        out.append("| Language | Files parsed |"); out.append("|---|---|")
        for lang, n in sorted(idx.counts.items()):
            out.append(f"| {lang} | {n} |")
        tests = sum(1 for f in idx.files.values() if f.is_test)
        out.append(f"| (test files skipped) | {tests} |")
        unsup = {}
        for rel, why in idx.unsupported:
            unsup.setdefault(why, 0)
            unsup[why] += 1
        for why, n in sorted(unsup.items()):
            out.append(f"| {why} | {n} (not analyzed) |")
        out += ["", "Detectors that ran: " + ", ".join(ir["provenance"]["detectors"]), ""]
        from collections import Counter
        c = Counter(f["kind"] for f in facts.facts)
        out.append("Facts: " + ", ".join(f"{k} {v}" for k, v in sorted(c.items())))
        out += ["", "## Model", "", "| Collection | Count |", "|---|---|"]
        for k in ("processes", "entities", "stores", "boundaries", "flows", "entry_points", "controls", "weaknesses", "schemas", "assets", "threat_agents", "gaps"):
            out.append(f"| {k} | {len(ir[k])} |")
        out += ["", "## Attack surface", "", "Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write (Black Duck's dependency analysis).", ""]
        by_proto = {}
        for ep in ir["entry_points"]:
            by_proto.setdefault(ep["protocol"], []).append(ep)
        for proto, eps in sorted(by_proto.items()):
            noauth = sum(1 for e in eps if not any(self.ctl[c]["kind"] == "authn" for c in e["controls"]))
            out.append(f"- **{proto}**: {len(eps)} entry points, {noauth} without a detected authn control")
        listeners = [f for f in facts.by_kind("listener")]
        if listeners:
            out.append("- **listeners**: " + ", ".join(sorted({f"{l['file']} port {l.get('port')}{' (TLS)' if l.get('tls') else ''}" for l in listeners})))
        exits = sorted({self.nodes[f["target"]]["name"] for f in ir["flows"] if f["target"] in self.ents and any(c in (f.get("payload") or {}).get("data_classes", []) for c in ("pii", "financial", "credential", "secret", "health"))})
        out.append(f"- **exit points carrying sensitive data**: {', '.join(exits) if exits else 'none detected'}")
        deps = facts.by_kind("dependencies")
        if deps:
            total = sum(len(d["packages"]) for d in deps)
            out.append(f"- **third-party dependencies**: {total} declared in {', '.join(sorted({d['file'] for d in deps}))}; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodeled attack surface")
        out += ["", "### Entry points", "", "| Entry point | Controls |", "|---|---|"]
        for ep in ir["entry_points"][:60]:
            out.append(f'| {ep["method"]} {ep["path"]} | {", ".join(self.ctl[c]["name"] for c in ep["controls"]) or "none"} |')
        if len(ir["entry_points"]) > 60: out.append(f"| ... {len(ir['entry_points']) - 60} more | |")
        out += ["", "### External entities", "", "| Entity | Kind | Host |", "|---|---|---|"]
        for e in ir["entities"]:
            out.append(f'| {_label(e["name"])} | {e["kind"]} | {e.get("host", "-")} |')
        out += ["", "### Data stores", "", "| Store | Technology | Data classes | Boundary |", "|---|---|---|---|"]
        for s in ir["stores"]:
            out.append(f'| {_label(s["name"])} | {s["technology"]} | {", ".join(s["data_classes"]) or "-"} | {", ".join(b["name"] for b in ir["boundaries"] if s["id"] in b["contains"]) or "-"} |')
        out += ["", "## Lint", ""]
        if not lint_rows: out.append("No findings.")
        for sev, rule, nid, msg in lint_rows[:80]:
            out.append(f"- **{sev}** `{rule}` {msg}")
        if len(lint_rows) > 80: out.append(f"- ... {len(lint_rows) - 80} more")
        out += ["", "## Inferred elements (dashed in diagrams)", ""]
        inf = [n for k in ("processes", "entities", "stores", "boundaries", "flows", "threat_agents") for n in ir[k] if n.get("origin") == "inferred"]
        for n in inf[:40]:
            out.append(f"- {n.get('name', n['id'])} (confidence {n.get('confidence')}): {n.get('rationale', '')}")
        out += ["", "## Gaps and questions", ""]
        for g in ir["gaps"][:80]:
            out.append(f"- `{g['kind']}` {g.get('path', '')}{':' + str(g['line']) if g.get('line') else ''}: {g['detail']}")
        if len(ir["gaps"]) > 80: out.append(f"- ... {len(ir['gaps']) - 80} more")
        return "\n".join(out) + "\n"
