"""Renderers. Every output reads only the IR, so a model edited by overrides renders the same way.

  dfd()        Mermaid flowchart DFDs at L0, L1 and L2 (node and edge budgets, Gane-Sarson-like shapes)
  sequence()   one control-flow sequence diagram per entry point: caller, controls in registration
               order, handler, the modules it calls, and what it reaches
  stride()     STRIDE-per-element table with weaknesses (CWE, severity) first
  matrix()     Black Duck style control-path traceability matrix (threat agent x asset)
  report()     coverage, attack surface, lint, inferred elements and open questions
"""
import heapq
from collections import Counter, OrderedDict
from .model import BLOCKING_KINDS, SENSITIVE_CLASSES, SEVERITY_ORDER, WEAKNESSES, requires_auth

NODE_BUDGET = 25
EDGE_BUDGET = 40
LABEL_MAX = 60
STRIDE_LETTERS = {"S": "Spoofing", "T": "Tampering", "R": "Repudiation", "I": "Information disclosure", "D": "Denial of service", "E": "Elevation of privilege"}
STRIDE_BY_TYPE = {"ext": "S R", "proc": "S T R I D E", "store": "T R I D", "flow": "T I D"}


def _mm(x):
    return x.replace(":", "_")


def _short(s, n=LABEL_MAX):
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[:n - 3].rstrip() + "..."


def _label(s, n=LABEL_MAX):
    """Text safe inside a quoted Mermaid flowchart label."""
    return _short(str(s).replace('"', "'").replace("[", "(").replace("]", ")").replace(";", ",").replace("#", "").replace("%%", "").replace("|", "/")
                  .replace("<", "\u2039").replace(">", "\u203a"), n)     # <id> must not be read as HTML


def _seq_text(s, n=LABEL_MAX):
    """Text safe inside a sequenceDiagram participant alias or message."""
    return _short(str(s).replace(";", ",").replace(":", " -").replace("#", "").replace("%%", "").replace("-->", "to").replace("->", "to")
                  .replace("<", "\u2039").replace(">", "\u203a"), n)


def cell(s):
    """Text safe inside a Markdown table cell."""
    return " ".join(str(s).split()).replace("\\", "\\\\").replace("|", "\\|")


class View:
    def __init__(self, ir):
        self.ir = ir
        self.procs = {p["id"]: p for p in ir["processes"]}
        self.nodes = {**self.procs, **{e["id"]: e for e in ir["entities"]}, **{s["id"]: s for s in ir["stores"]}}
        self.stores = {s["id"] for s in ir["stores"]}
        self.ents = {e["id"] for e in ir["entities"]}
        self.inbound = {e["id"] for e in ir["entities"] if e["identity"][-1] == "inbound"}
        self.sch = {s["id"]: s for s in ir["schemas"]}
        self.ctl = {c["id"]: c for c in ir["controls"]}
        self.eps = {e["id"]: e for e in ir["entry_points"]}
        self.bnames = {b["id"]: b["name"] for b in ir["boundaries"]}
        self.infra_procs = {e["process"] for e in ir["entry_points"] if e.get("infrastructure")} - {e["process"] for e in ir["entry_points"] if not e.get("infrastructure")}
        self.children = {}
        for p in self.procs.values():
            if p.get("parent"):
                self.children.setdefault(p["parent"], []).append(p["id"])
        self.display = self._unique_display()

    def name(self, nid):
        if nid in self.display:
            return self.display[nid]
        n = self.nodes.get(nid) or self.ctl.get(nid) or self.eps.get(nid)
        return (n.get("name") or nid) if n else nid

    def _unique_display(self):
        """Labels are truncated for diagrams; two elements must never render the same label."""
        out, seen = {}, Counter()
        for nid in sorted(self.nodes):
            out[nid] = _label(self.nodes[nid]["name"])
            seen[out[nid]] += 1
        for nid in sorted(self.nodes):
            if seen[out[nid]] > 1:
                out[nid] = _label(self.nodes[nid]["name"], LABEL_MAX - 7) + f" ({nid.split(':')[1][:4]})"
        return out

    def ancestor_at(self, pid, level):
        p = self.procs[pid]
        while p["level"] > level and p.get("parent"):
            p = self.procs[p["parent"]]
        return p["id"]

    def mm_node(self, nid, label=None):
        lab = _label(label) if label else self.display[nid]
        if nid.startswith("proc"):
            return f'{_mm(nid)}(["{lab}"])'
        if nid.startswith("store"):
            return f'{_mm(nid)}[("{lab}")]'
        return f'{_mm(nid)}["{lab}"]'

    def edge_label(self, f, n=LABEL_MAX):
        p = f.get("payload") or {}
        name = p.get("name") or (self.sch[p["schema_ref"]]["name"] if p.get("schema_ref") in self.sch else "")
        dc = ",".join(c for c in p.get("data_classes", []) if c not in ("internal", "public"))
        return _label(f'{f["protocol"]}: {name}'.rstrip(": ") + (f" ({dc})" if dc else ""), n)

    # ================================================================ DFD
    def dfd(self, level, title, focus=None):
        """Flows rolled up to `level`. With focus=<L1 id>: that process's L2 children and their neighbours."""
        rolled = OrderedDict()

        def in_focus(x):
            return x.startswith("proc") and self.ancestor_at(x, 1) == focus
        for f in self.ir["flows"]:
            if f["source"] in self.infra_procs or f["target"] in self.infra_procs:
                continue
            s = self.ancestor_at(f["source"], level) if f["source"] in self.procs else f["source"]
            t = self.ancestor_at(f["target"], level) if f["target"] in self.procs else f["target"]
            if focus:
                if not (in_focus(s) or in_focus(t)):
                    continue
                if s in self.procs and not in_focus(s):
                    s = self.ancestor_at(s, 1)
                if t in self.procs and not in_focus(t):
                    t = self.ancestor_at(t, 1)
            if s != t:
                rolled.setdefault((s, t), []).append(f)
        shown = {s for s, _ in rolled} | {t for _, t in rolled}
        if focus:
            shown.add(focus) if not any(in_focus(x) for x in shown) else None
        summaries = Counter()
        if len(shown) > NODE_BUDGET:          # collapse the least-connected entities, then stores
            deg = Counter()
            for s, t in rolled:
                deg[s] += 1; deg[t] += 1
            for group, summary in ((self.ents - self.inbound, "ext:summary"), (self.stores, "store:summary")):
                members = sorted((x for x in shown if x in group), key=lambda x: (deg[x], x))
                while len(shown) > NODE_BUDGET and len(members) > 3:
                    victim = members.pop(0)
                    for key in [k for k in rolled if victim in k]:
                        fs = rolled.pop(key)
                        rolled.setdefault(tuple(summary if k == victim else k for k in key), []).extend(fs)
                    shown.discard(victim); shown.add(summary); summaries[summary] += 1
        out = [f"%% {_seq_text(title, 120)}", "flowchart LR"]
        placed, emitted = set(), []
        for b in sorted(self.ir["boundaries"], key=lambda b: (-len(b["contains"]), b["id"])):
            members = sorted(m for m in b["contains"] if m in shown and m not in placed)
            if not members:
                continue
            out.append(f'  subgraph {_mm(b["id"])}["{_label(b["name"])}"]')
            for m in members:
                out.append("    " + self._node_with_count(m)); placed.add(m)
            out.append("  end")
            emitted.append(b["id"])
        for m in sorted(shown - placed):
            if m in summaries:
                lab = ("other external services" if m.startswith("ext") else "other data stores") + f" (+{summaries[m]})"
                out.append(f'  {_mm(m)}["{lab}"]' if m.startswith("ext") else f'  {_mm(m)}[("{lab}")]')
            else:
                out.append("  " + self._node_with_count(m))
        edges = sorted(rolled.items())
        if len(edges) > EDGE_BUDGET:
            out.append(f"  %% {len(edges) - EDGE_BUDGET} lower-weight edges omitted (edge budget {EDGE_BUDGET})")
            edges = sorted(sorted(edges, key=lambda kv: (-len(kv[1]), kv[0]))[:EDGE_BUDGET])
        for (s, t), fs in edges:
            labels = sorted({self.edge_label(f, 56) for f in fs})
            lab = "<br/>".join(labels[:3]) + ("<br/>..." if len(labels) > 3 else "")
            arrow = "-.->" if all(f["origin"] == "inferred" for f in fs) else "-->"
            out.append(f'  {_mm(s)} {arrow}|"{lab}"| {_mm(t)}')
        for n in sorted(shown):
            if n in self.nodes and self.nodes[n]["origin"] == "inferred":
                out.append(f"  style {_mm(n)} stroke-dasharray: 5 5")
        for bid in emitted:
            out.append(f"  style {_mm(bid)} stroke-dasharray: 8 4,fill:none")
        out += ['  subgraph legend["Legend"]', '    lg_e["External entity"]', '    lg_p(["Process"])', '    lg_s[("Data store")]', "  end", "  style legend stroke-dasharray: 8 4,fill:none"]
        return "\n".join(out) + "\n"

    def _node_with_count(self, nid):
        if nid in self.procs and self.procs[nid]["level"] < 2 and self.children.get(nid):
            hidden = sum(1 for c in self.children[nid] if c not in self.infra_procs)
            if hidden:
                return self.mm_node(nid, f'{_short(self.procs[nid]["name"], LABEL_MAX - 6)} (+{hidden})')
        return self.mm_node(nid)

    # ================================================================ sequence
    def sequence(self, ep):
        """Caller -> controls (registration order) -> handler -> called modules -> reached stores/services."""
        flows = self.ir["flows"]
        hp = ep["process"]
        client = next((f["source"] for f in sorted(flows, key=lambda f: f["id"]) if f["target"] == hp and f["source"] in self.inbound), None)
        chain = list(ep.get("call_chain") or [hp])
        allowed = set(chain) | set(ep.get("reaches") or [])
        parts = ([client] if client else []) + list(ep["controls"]) + [p for p in chain]
        lines, budget = [], 16
        for pid in chain:
            outgoing = [f for f in flows if f["source"] == pid and f["target"] in allowed and f["target"] != client and f["protocol"] != "in_process"]
            reads = [f for f in flows if f["target"] == pid and f["source"] in self.stores and f["source"] in allowed]
            for f in sorted(outgoing + reads, key=lambda f: (f["evidence"][0]["path"], f["evidence"][0]["start_line"], f["id"])):
                if budget <= 0:
                    break
                other = f["source"] if f["target"] == pid else f["target"]
                if other not in parts:
                    parts.append(other)
                if f["target"] == pid:
                    lines.append(f"  {_mm(pid)}->>{_mm(other)}: read")
                    lines.append(f"  {_mm(other)}-->>{_mm(pid)}: {_seq_text(self.edge_label(f))}")
                else:
                    lines.append(f"  {_mm(pid)}->>{_mm(other)}: {_seq_text(self.edge_label(f))}")
                    if f["direction"] == "request_response" and other not in self.procs:
                        lines.append(f"  {_mm(other)}-->>{_mm(pid)}: response")
                budget -= 1
        out = [f"%% Control flow: {_seq_text(ep['method'] + ' ' + ep['path'], 120)}", "sequenceDiagram", "  autonumber"]
        for p in parts:
            kind = "actor" if p == client else "participant"
            nm = self.ctl[p]["name"] + (" (conditional)" if self.ctl[p].get("conditional") else "") if p in self.ctl else self.name(p)
            out.append(f"  {kind} {_mm(p)} as {_seq_text(nm, 50)}")
        prev = _mm(client) if client else None
        for c in ep["controls"]:
            if prev:
                out.append(f"  {prev}->>{_mm(c)}: {_seq_text(ep['method'] + ' ' + ep['path'], 50)} ({self.ctl[c]['kind']})")
            if self.ctl[c]["kind"] in BLOCKING_KINDS and client:
                out.append(f"  opt {self.ctl[c]['kind']} fails")
                out.append(f"    {_mm(c)}-->>{_mm(client)}: rejected")
                out.append("  end")
            prev = _mm(c)
        if prev:
            out.append(f"  {prev}->>{_mm(hp)}: {'dispatch' if ep['controls'] else _seq_text(ep['method'] + ' ' + ep['path'], 50)}")
        for a, b in zip(chain, chain[1:]):
            if any(f["source"] == a and f["target"] == b for f in flows):
                out.append(f"  {_mm(a)}->>{_mm(b)}: call")
        out += lines
        if client:
            out.append(f"  {_mm(hp)}-->>{_mm(client)}: response")
        return "\n".join(out) + "\n"

    # ================================================================ STRIDE
    def stride(self):
        rows = []
        for w in sorted(self.ir["weaknesses"], key=lambda w: (SEVERITY_ORDER.get(w["severity"], 9), w["kind"], w["id"])):
            ev = w["evidence"][0]
            on = ", ".join(_short(self.name(x), 40) for x in w["applies_to"][:3])
            rows.append((0 if w["severity"] in ("high", "medium") else 3, [w["name"], f"Weakness ({w['severity']})", " ".join(w["stride"]), "-", "-", on or "-",
                                                                         f"{w['cwe']} {WEAKNESSES[w['kind']][3]} at {ev['path']}:{ev['start_line']}"]))
        for e in self.ir["entities"]:
            hint = "inbound caller: verify authentication on every entry point" if e["id"] in self.inbound else \
                "outbound dependency: confirm credential storage, TLS and timeouts" + (" (LLM API: check what data is sent)" if e.get("kind") == "llm_api" else "")
            rows.append((2, [e["name"], "External entity", STRIDE_BY_TYPE["ext"], "-", "-", "-", hint]))
        for s in self.ir["stores"]:
            inb = ", ".join(b["name"] for b in self.ir["boundaries"] if s["id"] in b["contains"]) or "no boundary"
            sens = [c for c in s["data_classes"] if c in SENSITIVE_CLASSES]
            rows.append((1 if sens else 2, [s["name"], "Data store", STRIDE_BY_TYPE["store"], ", ".join(s["data_classes"]) or "-", f"in {inb}", f"encryption at rest: {s['encryption_at_rest']}",
                                            "holds sensitive data: confirm encryption at rest, access control and retention" if sens else ""]))
        for f in self.ir["flows"]:
            if f["protocol"] == "in_process":
                continue
            dc = (f.get("payload") or {}).get("data_classes", [])
            hints, rank = [], 2
            if f["target"] in self.ents and any(c in SENSITIVE_CLASSES for c in dc):
                hints.append("EXIT POINT: sensitive data leaves the system" + (" to an LLM API" if self.nodes[f["target"]].get("kind") == "llm_api" else "")); rank = 0
            if f["crosses_boundary"] and f["source"] in self.inbound and not any(self.ctl[c]["kind"] in BLOCKING_KINDS for c in f["controls"]):
                hints.append("inbound crossing without authentication"); rank = min(rank, 1)
            if f["crosses_boundary"] and (f["authentication"] == "unknown" or f["encryption"] == "unknown"):
                hints.append(f"authentication={f['authentication']}, encryption={f['encryption']}: question for the team"); rank = min(rank, 1)
            rows.append((rank, [f"{self.name(f['source'])} -> {self.name(f['target'])}", "Data flow" + (" (inferred)" if f["origin"] == "inferred" else ""), STRIDE_BY_TYPE["flow"], ", ".join(dc) or "-",
                                ", ".join(self.bnames.get(b, b) for b in f["crosses_boundary"]) or "-", ", ".join(self.ctl[c]["name"] for c in f["controls"]) or "none", "; ".join(hints)]))
        for p in self.ir["processes"]:
            if p["level"] != 2 or p["id"] in self.infra_procs:
                continue
            eps = [x for x in self.ir["entry_points"] if x["process"] == p["id"]]
            c = ", ".join(dict.fromkeys(self.ctl[x]["name"] for e in eps for x in e["controls"])) if eps else "n/a (internal)"
            rows.append((2, [p["name"], "Process", STRIDE_BY_TYPE["proc"], "-", "-", c or "none", "entry point" if eps else ""]))
        head = ["# STRIDE per element", "", "Weaknesses first (by severity), then exit points and unanswered link questions, then the rest. "
                "STRIDE letters: " + ", ".join(f"{k} {v}" for k, v in STRIDE_LETTERS.items()) + ". Risk ratings are left to the team.", "",
                "| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls / applies to | Notes |", "|---|---|---|---|---|---|---|"]
        body = ["| " + " | ".join(cell(x) for x in r) + " |" for _, r in sorted(rows, key=lambda x: x[0])]
        assets = ["", "## Data assets", "", "| Data class | Processed by | Stored in | Leaves the system via |", "|---|---|---|---|"]
        for a in self.ir["assets"]:
            if a["kind"] != "data":
                continue
            cls = a["data_classes"][0]
            exits = sorted({self.name(f["target"]) for f in self.ir["flows"] if f["target"] in self.ents and cls in (f.get("payload") or {}).get("data_classes", [])})
            assets.append("| " + " | ".join(cell(x) for x in [cls, self._names(a["processed_by"]), self._names(a["held_by"]), ", ".join(exits) or "-"]) + " |")
        return "\n".join(head + body + assets) + "\n"

    def _names(self, ids, n=8):
        return (", ".join(self.name(x) for x in ids[:n]) + (f" (+{len(ids) - n})" if len(ids) > n else "")) if ids else "-"

    # ================================================================ traceability matrix
    def _effective(self, f, agent):
        """Controls on a flow that stop this agent: blocking kinds it does not hold, registered unconditionally."""
        return [c for c in f["controls"] if self.ctl[c]["kind"] in BLOCKING_KINDS and self.ctl[c]["kind"] not in agent.get("passes_controls", []) and not self.ctl[c].get("conditional")]

    def _weakest_path(self, agent, goals):
        """Path from the agent's entry to any goal that crosses the fewest effective controls (ties: shortest).
        Flows are walked in either direction (a read is still a route to the data); external entities
        other than the start are not traversed (an attacker does not route through Stripe)."""
        adj = {}
        for f in self.ir["flows"]:
            adj.setdefault(f["source"], []).append((f["target"], f))
            adj.setdefault(f["target"], []).append((f["source"], f))
        starts = sorted(agent["entry"])
        heap = [(0, 0, s, (s,), ()) for s in starts]
        best = {}
        while heap:
            cost, hops, cur, path, fl = heapq.heappop(heap)
            if cur in goals:
                return list(path), list(fl), cost
            if best.get(cur, (99, 99)) <= (cost, hops):
                continue
            best[cur] = (cost, hops)
            for nx, f in sorted(adj.get(cur, []), key=lambda x: (x[0], x[1]["id"])):
                if nx in path or (nx in self.ents and nx not in goals):
                    continue
                c = cost + (1 if self._effective(f, agent) else 0)
                heapq.heappush(heap, (c, hops + 1, nx, path + (nx,), fl + (f["id"],)))
        return None, None, None

    def matrix(self):
        flows = {f["id"]: f for f in self.ir["flows"]}
        rows = []
        for ag in self.ir["threat_agents"]:
            for a in self.ir["assets"]:
                path, fl, cost = self._weakest_path(ag, set(a["held_by"]))
                if path is None:
                    path, fl, cost = self._weakest_path(ag, set(a["processed_by"]))
                if path is None:
                    rows.append((4, ag, a, "no path", "-", "-", "unreachable from this agent over the modelled flows"))
                    continue
                fl = [flows[i] for i in fl]
                eff = list(dict.fromkeys(self.ctl[c]["name"] for f in fl for c in self._effective(f, ag)))
                other = list(dict.fromkeys(self.ctl[c]["name"] for f in fl for c in f["controls"] if self.ctl[c]["name"] not in eff))
                unknown = [f for f in fl if f["protocol"] != "in_process" and (f["authentication"] == "unknown" or f["encryption"] == "unknown")]
                kinds_on_path = {self.ctl[c]["kind"] for f in fl for c in f["controls"]}
                if len(path) == 1:
                    verdict, rank = "agent starts at the asset holder: no control can apply", 0
                elif not eff and "authn" in kinds_on_path and "authz" not in kinds_on_path and "authn" in ag.get("passes_controls", []):
                    verdict, rank = "authentication only: no authorization control detected on the path (check object- and function-level access)", 1
                elif not eff:
                    verdict, rank = "NO BLOCKING CONTROL on the weakest path: potential attack path", 0
                elif unknown:
                    verdict, rank = "blocked at entry; unanswered: " + "; ".join(f"{self.name(f['source'])} -> {self.name(f['target'])} " + " and ".join(k for k in ("authentication", "encryption") if f[k] == "unknown") for f in unknown[:2]), 2
                else:
                    verdict, rank = "blocked", 3
                shown = self.name(path[0]) + " (inside)" if len(path) == 1 else " -> ".join(self.name(x) for x in path)
                rows.append((rank, ag, a, shown, ", ".join(eff) or "none", ", ".join(other) or "none", verdict))
        rows.sort(key=lambda r: (r[0], r[1]["id"], r[2]["id"]))
        out = ["# Control-path traceability matrix", "",
               "One row per (threat agent, asset) pair. The path is the route from where the agent starts to an element holding (else processing) the asset that crosses the fewest blocking controls (authentication, authorization) the agent does not already hold. "
               "Conditionally registered controls do not count as blocking. Other controls on the path (validation, rate limiting, CSRF, headers) are listed separately because they mitigate but do not stop the agent. Worst first.", "",
               "| Threat agent | Asset | Weakest path | Blocking controls | Other controls | Verdict |", "|---|---|---|---|---|---|"]
        for _, ag, a, path, eff, oth, v in rows:
            out.append("| " + " | ".join(cell(x) for x in [ag["name"], a["name"], path, eff, oth, v]) + " |")
        out += ["", "## Threat agent profiles", "", "| Agent | Access | Location | Starts at | Holds | Goals | Origin |", "|---|---|---|---|---|---|---|"]
        for ag in self.ir["threat_agents"]:
            out.append("| " + " | ".join(cell(x) for x in [ag["name"], ag["access"], self.bnames.get(ag.get("location"), "outside all boundaries"), self._names(ag["entry"], 5),
                                                         ", ".join(ag.get("passes_controls", [])) or "-", "; ".join(ag["goals"]), ag["origin"]]) + " |")
        out += ["", "## Assets", "", "| Asset | Kind | Data classes | Held by | Processed by |", "|---|---|---|---|---|"]
        for a in self.ir["assets"]:
            out.append("| " + " | ".join(cell(x) for x in [a["name"], a["kind"], ", ".join(a["data_classes"]), self._names(a["held_by"]), self._names(a["processed_by"])]) + " |")
        return "\n".join(out) + "\n"

    # ================================================================ report
    def report(self, idx, facts, lint_rows):
        ir = self.ir
        prov = ir["provenance"]
        out = [f"# code2design report: {cell(prov['generated_from'])}", "", f"Commit `{prov['commit'][:12]}`, code2design {prov['tool_version']}, IR {ir['version']}.", "", "## Coverage", "",
               "| Language | Files parsed |", "|---|---|"]
        for lang, n in sorted(idx.counts.items()):
            out.append(f"| {lang} | {n} |")
        out.append(f"| (test files, not modelled) | {sum(1 for f in idx.files.values() if f.is_test)} |")
        for why, n in sorted(Counter(why for _rel, why in idx.unsupported).items()):
            out.append(f"| {cell(why)} | {n} (not analyzed) |")
        out += ["", "Detectors: " + ", ".join(prov["detectors"]), "", "Facts: " + ", ".join(f"{k} {v}" for k, v in sorted(Counter(f["kind"] for f in facts.facts).items())),
                "", "## Model", "", "| Collection | Count |", "|---|---|"]
        for k in ("processes", "entities", "stores", "boundaries", "flows", "entry_points", "controls", "weaknesses", "schemas", "assets", "threat_agents", "gaps"):
            out.append(f"| {k} | {len(ir[k])} |")
        out += ["", "## Attack surface", "", "Entry points are where a threat agent first touches the system; exit points are where data leaves it; dependencies are code the team did not write.", ""]
        by_proto = {}
        for ep in ir["entry_points"]:
            by_proto.setdefault(ep["protocol"], []).append(ep)
        for proto, eps in sorted(by_proto.items()):
            main = [e for e in eps if not e.get("infrastructure")]
            noauth = [e for e in main if not requires_auth([self.ctl[c]["kind"] for c in e["controls"]])]
            public = sum(1 for e in noauth if e["exposure"] == "public")
            cond = sum(1 for e in main if any(self.ctl[c].get("conditional") for c in e["controls"]))
            out.append(f"- **{proto}**: {len(main)} entry points, {len(noauth)} without a detected authentication control ({public} of them published outside the deployment)"
                       + (f", {cond} guarded by conditionally registered middleware" if cond else "") + (f"; {len(eps) - len(main)} infrastructure entry points (health, preflight, docs) not counted" if len(eps) != len(main) else ""))
        listeners = facts.by_kind("listener")
        if listeners:
            out.append("- **listeners**: " + ", ".join(sorted({f"{l['file']} port {l.get('port')}{' (TLS)' if l.get('tls') else ''}" for l in listeners})))
        exits = sorted({self.name(f["target"]) for f in ir["flows"] if f["target"] in self.ents and any(c in SENSITIVE_CLASSES for c in (f.get("payload") or {}).get("data_classes", []))})
        out.append(f"- **exit points carrying sensitive data**: {', '.join(exits) if exits else 'none detected'}")
        deps = facts.by_kind("dependencies")
        if deps:
            out.append(f"- **third-party dependencies**: {sum(len(d['packages']) for d in deps)} declared in {', '.join(sorted({d['file'] for d in deps}))}; those recognized as stores, SDKs or auth middleware appear in the model, the rest are unmodelled attack surface")
        if ir["weaknesses"]:
            sev = Counter(w["severity"] for w in ir["weaknesses"])
            out.append("- **weaknesses**: " + ", ".join(f"{sev[s]} {s}" for s in ("high", "medium", "low", "info") if sev[s]) + " (see stride-table.md and findings.sarif)")
        out += ["", "### Entry points", "", "| Entry point | Exposure | Controls (registration order) | Reaches |", "|---|---|---|---|"]
        for ep in ir["entry_points"][:80]:
            out.append("| " + " | ".join(cell(x) for x in [f"{ep['method']} {ep['path']}" + (" (infrastructure)" if ep.get("infrastructure") else ""), ep["exposure"],
                                                         ", ".join(self.ctl[c]["name"] + (" (conditional)" if self.ctl[c].get("conditional") else "") for c in ep["controls"]) or "none",
                                                         self._names([x for x in ep.get("reaches", []) if x not in self.procs], 5)]) + " |")
        if len(ir["entry_points"]) > 80:
            out.append(f"| ... {len(ir['entry_points']) - 80} more | | | |")
        out += ["", "### Weaknesses", ""] + (["None detected."] if not ir["weaknesses"] else ["| Severity | CWE | Weakness | Location |", "|---|---|---|---|"])
        for w in sorted(ir["weaknesses"], key=lambda w: (SEVERITY_ORDER.get(w["severity"], 9), w["kind"], w["id"]))[:80]:
            ev = w["evidence"][0]
            out.append("| " + " | ".join(cell(x) for x in [w["severity"], w["cwe"], w["name"], f"{ev['path']}:{ev['start_line']}"]) + " |")
        out += ["", "### External entities", "", "| Entity | Kind | Host |", "|---|---|---|"]
        for e in ir["entities"]:
            out.append("| " + " | ".join(cell(x) for x in [e["name"], e["kind"], e.get("host", "-")]) + " |")
        out += ["", "### Data stores", "", "| Store | Technology | Data classes | Encryption at rest | Boundary |", "|---|---|---|---|---|"]
        for s in ir["stores"]:
            tech = s["technology"] + (f" (one of {', '.join(s['candidate_engines'])})" if s.get("candidate_engines") else "")
            out.append("| " + " | ".join(cell(x) for x in [s["name"], tech, ", ".join(s["data_classes"]) or "-", s["encryption_at_rest"], ", ".join(b["name"] for b in ir["boundaries"] if s["id"] in b["contains"]) or "-"]) + " |")
        out += ["", "## Lint", ""]
        if not lint_rows:
            out.append("No findings.")
        for sev, rule, _nid, msg in lint_rows[:80]:
            out.append(f"- **{sev}** `{rule}` {msg}")
        if len(lint_rows) > 80:
            out.append(f"- ... {len(lint_rows) - 80} more")
        out += ["", "## Inferred elements (dashed in diagrams)", ""]
        inf = [n for k in ("processes", "entities", "stores", "boundaries", "flows", "threat_agents") for n in ir[k] if n.get("origin") == "inferred"]
        for n in inf[:40]:
            label = n.get("name") or (f"{self.name(n['source'])} -> {self.name(n['target'])}" if "source" in n else n["id"])
            out.append(f"- {label} (confidence {n.get('confidence')}): {n.get('rationale', '')}")
        if len(inf) > 40:
            out.append(f"- ... {len(inf) - 40} more")
        out += ["", "## Gaps and questions", ""]
        for g in ir["gaps"][:80]:
            out.append(f"- `{g['kind']}` {g.get('path', '')}{':' + str(g['line']) if g.get('line') else ''}: {g['detail']}")
        if len(ir["gaps"]) > 80:
            out.append(f"- ... {len(ir['gaps']) - 80} more")
        return "\n".join(out) + "\n"


def flow_diagram_order(ir):
    """Which entry points get a sequence diagram first: public and unauthenticated, then those that
    reach the most stores and external services, then by path."""
    ctl = {c["id"]: c for c in ir["controls"]}

    def key(e):
        authed = requires_auth([ctl[c]["kind"] for c in e["controls"]])
        return (bool(e.get("infrastructure")), e["exposure"] != "public", authed, -len([x for x in e.get("reaches", []) if not x.startswith("proc")]), e["path"], e["method"], e["id"])
    return sorted(ir["entry_points"], key=key)
