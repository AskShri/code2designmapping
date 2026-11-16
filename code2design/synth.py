"""Synthesis: validated facts + call graph -> the IR (schema/dfd-ir.schema.json).

Every element carries evidence; inferred elements carry confidence and rationale. Nothing here
depends on set iteration order, line numbers in identities, or the clock.
"""
import hashlib, os, re, subprocess
from collections import OrderedDict
from . import __version__, IR_VERSION
from .model import (sid, classify_field, sorted_by_id, evidence, span_hash, auth_scheme, requires_auth,
                    TECH_PROTOCOL, TECH_LABEL, SQL_TECHS, SENSITIVE_CLASSES, WEAKNESSES, BLOCKING_KINDS)
from .routing import Routing
from .index import JS_LANGS

DET = f"synth@{__version__}"
WRAPPER_DIRS = {"src", "lib", "app", "server", "backend", "api", "source", "main", "java", "cmd", "internal", "pkg"}
INFRA_PATH_RX = re.compile(r"(^|/)(_?health[a-z_-]*|_?ready[a-z]*|_?live[a-z]*|metrics|ping|status|version|favicon\.ico|robots\.txt|docs|api-docs|swagger[\w./-]*|openapi[\w./-]*|actuator(/.*)?)/?$", re.I)
USAGE_SKIP = ("client_init", "service_definition", "model_definition", "sdk_import")
MAX_EVIDENCE = 6
DATA_ASSET_NAMES = {"pii": "Personal data (PII)", "financial": "Financial data", "health": "Health data", "credential": "User credentials"}


def repo_name(root, facts):
    """Stable model name: root manifest name, else the git remote's repository name, else the directory."""
    mod = next((m for m in sorted(facts.by_kind("module"), key=lambda m: m["id"]) if m["path"] == "."), None)
    if mod:
        return mod["name"]
    try:
        top = subprocess.run(["git", "-C", root, "rev-parse", "--show-toplevel"], capture_output=True, text=True, timeout=10).stdout.strip()
        url = subprocess.run(["git", "-C", root, "config", "--get", "remote.origin.url"], capture_output=True, text=True, timeout=10).stdout.strip()
        if url and top and os.path.realpath(top) == os.path.realpath(root):    # only the repository's own remote names it
            return re.sub(r"\.git$", "", url.rstrip("/").split("/")[-1].split(":")[-1])
    except Exception:  # noqa: BLE001
        pass
    return os.path.basename(root.rstrip("/"))


def _git_commit(root):
    try:
        # the last commit that touched the analyzed tree: stable for a subdirectory of a larger repository
        out = subprocess.run(["git", "-C", root, "log", "-1", "--format=%H", "--", "."], capture_output=True, text=True, timeout=10).stdout.strip() \
            or subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10).stdout.strip()
        return out if re.fullmatch(r"[0-9a-f]{7,40}", out) else "0" * 40
    except Exception:  # noqa: BLE001
        return "0" * 40


class Synth:
    def __init__(self, idx, facts, cg, name=None, scope=None):
        self.idx, self.facts, self.cg = idx, facts, cg
        self.name = name or repo_name(idx.root, facts)
        self.scope = scope or {}
        self.gaps = []
        self.processes, self.entities, self.stores, self.boundaries, self.flows = {}, {}, {}, {}, {}
        self.entry_points, self.controls, self.weaknesses, self.schemas, self.assets, self.agents = {}, {}, {}, {}, {}, {}
        self.flow_facts = {}          # flow id -> set of fact ids backing it

    # ================================================================== helpers
    def _ev_file(self, path, line=1):
        sf = self.idx.files.get(path)
        return evidence(sf, max(1, min(line, len(sf.lines))), None, DET) if sf else self._ev_synthetic()

    def _ev_fn(self, key):
        sf = self.idx.files[key[0]]
        start = self.cg.functions.get(key, (1, 1))[0]
        return evidence(sf, start, None, DET, symbol=None if key[1].startswith("<") else f"{key[0]}::{key[1].split('#')[0]}")

    def _ev_synthetic(self):
        return OrderedDict(path=".", start_line=1, end_line=1, detector=DET, content_hash=span_hash([self.name]))

    def _add_ev(self, node, evs):
        for e in evs:
            if len(node["evidence"]) >= MAX_EVIDENCE:
                break
            if e not in node["evidence"]:
                node["evidence"].append(e)

    def _proc(self, identity, name, level, parent, module, ev):
        pid = sid("proc", *identity)
        if pid not in self.processes:
            p = OrderedDict(id=pid, identity=list(identity), origin="observed", name=name, level=level, module=module, evidence=list(ev)[:MAX_EVIDENCE])
            if parent:
                p["parent"] = parent
            self.processes[pid] = p
        return pid

    def _flow(self, src, dst, protocol, direction, auth="unknown", enc="unknown", ev=(), controls=(), payload=None, purpose=None, fact_id=None, inferred=None):
        fid = sid("flow", "flow", src, dst, protocol)
        if fact_id:
            self.flow_facts.setdefault(fid, set()).add(fact_id)
        f = self.flows.get(fid)
        if f is None:
            f = OrderedDict(id=fid, identity=["flow", src, dst, protocol], origin="inferred" if inferred else "observed")
            if inferred:
                f["confidence"], f["rationale"] = inferred
            f.update(source=src, target=dst, protocol=protocol, direction=direction, authentication=auth, encryption=enc)
            if purpose:
                f["purpose"] = purpose[:80]
            if payload:
                f["payload"] = payload
            f["crosses_boundary"] = []; f["controls"] = list(dict.fromkeys(controls)); f["evidence"] = list(ev)[:MAX_EVIDENCE]
            self.flows[fid] = f
            return fid
        self._add_ev(f, ev)
        for c in controls:
            if c not in f["controls"]:
                f["controls"].append(c)
        if f["origin"] == "inferred" and not inferred:      # an observed access supersedes the inference
            f["origin"] = "observed"; f.pop("confidence", None); f.pop("rationale", None)
        if f["direction"] != direction and "request_response" not in (f["direction"], direction):
            f["direction"] = "unknown" if "unknown" in (f["direction"], direction) else f["direction"]
        if payload and not f.get("payload"):
            f["payload"] = payload
        if purpose and f.get("purpose") and purpose[:80] < f["purpose"]:
            f["purpose"] = purpose[:80]          # order-independent: the same flow always gets the same purpose
        return fid

    # ================================================================== services and processes
    def _services(self):
        """service name -> context dir from deployment descriptors; exposure per service."""
        idx = self.idx
        hints = sorted(self.facts.by_kind("boundary_hint"), key=lambda f: ({"compose": 0, "k8s": 1}.get(f["source"], 2), f["name"], f["id"]))
        by_ctx, self.exposure, self.hint_of = OrderedDict(), {}, {}
        for f in hints:
            if f["boundary_kind"] != "container" or f.get("holds_store") or f.get("infra"):
                continue
            ctx = f.get("context")
            if ctx is None:
                continue
            ctx = "." if ctx in ("", ".") else ctx.rstrip("/")
            if ctx != "." and not any(p.startswith(ctx + "/") for p in idx.files):
                continue
            name = f["name"]
            if ctx not in by_ctx:
                by_ctx[ctx] = name
                self.hint_of[name] = f
            if f["source"] in ("compose", "k8s"):
                owner = by_ctx[ctx]
                self.exposure[owner] = self.exposure.get(owner, False) or bool(f.get("exposed"))
        strong = {(f.get("context") or ".").rstrip("/") or "." for f in hints if f["source"] in ("compose", "k8s")}
        for ctx in list(by_ctx):   # a Dockerfile nested inside a declared service belongs to that service
            if ctx not in strong and any(ctx.startswith(sc + "/") for sc in strong if sc != "."):
                del by_ctx[ctx]
        self.svcs = OrderedDict((name, ctx) for ctx, name in by_ctx.items())
        self.has_descriptors = any(f["source"] in ("compose", "k8s") for f in hints)
        self.host_to_hint = {}
        for f in hints:
            if f.get("host") and f["boundary_kind"] == "container":      # an Ingress never stands for the workload behind it
                self.host_to_hint.setdefault(f["host"], f)
        self.service_hosts = {f["host"] for f in self.facts.by_kind("service_host")}
        self.env_hosts = {}
        for f in hints:
            for k, v in sorted((f.get("env_hosts") or {}).items()):
                self.env_hosts.setdefault(k, v.split("://")[-1].split(":")[0].split("/")[0])

    def service_of(self, path):
        best = None
        for name, ctx in self.svcs.items():
            if ctx == "." or path.startswith(ctx + "/"):
                if best is None or len(ctx) > len(self.svcs[best]):
                    best = name
        return best

    def _l1_key(self, path):
        svc = self.service_of(path)
        if len(self.svcs) > 1 and svc is not None:
            return (svc, self.svcs[svc])
        base = self.svcs[svc] if svc is not None else "."
        rel = path if base == "." else path[len(base) + 1:]
        segs = rel.split("/")[:-1]
        k = 0
        while k < len(segs) and segs[k] in WRAPPER_DIRS:
            k += 1
        # Java/C# package trees: skip the organisation prefix down to the first directory that holds sources or branches
        if k < len(segs) and self.idx.files[path].lang in ("java", "c_sharp"):
            prefix = (base + "/" if base != "." else "") + "/".join(segs[:k])
            while k < len(segs) - 1:
                here = prefix + ("/" if prefix else "") + segs[k]
                kids = {p[len(here) + 1:].split("/")[0] for p in self.idx.files if p.startswith(here + "/")}
                if len(kids) != 1 or any("/" not in p[len(here) + 1:] for p in self.idx.files if p.startswith(here + "/")):
                    break
                prefix = here; k += 1
        if k >= len(segs):
            return (svc or self.name, base)
        mod = "/".join(([base] if base != "." else []) + segs[:k + 1])
        return (segs[k], mod)

    def _processes(self):
        root_ev = next((m["evidence"] for m in sorted(self.facts.by_kind("module"), key=lambda m: m["id"]) if m["path"] == "."), [self._ev_synthetic()])
        self.root = self._proc(("process", "L0", self.name), self.name, 0, None, ".", root_ev)
        self.l1_of_file, self.l1_ids = {}, OrderedDict()
        for path in self.idx.files:
            self.l1_of_file[path] = self._l1_key(path)
        for path in sorted(self.l1_of_file):
            key = self.l1_of_file[path]
            if key not in self.l1_ids:
                self.l1_ids[key] = self._proc(("process", "L1", key[1], key[0]), key[0], 1, self.root, key[1], [self._ev_file(path)])
        self.module_proc = {}

    def module_process(self, f):
        if f not in self.module_proc:
            nm = os.path.splitext(os.path.basename(f))[0]
            if nm in ("index", "main", "app", "server", "__init__", "routes", "mod"):
                nm = os.path.basename(os.path.dirname(f)) or nm
            self.module_proc[f] = self._proc(("process", "module", f), nm, 2, self.l1_ids[self.l1_of_file[f]], f, [self._ev_file(f)])
        return self.module_proc[f]

    def service_label(self, path):
        return self.l1_of_file[path][0] if len(self.svcs) > 1 else (self.service_of(path) or self.name)

    # ================================================================== entry points and controls
    def _control_id(self, c):
        cid = sid("ctl", "control", c["control_kind"], c["file"], c["name"])
        if cid not in self.controls:
            node = OrderedDict(id=cid, identity=["control", c["control_kind"], c["file"], c["name"]], origin="observed", kind=c["control_kind"], name=c["name"], scope=c["scope"], applies_to=[], evidence=list(c["evidence"]))
            if c.get("conditional"):
                node["conditional"] = True
            self.controls[cid] = node
        else:
            self._add_ev(self.controls[cid], c["evidence"])
            if c.get("conditional"):
                self.controls[cid]["conditional"] = True
        return cid

    def _handler_key(self, ep):
        cg, f = self.cg, ep["file"]
        sf = self.idx.files.get(f)
        if ep.get("handler_scope"):
            return (ep.get("handler_file") or f, f"<{ep['handler_scope']}>", ep.get("handler_class"))
        if ep.get("handler_span"):
            return cg.function_by_span(f, *ep["handler_span"])
        hf = ep.get("handler_file") or f
        if ep.get("handler_symbol") and hf in self.idx.files:
            k = cg.function_at(hf, ep["handler_symbol"]) or cg.function_at(hf, ep["handler_symbol"].split(".")[-1])
            if k:
                return k
        if ep.get("handler_ref") and sf is not None:
            k = cg.resolve_ref(sf, ep["handler_ref"], ep["evidence"][0]["start_line"])
            if k:
                return k
        return None

    def _reach(self, key):
        cg, idx = self.cg, self.idx
        if key is None:
            return []
        if len(key) == 3:                      # scoped pseudo-handlers (gRPC service implementations)
            f, scope, cls = key
            if scope == "<class>" and cls:
                funcs = cg.functions_in(f, cls)
            elif scope == "<package>":
                d = os.path.dirname(f)
                lang = idx.files[f].lang
                funcs = sorted(k for k in cg.functions if not k[1].startswith("<") and idx.files[k[0]].lang == lang and os.path.dirname(k[0]) == d)
                methods = [k for k in funcs if "." in k[1]]
                funcs = methods or funcs     # Go: the service is implemented by receiver methods; main/init are setup
            else:
                funcs = sorted(k for k in cg.functions if k[0] == f)
            out, seen = [], set()
            for k in funcs:
                for r in cg.reach(k, 6):
                    if r not in seen:
                        seen.add(r); out.append(r)
            return out
        return cg.reach(key)

    def _entry_points(self):
        facts, idx = self.facts, self.idx
        routing = Routing(facts, lambda p: self.service_of(p) if p in idx.files or "/" in p or True else None)
        handler_controls = {}
        for c in facts.by_kind("control"):
            if c["scope"] == "handler" and c.get("handler_file") in idx.files:
                if c.get("handler_symbol"):
                    k = self.cg.function_at(c["handler_file"], c["handler_symbol"])
                else:       # a check made inside the handler body: the function that contains it
                    k = self.cg.enclosing(c["handler_file"], c["evidence"][0]["start_line"])
                if k and k[1] != "<module>":
                    handler_controls.setdefault(k, []).append(c)
        self.handler_proc, self.handler_key, self.ep_of_fact, self.ep_facts = {}, {}, {}, {}
        self.handler_by_key, self.handler_labels = {}, {}
        self.listener_tls = {}
        for l in facts.by_kind("listener"):
            svc = self.service_of(l["file"])
            self.listener_tls[svc] = self.listener_tls.get(svc, False) or bool(l["tls"])
        unrooted = {}
        for ep in sorted(facts.by_kind("entry_point"), key=lambda e: e["id"]):
            f = ep["file"]
            if f not in idx.files:
                continue
            proto = ep["protocol"]
            svc_label = self.service_label(f)
            if proto == "http":
                full, ctl_facts, rooted = routing.resolve(ep)
                label = f"{ep['method']} {full}"
                if not rooted and ep["detector"].split("@")[0] in ("js", "py", "go"):
                    unrooted.setdefault((f, ep["router"]), ep)
            else:
                full, ctl_facts = ep["path"], []
                label = f"gRPC {full}" if proto == "grpc" else f"{ep['method']} {full}"
            route_ctls = [facts.get(c) for c in ep.get("route_controls", [])]
            key = self._handler_key(ep)
            hctl = handler_controls.get(key, []) if key and len(key) == 2 else []
            ordered = list(ctl_facts) + route_ctls + hctl
            if ep.get("anonymous"):
                ordered = [c for c in ordered if c["control_kind"] not in BLOCKING_KINDS or c["scope"] == "route"]
                ordered = [c for c in ordered if c["control_kind"] not in BLOCKING_KINDS]
            ctls = list(dict.fromkeys(self._control_id(c) for c in ordered))
            ident = ("entry_point", proto, ep["method"], full, svc_label)
            eid = sid("ep", *ident)
            if eid in self.entry_points:       # the same route declared twice ("" and "/" variants)
                node = self.entry_points[eid]
                self._add_ev(node, ep["evidence"])
                self.ep_of_fact[ep["id"]] = eid
                continue
            hkey = ("key", svc_label) + tuple(key) if key else ("label", svc_label, label)
            pid = self.handler_by_key.get(hkey)
            if pid is None:
                pid = self._proc(("process", "handler", svc_label, label), f"{label} handler", 2, self.l1_ids[self.l1_of_file[f]], f, ep["evidence"])
                self.handler_by_key[hkey] = pid
                self.handler_labels[pid] = []
            else:
                self._add_ev(self.processes[pid], ep["evidence"])
            self.handler_labels[pid].append((ep["method"], full if proto != "grpc" else f"gRPC {full}"))
            node = OrderedDict(id=eid, identity=list(ident), origin="observed", process=pid, protocol=proto, method=ep["method"], path=full, exposure="unknown",
                               controls=ctls, call_chain=[pid], reaches=[], evidence=list(ep["evidence"])[:MAX_EVIDENCE])
            svc = self.service_of(f)
            if self.has_descriptors and svc in self.exposure:
                node["exposure"] = "public" if self.exposure[svc] else "internal"
            if proto in ("amqp", "kafka", "sqs", "pubsub"):
                node["exposure"] = "internal"
            if ep["method"] == "OPTIONS" or (proto == "http" and INFRA_PATH_RX.search(full)) or (proto == "grpc" and "health" in full.lower()):
                node["infrastructure"] = True
            self.entry_points[eid] = node
            self.ep_of_fact[ep["id"]] = eid
            self.ep_facts[eid] = ep
            self.handler_proc[eid] = pid
            self.handler_key[eid] = key
            for c in ctls:
                if eid not in self.controls[c]["applies_to"]:
                    self.controls[c]["applies_to"].append(eid)
        for pid, labels in sorted(self.handler_labels.items()):
            labels = sorted(set(labels))
            if len(labels) < 2:
                continue
            paths = sorted({p for _m, p in labels})
            if len(paths) == 1:
                methods = [m for m, _p in labels]
                self.processes[pid]["name"] = f"{'|'.join(methods)} {paths[0]} handler" if not paths[0].startswith("gRPC") else f"{paths[0]} handler"
            else:
                self.processes[pid]["name"] = f"{labels[0][0]} {paths[0]} handler (+{len(paths) - 1} routes)"
        for (f, router), ep in sorted(unrooted.items()):
            self.gaps.append(OrderedDict(kind="unresolved", path=f, line=ep["evidence"][0]["start_line"], detail=f"router '{router}' in {f} is not mounted from a detected application object; its routes are shown without a mount prefix"))

    # ================================================================== ownership
    def _ownership(self):
        cg = self.cg
        self.owner_of = {}
        for kind in ("store_access", "outbound_call", "schema", "weakness"):
            for fct in self.facts.by_kind(kind):
                if fct.get("file") in self.idx.files and fct.get("operation") not in USAGE_SKIP:
                    self.owner_of[fct["id"]] = cg.enclosing(fct["file"], fct["evidence"][0]["start_line"])
        self.handlers_of_key = {}
        for eid, key in sorted(self.handler_key.items()):
            if key and len(key) == 2:
                lst = self.handlers_of_key.setdefault(key, [])
                if all(self.handler_proc[x] != self.handler_proc[eid] for x in lst):
                    lst.append(eid)
        self.reach = {eid: self._reach(key) for eid, key in sorted(self.handler_key.items())}
        self.reach_set = {eid: set(keys) for eid, keys in self.reach.items()}
        for eid, key in self.handler_key.items():     # scoped handlers own every function of their scope
            if key and len(key) == 3:
                for k in self.reach[eid]:
                    self.handlers_of_key.setdefault(("scoped", eid), [eid])
        self.reached_by = {}
        for eid, keys in sorted(self.reach.items()):
            for k in keys:
                self.reached_by.setdefault(k, []).append(eid)

    def sources_for(self, fct):
        """Processes that perform a usage fact: the handler whose own function contains it, else its module."""
        owner = self.owner_of.get(fct["id"])
        if owner in self.handlers_of_key:
            return [self.handler_proc[eid] for eid in self.handlers_of_key[owner]]
        return [self.module_process(fct["file"])]

    # ================================================================== stores
    def _declared(self):
        self.declared = sorted(self.facts.by_kind("store_access"), key=lambda f: f["id"])
        self.declared = [f for f in self.declared if f["operation"] == "service_definition"]
        self.declared_by_tech = {}
        for f in self.declared:
            self.declared_by_tech.setdefault(f["technology"], []).append(f)
        model_techs = {f["technology"] for f in self.facts.by_kind("store_access") if f["operation"] == "model_definition"}
        concrete = sorted((set(self.declared_by_tech) | model_techs) & (set(SQL_TECHS) - {"sql"}))
        self.single_sql = concrete[0] if len(concrete) == 1 else None

    def store_for(self, tech, logical, ev):
        if tech == "sql" and self.single_sql:
            tech = self.single_sql                 # the one SQL engine the repository declares
        norm = (logical or "").lower()
        if norm and not norm.endswith("*"):
            norm = norm[:-1] if norm.endswith("s") and not norm.endswith("ss") and len(norm) > 3 else norm
        key = sid("store", "store", tech, norm)
        st = self.stores.get(key)
        if st is None:
            name = f"{TECH_LABEL.get(tech, tech)}: {logical}" if logical else TECH_LABEL.get(tech, tech)
            st = OrderedDict(id=key, identity=["store", tech, norm], origin="observed", name=name, technology=tech)
            if logical:
                st["logical_name"] = logical
            st.update(data_classes=[], encryption_at_rest="unknown", evidence=[ev])
            self.stores[key] = st
        else:
            self._add_ev(st, [ev])
        return key

    def _stores(self):
        facts = self.facts
        self._declared()
        usage = [f for f in sorted(facts.by_kind("store_access"), key=lambda f: f["id"])]
        for fct in usage:
            if fct["operation"] == "model_definition":
                self.store_for(fct["technology"], fct.get("logical_name"), fct["evidence"][0])
        for fct in usage:
            op = fct["operation"]
            if op in USAGE_SKIP or fct["file"] not in self.idx.files:
                continue
            st = self.store_for(fct["technology"], fct.get("logical_name"), fct["evidence"][0])
            proto = TECH_PROTOCOL.get(self.stores[st]["technology"], "unknown")
            for src in self.sources_for(fct):
                if op == "read":
                    self._flow(st, src, proto, "one_way", ev=fct["evidence"], purpose=fct.get("method") or "read", fact_id=fct["id"])
                elif op == "write":
                    self._flow(src, st, proto, "one_way", ev=fct["evidence"], purpose=fct.get("method") or "write", fact_id=fct["id"])
                else:
                    self._flow(src, st, proto, "unknown", ev=fct["evidence"], purpose=f"{fct.get('method') or 'access'} (direction unknown)", fact_id=fct["id"])
        # client libraries imported with no resolved call site: the store exists, the access is inferred
        used = {s["technology"] for s in self.stores.values()}
        for fct in usage:
            if fct["operation"] != "client_init" or fct["file"] not in self.idx.files:
                continue
            tech = fct["technology"]
            if tech in ("unknown", "sql") or tech in used or (tech in SQL_TECHS and any(t in used for t in SQL_TECHS)):
                continue
            st = self.store_for(tech, None, fct["evidence"][0])
            self._flow(self.module_process(fct["file"]), st, TECH_PROTOCOL.get(tech, "unknown"), "unknown", ev=fct["evidence"], purpose="client imported",
                       inferred=(0.6, f"the {tech} client library is imported in {fct['file']} but no call site could be resolved"))
        # stores declared by deployment descriptors or IaC
        for fct in self.declared:
            tech = fct["technology"]
            same = [s for s in self.stores.values() if s["technology"] == tech]
            if not same and tech in SQL_TECHS:
                same = [s for s in self.stores.values() if s["technology"] == "sql"]
                for st in same:            # the engine is chosen by configuration: record each candidate
                    engines = st.setdefault("candidate_engines", [])
                    if tech not in engines:
                        engines.append(tech); engines.sort()
            if same:
                for s in same:
                    self._add_ev(s, fct["evidence"])
            else:
                many = len(self.declared_by_tech.get(tech, [])) > 1 and len({f.get("logical_name") for f in self.declared_by_tech[tech]}) > 1 and fct.get("iac")
                st = self.store_for(tech, fct.get("logical_name") if many else None, fct["evidence"][0])
                self.stores[st]["description"] = f"declared as '{fct.get('logical_name')}' in {fct['file']}"
                same = [self.stores[st]]
            if fct.get("encryption_at_rest") in ("yes", "no"):
                for s in same:
                    s["encryption_at_rest"] = fct["encryption_at_rest"]
        # an unnamed store next to named ones of the same technology is an unresolved table/collection
        for st in sorted(self.stores.values(), key=lambda s: s["id"]):
            if not st.get("logical_name") and any(o.get("logical_name") and o["technology"] == st["technology"] for o in self.stores.values()):
                if not any(f["source"] == st["id"] or f["target"] == st["id"] for f in self.flows.values()):
                    continue
                unit = "collection" if st["technology"] == "mongodb" else "key" if st["technology"] == "redis" else "table"
                st["name"] = f"{TECH_LABEL.get(st['technology'], st['technology'])} ({unit} unresolved)"
                self.gaps.append(OrderedDict(kind="unresolved", path=st["evidence"][0]["path"], line=st["evidence"][0]["start_line"],
                                             detail=f"a {st['technology']} access could not be traced to a {unit}; it is shown as a separate store"))
        # drop unnamed stores that nothing touches when named stores of the same technology exist (declared backing instance)
        for sidv in sorted(self.stores):
            st = self.stores[sidv]
            if not st.get("logical_name") and not any(f["source"] == sidv or f["target"] == sidv for f in self.flows.values()) and any(o.get("logical_name") and o["technology"] == st["technology"] for o in self.stores.values()):
                del self.stores[sidv]

    # ================================================================== outbound calls
    def entity_for(self, name, host, kind, ev):
        key = name or host
        eid = sid("ext", "external", key, "outbound")
        e = self.entities.get(eid)
        if e is None:
            e = OrderedDict(id=eid, identity=["external", key, "outbound"], origin="observed", name=name or host, kind=kind or "system")
            if host:
                e["host"] = host
            if name and name != host:
                e["sdk_service"] = name
            e["evidence"] = [ev]
            self.entities[eid] = e
        else:
            self._add_ev(e, [ev])
        return eid

    def _service_target(self, host):
        """A compose/k8s hostname -> ('store', id) | ('process', id) | ('named', label) | None."""
        hint = self.host_to_hint.get(host)
        if hint is None:
            return ("named", f"{host} service") if host in self.service_hosts else None
        if hint.get("holds_store"):
            return ("store_tech", hint["technology"], hint)
        ctx = hint.get("context")
        for (nm, mod), pid in self.l1_ids.items():
            if (ctx and ctx != "." and (mod == ctx or mod.startswith(ctx + "/"))) or nm == hint["name"]:
                return ("process", pid)
        return ("named", f"{hint['name']} service")

    def _store_of_tech(self, tech, hint):
        """The store a deployment host stands for: the only store of that technology, else an unnamed one."""
        tech = self.single_sql if tech in SQL_TECHS and self.single_sql else tech
        same = sorted(s for s in self.stores if self.stores[s]["technology"] in ((tech, "sql") if tech in SQL_TECHS else (tech,)))
        if len(same) == 1:
            self._add_ev(self.stores[same[0]], hint["evidence"])
            return same[0]
        return self.store_for(tech, None, hint["evidence"][0])

    def _grpc_handler(self, l1_pid, hint):
        """The gRPC entry point of a service that a client stub names (CartService), when the repo has it."""
        if not hint:
            return None
        want = hint.lower().replace("service", "")
        for eid in sorted(self.entry_points):
            ep = self.entry_points[eid]
            if ep["protocol"] == "grpc" and self.processes[ep["process"]].get("parent") == l1_pid and ep["path"].lower().replace("service", "") == want:
                return ep["process"]
        return None

    def _outbound(self):
        facts = self.facts
        secret_files = {f["file"] for f in facts.by_kind("config_value") if f["data_class"] == "secret"}
        calls = sorted(facts.by_kind("outbound_call"), key=lambda f: f["id"])
        sdk_of_host = {}          # api.groq.com called with fetch is the same service as the Groq SDK
        for f in calls:
            if f.get("sdk_service") and f.get("host") and not f["host"].startswith(("env:", "svc:", "variable:")):
                sdk_of_host.setdefault(f["host"], (f["sdk_service"], f.get("entity_kind")))
        used_sdk = {(self.service_of(f["file"]), f.get("sdk_service")) for f in calls if f["operation"] != "sdk_import" and f["file"] in self.idx.files}
        for fct in calls:
            if fct["file"] not in self.idx.files:
                continue
            imported_only = fct["operation"] == "sdk_import"
            host, name = fct.get("host"), fct.get("sdk_service")
            if imported_only and (self.service_of(fct["file"]), name) in used_sdk:
                continue
            if host and host.startswith("env:"):
                var = host[4:]
                if re.search(r"(LISTEN|BIND|^PORT$|_PORT$)", var):
                    continue                       # the service's own listen address
                host = self.env_hosts.get(var, host)
            if host and host.startswith("svc:"):
                hint = host[4:].lower()
                hit = next((c for c in (hint, hint + "service", hint.replace("service", "") + "service") if c in self.host_to_hint or c in self.service_hosts), None)
                name = name or (None if hit else f"{fct['host'][4:]} service")
                host = hit
            if host and host.split(":")[0].lower() in ("localhost", "127.0.0.1", "0.0.0.0", "::1", "::", "[::]") and not name:
                continue
            if not name and host in sdk_of_host:
                name, kind_hint = sdk_of_host[host]
            else:
                kind_hint = None
            proto = fct["protocol"] if fct["protocol"] in ("https", "http", "grpc", "smtp") else "unknown"
            enc = "tls" if proto == "https" else "none" if (proto == "http" or fct.get("insecure")) else "unknown"
            auth = "credentials" if (name and fct["file"] in secret_files) else "unknown"
            srcs = [self.module_process(fct["file"])] if imported_only else self.sources_for(fct)
            inferred = (0.6, f"the {name} SDK is imported in {fct['file']} but no call site could be resolved") if imported_only else None
            target = self._service_target(host) if host and not host.startswith(("env:", "variable:")) else None
            if target and target[0] == "store_tech":
                target = ("store", self._store_of_tech(target[1], target[2]))
            for src in srcs:
                if target and target[0] == "store":
                    self._flow(src, target[1], TECH_PROTOCOL.get(self.stores[target[1]]["technology"], "unknown"), "unknown", auth, enc, fct["evidence"], purpose=fct["operation"], fact_id=fct["id"])
                elif target and target[0] == "process":
                    dst = self._grpc_handler(target[1], fct.get("service_hint")) if proto == "grpc" else None
                    if (dst or target[1]) == self.processes[src].get("parent") or (dst or target[1]) == src:
                        continue
                    self._flow(src, dst or target[1], proto if proto != "unknown" else "http", "request_response", auth, enc, fct["evidence"], purpose=f"{fct['operation']}"[:60], fact_id=fct["id"])
                else:
                    nm, h = name, host
                    if target and target[0] == "named":
                        nm = nm or target[1]
                    if h and h.startswith("variable:"):
                        self.gaps.append(OrderedDict(kind="unresolved", path=fct["file"], line=fct["evidence"][0]["start_line"], detail="the target of an outbound call is built from a variable; the host is not resolvable statically"))
                        nm, h = nm or f"Unresolved {proto if proto != 'unknown' else 'HTTP'} target", None
                    elif h and h.startswith("env:"):
                        nm, h = nm or f"Service at ${h[4:]}", None
                    if not h and not nm:
                        nm = f"Unresolved {proto if proto != 'unknown' else 'HTTP'} target"
                    eid = self.entity_for(nm, h, kind_hint or fct.get("entity_kind"), fct["evidence"][0])
                    self._flow(src, eid, proto, "request_response", auth, enc, fct["evidence"], purpose=fct["operation"], fact_id=fct["id"], inferred=inferred)

    def _declared_links(self):
        """An environment variable of service S naming host H declares that S talks to H."""
        for fct in sorted(self.facts.by_kind("declared_link"), key=lambda f: f["id"]):
            svc = fct["source_service"]
            target = self._service_target(fct["target_host"])
            if target is None or target[0] == "named":
                continue
            ctx = self.svcs.get(svc)
            if ctx is not None and len(self.svcs) <= 1:
                kids = sorted(pid for (nm, mod), pid in self.l1_ids.items() if ctx == "." or mod == ctx or mod.startswith(ctx + "/"))
            else:
                kids = sorted(pid for (nm, mod), pid in self.l1_ids.items() if nm == svc)
            if not kids:
                continue
            src = kids[0] if len(kids) == 1 else None
            members = {p for p in self.processes if self.processes[p].get("parent") in kids} | set(kids)
            if target[0] == "store_tech":
                tech = target[1]
                techs = (tech, "sql", self.single_sql) if tech in SQL_TECHS else (tech,)
                tgt_members = {s for s in self.stores if self.stores[s]["technology"] in techs}
                if any((f["source"] in members and f["target"] in tgt_members) or (f["target"] in members and f["source"] in tgt_members) for f in self.flows.values()):
                    continue
                tgt = self._store_of_tech(tech, target[2])
                target = ("store", tgt)
            tgt = target[1]
            tgt_members = {tgt} | ({p for p in self.processes if self.processes[p].get("parent") == tgt} if target[0] == "process" else {s for s in self.stores if self.stores[s]["technology"] == self.stores[tgt]["technology"]} if target[0] == "store" else set())
            if any((f["source"] in members and f["target"] in tgt_members) or (f["target"] in members and f["source"] in tgt_members) for f in self.flows.values()):
                continue
            if src is None:
                src = sorted(members & set(self.l1_ids.values()))[0] if members & set(self.l1_ids.values()) else None
            if src is None or src == tgt:
                continue
            proto = TECH_PROTOCOL.get(self.stores[tgt]["technology"], "unknown") if target[0] == "store" else "unknown"
            self._flow(src, tgt, proto, "unknown", ev=fct["evidence"], purpose=f"declared via {fct.get('via', 'environment')}",
                       inferred=(0.7, f"{fct.get('via', 'an environment variable')} of service '{fct['source_service']}' names host '{fct['target_host']}' in {fct['file']}; no call site was resolved in code"))

    # ================================================================== in-process structure
    def _in_process(self):
        cg, idx = self.cg, self.idx
        self.fact_funcs = {}
        for fid_, owner in sorted(self.owner_of.items()):
            if self.facts.get(fid_)["kind"] in ("store_access", "outbound_call"):
                self.fact_funcs.setdefault(owner, []).append(fid_)
        self.modules_reached = {}      # entry point id -> ordered module processes its handler reaches
        for eid in sorted(self.reach):
            hpid, hkey = self.handler_proc[eid], self.handler_key[eid]
            keys = self.reach[eid]
            chain = []
            for k in keys:
                if k == hkey or k not in self.fact_funcs or k in self.handlers_of_key:
                    continue
                if hkey and len(hkey) == 3:
                    continue                        # scoped handlers own their scope's functions directly
                mp = self.module_process(k[0])
                if mp != hpid:
                    self._flow(hpid, mp, "in_process", "request_response", "none", "none", [self._ev_fn(k)], purpose=f"calls {k[1].split('#')[0]}")
                    if mp not in chain:
                        chain.append(mp)
            if hkey and len(hkey) == 2:
                for k in keys:
                    if k == hkey or k not in self.fact_funcs:
                        continue
                    for nx in sorted(cg.calls.get(k, ())):
                        if nx in self.reach_set[eid] and nx in self.fact_funcs and nx not in self.handlers_of_key and k[0] != nx[0] and k not in self.handlers_of_key:
                            self._flow(self.module_process(k[0]), self.module_process(nx[0]), "in_process", "request_response", "none", "none", [self._ev_fn(nx)], purpose=f"calls {nx[1].split('#')[0]}")
            self.modules_reached[eid] = chain
            self.entry_points[eid]["call_chain"] = [hpid] + chain[:11]
        # scoped (gRPC) handlers: facts of the scope belong to the handler itself
        # modules no handler reaches (background work): link along imports so they are not isolated
        for f in sorted(self.module_proc):
            if any(k in self.reached_by for k in self.fact_funcs if k[0] == f):
                continue
            sf = idx.files[f]
            if sf.lang not in JS_LANGS and sf.lang != "python":
                continue
            for local, spec in sorted(sf.bindings.items()):
                tgt = idx.resolve(sf, spec)
                if tgt and tgt in self.module_proc and tgt != f and re.search(r"\b" + re.escape(local) + r"\b", sf.text):
                    self._flow(self.module_proc[f], self.module_proc[tgt], "in_process", "request_response", "none", "none", [self._ev_file(f)], purpose=f"uses {local}")

    def _reaches(self):
        inbound = set(getattr(self, "inbound_clients", {}).values())
        for eid in sorted(self.entry_points):
            hpid = self.handler_proc[eid]
            keyset = self.reach_set.get(eid, set())
            reached = []
            for fid in sorted(self.flows):
                fl = self.flows[fid]
                if fl["protocol"] == "in_process":
                    continue
                backing = self.flow_facts.get(fid, ())
                hit = fl["source"] == hpid or fl["target"] == hpid or any(self.owner_of.get(x) in keyset for x in backing)
                if not hit:
                    continue
                ends = [fl["target"]] if fl["target"] != hpid else []
                if fl["source"] in self.stores:
                    ends.append(fl["source"])
                for end in ends:
                    if end == hpid or end in inbound:
                        continue
                    if end in self.stores or end in self.entities or (end in self.processes and (self.processes[end]["level"] == 1 or end in self.handler_proc.values())):
                        if end not in reached:
                            reached.append(end)
            self.entry_points[eid]["reaches"] = sorted(reached)

    # ================================================================== scoped handlers own their facts
    def _rehome_scoped(self):
        """gRPC service implementations: accesses made anywhere in the service scope are the handler's."""
        scoped = [eid for eid, k in sorted(self.handler_key.items()) if k and len(k) == 3 and not self.entry_points[eid].get("infrastructure")]
        self.scoped_owner = {}
        for eid in scoped:
            for k in self.reach[eid]:
                self.scoped_owner.setdefault(k, []).append(eid)

    # ================================================================== schemas and payloads
    def _schema_node(self, sc):
        owner = self.owner_of.get(sc["id"])
        if sc["schema_kind"] == "request":
            fn = owner[1].split("#")[0] if owner and not owner[1].startswith("<") else None
            ident = ("schema", sc["file"], "request fields", fn or "<module>")
            name = f"request fields ({fn})" if fn else "request fields"
        else:
            ident = ("schema", sc["file"], sc["name"])
            name = sc["name"]
        scid = sid("sch", *ident)
        node = self.schemas.get(scid)
        if node is None:
            node = OrderedDict(id=scid, identity=list(ident), origin="observed", name=name, fields=[], evidence=[])
            self.schemas[scid] = node
        have = {f["name"] for f in node["fields"]}
        for x in sc["fields"]:
            if x.get("name") and x["name"] not in have:
                have.add(x["name"])
                node["fields"].append(OrderedDict(name=x["name"], type=str(x.get("type") or "unknown")[:30], data_class=classify_field(x["name"])))
        self._add_ev(node, sc["evidence"])
        return scid

    def _schemas(self):
        facts, idx, cg = self.facts, self.idx, self.cg
        self.schema_of_fact = {}
        all_schemas = sorted(facts.by_kind("schema"), key=lambda s: s["id"])
        for sc in all_schemas:
            self.schema_of_fact[sc["id"]] = self._schema_node(sc)
        by_class = {}
        for sc in all_schemas:
            for nm in {sc.get("class_name"), sc["name"]} - {None}:
                by_class.setdefault(nm, []).append(sc)
        validation = [sc for sc in all_schemas if sc["schema_kind"] == "validation" and sc["file"] in idx.files]
        self.ep_schemas = {}
        for eid in sorted(self.entry_points):
            ep = self.ep_facts[eid]
            sf = idx.files[ep["file"]]
            refs = []
            keyset = self.reach_set.get(eid, set())
            # (a) request fields read by the handler or the functions it calls
            for sc in all_schemas:
                if sc["schema_kind"] == "request" and self.owner_of.get(sc["id"]) in keyset and self.owner_of[sc["id"]][1] != "<module>":
                    refs.append(self.schema_of_fact[sc["id"]])
            # (b) validation schemas named in the route registration or in the handler body
            ev = ep["evidence"][0]
            text = "\n".join(sf.lines[ev["start_line"] - 1:ev["end_line"]])
            hk = self.handler_key[eid]
            if hk and len(hk) == 2 and hk in cg.functions and hk[1] != "<module>":
                s_, e_ = cg.functions[hk]
                text += "\n" + "\n".join(idx.files[hk[0]].lines[s_ - 1:e_])
                hsf = idx.files[hk[0]]
            else:
                hsf = sf
            idents = set(re.findall(r"\b[A-Za-z_]\w*\b", text))
            pairs = set(re.findall(r"\b([A-Za-z_]\w*)\.([A-Za-z_]\w*)\b", text))
            for sc in validation:
                n0 = sc["name"].split(".")[0]
                if n0 in ("schema", "request fields"):
                    continue
                hit = False
                for fsf in {sf, hsf}:
                    if sc["file"] == fsf.path and n0 in idents:
                        hit = True
                    elif n0 in idents and n0 in fsf.bindings and idx.resolve(fsf, fsf.bindings[n0]) == sc["file"]:
                        hit = True
                    elif any(member == n0 and root in fsf.bindings and self._follow(fsf, root) == sc["file"] for root, member in pairs):
                        hit = True
                if hit:
                    refs.append(self.schema_of_fact[sc["id"]])
            # (c) parameter types the detector resolved (FastAPI models, Spring @RequestBody)
            for t in ep.get("payload_types") or []:
                for sc in by_class.get(t, [])[:1]:
                    refs.append(self.schema_of_fact[sc["id"]])
            self.ep_schemas[eid] = list(dict.fromkeys(refs))

    def _follow(self, sf, root):
        tgt = self.idx.resolve(sf, sf.bindings[root])
        if tgt and sf.lang in JS_LANGS:
            # index files that re-export: authValidation -> validations/index.js -> auth.validation.js
            rx = self.cg.reexports.get(tgt, {})
            if isinstance(rx.get(root), str):
                return rx[root]
        return tgt

    def _payload(self, eid):
        refs = self.ep_schemas.get(eid) or []
        if not refs:
            return None
        classes = sorted({f["data_class"] for r in refs for f in self.schemas[r]["fields"]} - {"internal", "public"})
        name = self.schemas[refs[0]]["name"] + (f" (+{len(refs) - 1})" if len(refs) > 1 else "")
        return OrderedDict(schema_ref=refs[0], name=name, data_classes=classes or ["internal"])

    def _data_classes(self):
        """Store data classes from their model schemas; request classes follow each handler's own reach."""
        modelled = set()
        for sc in sorted(self.facts.by_kind("schema"), key=lambda s: s["id"]):
            if sc["schema_kind"] not in ("model", "sql"):
                continue
            node = self.schemas[self.schema_of_fact[sc["id"]]]
            classes = {f["data_class"] for f in node["fields"]} - {"internal", "public"}
            want = {sc["name"].lower(), (sc.get("class_name") or sc["name"]).lower(), re.sub(r"(schema|entity|model)$", "", sc["name"].lower())}
            want |= {w[:-1] if w.endswith("s") else w + "s" for w in want}
            for st in self.stores.values():
                ln = (st.get("logical_name") or "").lower()
                if ln and ln in want:
                    modelled.add(st["id"])
                    st["data_classes"] = sorted(set(st["data_classes"]) | classes)
        req_classes = {}
        for eid in sorted(self.entry_points):
            p = self._payload(eid)
            if p:
                req_classes[eid] = ({c for c in p["data_classes"] if c in SENSITIVE_CLASSES}, self.schemas[p["schema_ref"]]["name"])
        for fid in sorted(self.flows):
            fl = self.flows[fid]
            if fl["protocol"] == "in_process" or fl.get("payload") or fl["source"] not in self.processes:
                continue
            if fl["target"] not in self.stores and fl["target"] not in self.entities:
                continue
            classes, sources = set(), set()
            for eid, (cls, sname) in req_classes.items():
                if cls and (fl["source"] == self.handler_proc[eid] or any(self.owner_of.get(x) in self.reach_set[eid] for x in self.flow_facts.get(fid, ()))):
                    classes |= cls
                    sources.add(sname)
            if classes:
                srcs = sorted(sources)
                fl["payload"] = OrderedDict(name=f"from {srcs[0]}" + (f" (+{len(srcs) - 1})" if len(srcs) > 1 else ""), data_classes=sorted(classes))
                if fl["target"] in self.stores and fl["target"] not in modelled:
                    st = self.stores[fl["target"]]
                    st["data_classes"] = sorted(set(st["data_classes"]) | classes)
        for fid in sorted(self.flows):
            fl = self.flows[fid]
            if fl["source"] in self.stores and not fl.get("payload") and self.stores[fl["source"]]["data_classes"]:
                fl["payload"] = OrderedDict(name=f"{self.stores[fl['source']]['name']} record", data_classes=list(self.stores[fl["source"]]["data_classes"]))
            if fl["target"] in self.stores and fl["source"] in self.processes and not fl.get("payload") and fl["target"] in modelled and self.stores[fl["target"]]["data_classes"] and fl["direction"] == "one_way":
                fl["payload"] = OrderedDict(name=f"{self.stores[fl['target']]['name']} record", data_classes=list(self.stores[fl["target"]]["data_classes"]))

    # ================================================================== inbound
    def _inbound(self):
        self.inbound_clients = {}
        specs = {"http": ("http-client", "HTTP client"), "grpc": ("grpc-client", "gRPC client"), "amqp": ("queue-producer", "Message producer"), "kafka": ("queue-producer", "Message producer"),
                 "sqs": ("queue-producer", "Message producer"), "pubsub": ("queue-producer", "Message producer")}
        targeted = {f["target"] for f in self.flows.values() if f["protocol"] != "in_process"}
        for eid in sorted(self.entry_points):
            ep = self.entry_points[eid]
            key, label = specs.get(ep["protocol"], ("http-client", "HTTP client"))
            internal = ep["exposure"] == "internal"
            if internal and ep["protocol"] in ("http", "grpc"):
                parent = self.processes[ep["process"]].get("parent")
                if ep["process"] in targeted or parent in targeted:
                    continue               # callers inside the repository are already modelled
                key, label = "internal-" + key, "Internal " + label
            cid = sid("ext", "external", key, "inbound")
            if cid not in self.entities:
                self.entities[cid] = OrderedDict(id=cid, identity=["external", key, "inbound"], origin="observed", name=label, kind="system", evidence=[])
                self.inbound_clients[key] = cid
            self._add_ev(self.entities[cid], ep["evidence"][:1]) if len(self.entities[cid]["evidence"]) < 3 else None
            kinds = [self.controls[c]["kind"] for c in ep["controls"]]
            auth = auth_scheme([self.controls[c]["name"] for c in ep["controls"] if self.controls[c]["kind"] in BLOCKING_KINDS]) if requires_auth(kinds) else "none"
            svc = self.service_of(self.ep_facts[eid]["file"])
            tls = self.listener_tls.get(svc, False)
            proto = ep["protocol"] if ep["protocol"] != "http" else ("https" if tls else "http")
            self._flow(cid, ep["process"], proto, "request_response" if ep["protocol"] in ("http", "grpc") else "one_way", auth, "tls" if tls else "unknown", ep["evidence"],
                       controls=ep["controls"], payload=self._payload(eid), purpose=f"{ep['method']} {ep['path']}" if ep["protocol"] != "grpc" else f"gRPC {ep['path']}")

    # ================================================================== boundaries
    def _boundaries(self):
        children = {}
        for p in self.processes.values():
            if p.get("parent"):
                children.setdefault(p["parent"], []).append(p["id"])

        def subtree(pid):
            out = [pid]
            for c in sorted(children.get(pid, [])):
                out += subtree(c)
            return out
        hints = sorted((b for b in self.facts.by_kind("boundary_hint") if b["boundary_kind"] == "container"), key=lambda f: ({"compose": 0, "k8s": 1}.get(f["source"], 2), f["name"], f["id"]))
        if any(b["source"] in ("compose", "k8s") and not b.get("holds_store") and not b.get("infra") for b in hints):
            hints = [b for b in hints if b["source"] != "dockerfile"]
        seen_contains = {}
        for b in hints:
            if b.get("infra") and not b.get("holds_store"):
                continue
            if b.get("holds_store"):
                declared = {f.get("host") for f in self.declared_by_tech.get(b["technology"], []) if f.get("host")}
                contains = sorted(s["id"] for s in self.stores.values() if s["technology"] == b["technology"]) if len(declared) <= 1 else []
            else:
                ctx = (b.get("context") or ".").rstrip("/") or "."
                contains = []
                for (nm, mod), pid in self.l1_ids.items():
                    if (len(self.svcs) > 1 and self.svcs.get(nm) == ctx and nm in self.svcs) or (len(self.svcs) <= 1 and (ctx == "." or mod == ctx or mod.startswith(ctx + "/"))):
                        contains += subtree(pid)
                if len(self.svcs) <= 1 and ctx == ".":
                    contains = sorted(self.processes)
            contains = sorted(set(contains))
            if not contains or tuple(contains) in seen_contains:
                continue
            bid = sid("bnd", "boundary", "container", b["name"])
            if bid in self.boundaries:
                continue
            seen_contains[tuple(contains)] = bid
            self.boundaries[bid] = OrderedDict(id=bid, identity=["boundary", "container", b["name"]], origin="observed", name=f"container: {b['name']}", kind="container", contains=contains, evidence=list(b["evidence"]))
        placed = {x for b in self.boundaries.values() for x in b["contains"]}
        unplaced = sorted(p for p in self.processes if p not in placed)
        if unplaced:
            bid = sid("bnd", "boundary", "repository", self.name)
            self.boundaries[bid] = OrderedDict(id=bid, identity=["boundary", "repository", self.name], origin="inferred", confidence=0.5,
                                               rationale="no container, Kubernetes or IaC boundary covers these processes; the repository itself is used as the trust boundary",
                                               name=f"repository: {self.name}", kind="repository", contains=unplaced, evidence=[self._ev_synthetic()])
            if not hints:
                self.gaps.append(OrderedDict(kind="no_boundary_info", detail="no docker compose, Dockerfile, Kubernetes or Terraform descriptors were found; the repository is the only trust boundary"))
        self._recompute_crossings()

    def _recompute_crossings(self):
        bnd_of = {}
        for b in self.boundaries.values():
            for x in b["contains"]:
                bnd_of.setdefault(x, set()).add(b["id"])
        for fl in self.flows.values():
            fl["crosses_boundary"] = sorted(bnd_of.get(fl["source"], set()) ^ bnd_of.get(fl["target"], set()))

    # ================================================================== weaknesses, assets, agents
    def _process_for_file(self, f, line=None):
        if f in self.idx.files and line is not None:
            owner = self.cg.enclosing(f, line)
            if owner in self.handlers_of_key:
                return [self.handler_proc[eid] for eid in self.handlers_of_key[owner]]
        if f in self.module_proc:
            return [self.module_proc[f]]
        if f in self.l1_of_file:
            return [self.l1_ids[self.l1_of_file[f]]]
        return [self.root]

    def _weakness(self, kind, ident, name, applies, ev):
        cwe, severity, stride, _title = WEAKNESSES[kind]
        wid = sid("wk", "weakness", kind, *ident)
        if wid not in self.weaknesses:
            self.weaknesses[wid] = OrderedDict(id=wid, identity=["weakness", kind, *ident], origin="observed", kind=kind, name=name, severity=severity, cwe=cwe, stride=list(stride),
                                               applies_to=sorted(set(applies)), evidence=list(ev)[:MAX_EVIDENCE])
        return wid

    def _weaknesses(self):
        ordinal = {}
        for w in sorted(self.facts.by_kind("weakness"), key=lambda f: (f["file"], f["weakness_kind"], f["name"], f["evidence"][0]["start_line"], f["id"])):
            if w["weakness_kind"] not in WEAKNESSES:
                continue
            k = (w["weakness_kind"], w["file"], w["name"])
            ordinal[k] = ordinal.get(k, 0) + 1
            applies = self._process_for_file(w["file"], w["evidence"][0]["start_line"])
            if w["weakness_kind"] in ("public_data_store", "unencrypted_data_store"):
                applies = sorted(s["id"] for s in self.stores.values() if any(e["path"] == w["file"] and e["start_line"] == w["evidence"][0]["start_line"] for e in s["evidence"])) or applies
            self._weakness(w["weakness_kind"], (w["file"], w["name"], str(ordinal[k])), w["name"], applies, w["evidence"])
        for eid in sorted(self.entry_points):
            ep = self.entry_points[eid]
            if ep["protocol"] != "http" or ep.get("infrastructure") or ep["exposure"] == "internal":
                continue
            if not requires_auth([self.controls[c]["kind"] for c in ep["controls"]]):
                self._weakness("unauthenticated_entry_point", (eid,), f"no authentication control detected on {ep['method']} {ep['path']}", [eid], ep["evidence"])

    def _assets(self):
        for cv in sorted(self.facts.by_kind("config_value"), key=lambda f: f["id"]):
            if cv["data_class"] != "secret":
                continue
            holders = self._process_for_file(cv["file"])
            aid = sid("asset", "asset", "credential", cv["name"])
            a = self.assets.get(aid)
            if a is None:
                self.assets[aid] = OrderedDict(id=aid, identity=["asset", "credential", cv["name"]], origin="observed", name=f"Secret {cv['name']}", kind="credential", data_classes=["secret"],
                                               held_by=sorted(holders), processed_by=sorted(holders), evidence=[cv["evidence"][0]])
            else:
                a["held_by"] = sorted(set(a["held_by"]) | set(holders)); a["processed_by"] = sorted(set(a["processed_by"]) | set(holders))
                self._add_ev(a, cv["evidence"][:1])
        for cls in ("pii", "financial", "health", "credential"):
            held = sorted(s["id"] for s in self.stores.values() if cls in s["data_classes"])
            proc = sorted({fl[end] for fl in self.flows.values() if cls in (fl.get("payload") or {}).get("data_classes", []) for end in ("source", "target") if fl[end] in self.processes})
            if not held and not proc:
                continue
            ev = [sc["evidence"][0] for sc in sorted(self.schemas.values(), key=lambda s: s["id"]) if any(f.get("data_class") == cls for f in sc["fields"])][:3]
            ev = ev or [self.stores[held[0]]["evidence"][0]] if (ev or held) else [self._ev_synthetic()]
            aid = sid("asset", "asset", "data", cls)
            self.assets[aid] = OrderedDict(id=aid, identity=["asset", "data", cls], origin="observed", name=DATA_ASSET_NAMES[cls], kind="data", data_classes=[cls], held_by=held, processed_by=proc, evidence=ev)

    def _agents(self):
        def add(access, ident, name, entry, passes, goals, conf, why, ev, location=None):
            aid = sid("agent", "agent", access, *ident)
            node = OrderedDict(id=aid, identity=["agent", access, *ident], origin="inferred", confidence=conf, rationale=why, name=name, access=access)
            if location:
                node["location"] = location
            node.update(entry=sorted(entry), passes_controls=passes, goals=goals, evidence=ev)
            self.agents[aid] = node
        for key, cid in sorted(self.inbound_clients.items()):
            eps = [e for e in self.entry_points.values() if any(f["source"] == cid and f["target"] == e["process"] for f in self.flows.values())]
            if not eps or key.startswith("queue"):
                continue
            main = [e for e in eps if not e.get("infrastructure")]
            guarded = [e for e in main if requires_auth([self.controls[c]["kind"] for c in e["controls"]])]
            ev = [sorted(eps, key=lambda e: e["id"])[0]["evidence"][0]]
            if key.startswith("internal-"):
                add("insider", (key,), f"Workload inside the deployment calling {self.entities[cid]['name'].replace('Internal ', '')} endpoints", [cid], [], ["call internal services directly"], 0.7,
                    "these entry points are not published outside the deployment; a caller must already be inside it", ev)
                continue
            add("anonymous", (key,), f"Anonymous {key.split('-')[0].upper()} caller", [cid], [], ["reach data or functions without authenticating"], 0.9,
                f"{len(main)} entry points are reachable from outside, {len(main) - len(guarded)} of them without a detected authentication control", ev)
            if guarded:
                add("authenticated", (key,), f"Authenticated {key.split('-')[0].upper()} caller", [cid], ["authn"], ["access other users' data", "use functions beyond their role"], 0.9,
                    f"{len(guarded)} entry points require authentication; a holder of valid credentials is a distinct agent", ev)
        for b in sorted(self.boundaries.values(), key=lambda b: b["id"]):
            inside = sorted(x for x in b["contains"] if x in self.processes and self.processes[x]["level"] == 2) or sorted(x for x in b["contains"] if x in self.processes and self.processes[x]["level"] == 1)
            if inside:
                add("insider", (b["id"],), f"Insider with access to {b['name']}", inside[:25], ["authn", "authz", "rate_limit", "input_validation", "csrf", "cors", "security_headers", "audit_log"],
                    ["read data stores directly", "exfiltrate secrets"], 0.8, "one insider agent per trust boundary, placed inside it", list(b["evidence"])[:1], location=b["id"])
        outbound = sorted(e["id"] for e in self.entities.values() if e["identity"][-1] == "outbound")
        if outbound:
            add("third_party", ("outbound",), "Compromised external service", outbound, [], ["return malicious responses", "harvest data sent to it"], 0.7,
                f"each of the {len(outbound)} outbound dependencies is a potentially hostile responder", [self.entities[outbound[0]]["evidence"][0]])

    # ================================================================== gaps
    def _gaps(self):
        idx = self.idx
        unsupported = {}
        for rel, why in idx.unsupported:
            unsupported.setdefault(why, []).append(rel)
        for why, files in sorted(unsupported.items()):
            self.gaps.append(OrderedDict(kind="unsupported_file", path=files[0], detail=f"{why}: {len(files)} file(s), e.g. {', '.join(files[:3])}"))
        for u in sorted(self.facts.by_kind("unresolved"), key=lambda f: f["id"]):
            self.gaps.append(OrderedDict(kind="unresolved", path=u["file"], detail=u["detail"]))
        touched = {f[end] for f in self.flows.values() for end in ("source", "target")}
        for st in sorted(self.stores.values(), key=lambda s: s["id"]):
            if st["id"] not in touched:
                self.gaps.append(OrderedDict(kind="unresolved", path=st["evidence"][0]["path"], line=st["evidence"][0]["start_line"],
                                             detail=f"{st['name']} is declared but no code access to it was detected (unsupported language, dynamic client, or a missing recognizer)"))
        for svc in sorted({self.service_of(self.ep_facts[e]["file"]) for e in self.entry_points if self.entry_points[e]["protocol"] == "http"}, key=str):
            if not self.listener_tls.get(svc, False):
                ls = sorted(self.facts.by_kind("listener"), key=lambda l: l["id"])
                l = next((x for x in ls if self.service_of(x["file"]) == svc), None)
                path = l["file"] if l else next(self.ep_facts[e]["file"] for e in sorted(self.entry_points) if self.service_of(self.ep_facts[e]["file"]) == svc)
                self.gaps.append(OrderedDict(kind="unknown_attribute", path=path, detail=f"Question: is TLS terminated in front of the HTTP listener of {svc or self.name}? Inbound flows are marked encryption=unknown until answered."))
        asked = set()
        for fid in sorted(self.flows):
            fl = self.flows[fid]
            if fl["protocol"] == "in_process" or not (fl["authentication"] == "unknown" or fl["encryption"] == "unknown"):
                continue
            tgt = self.stores.get(fl["target"]) or self.entities.get(fl["target"]) or self.stores.get(fl["source"])
            if tgt is None or tgt["id"] in asked:
                continue
            asked.add(tgt["id"])
            unknowns = " and ".join(k for k in ("authentication", "encryption") if fl[k] == "unknown")
            self.gaps.append(OrderedDict(kind="unknown_attribute", path=fl["evidence"][0]["path"], line=fl["evidence"][0]["start_line"], detail=f"Question: what is the {unknowns} of the link to {tgt['name']}?"))
        for st in sorted(self.stores.values(), key=lambda s: s["id"]):
            if st["encryption_at_rest"] == "unknown" and any(c in SENSITIVE_CLASSES for c in st["data_classes"]):
                self.gaps.append(OrderedDict(kind="unknown_attribute", path=st["evidence"][0]["path"], line=st["evidence"][0]["start_line"], detail=f"Question: is {st['name']} encrypted at rest? It holds {', '.join(st['data_classes'])}."))
        seen, out = set(), []
        for g in self.gaps:
            k = (g["kind"], g["detail"])
            if k not in seen:
                seen.add(k); out.append(g)
        self.gaps = out[:300]

    # ================================================================== finish
    def _unique_names(self):
        """Sibling processes with the same name get their directory appended; names stay code-derived."""
        groups = {}
        for p in self.processes.values():
            groups.setdefault((p["level"], p.get("parent") if p["level"] == 2 else None, p["name"]), []).append(p)
        for (_lvl, _parent, _name), ps in sorted(groups.items(), key=lambda kv: str(kv[0])):
            if len(ps) < 2:
                continue
            for p in sorted(ps, key=lambda p: p["id"]):
                d = os.path.dirname(p["module"]) if "." in os.path.basename(p["module"]) else p["module"]
                tail = "/".join(d.split("/")[-2:]) if d else p["module"]
                p["name"] = f"{p['name']} ({tail})"

    def build(self):
        self._services()
        self._processes()
        self._entry_points()
        self._ownership()
        self._rehome_scoped()
        self._stores()
        self._outbound()
        self._in_process()
        self._schemas()
        self._inbound()
        self._declared_links()
        self._data_classes()
        self._reaches()
        self._boundaries()
        self._weaknesses()
        self._assets()
        self._agents()
        self._gaps()
        self._unique_names()
        input_hashes = OrderedDict()
        for fct in self.facts.facts:
            for e in fct["evidence"]:
                p = e["path"]
                if p not in input_hashes and p != ".":
                    try:
                        with open(os.path.join(self.idx.root, p), "rb") as fh:
                            input_hashes[p] = "sha256:" + hashlib.sha256(fh.read()).hexdigest()
                    except OSError:
                        pass
        for c in self.controls.values():
            c["applies_to"] = sorted(set(c["applies_to"]))
        return OrderedDict(
            version=IR_VERSION,
            provenance=OrderedDict(tool_version=__version__, commit=_git_commit(self.idx.root), generated_from=self.name,
                                   detectors=sorted({f["detector"] for f in self.facts.facts} | {DET}),
                                   scope=OrderedDict(include=list(self.scope.get("include") or ["**"]), exclude=list(self.scope.get("exclude") or []), depth=2, out_of_scope_elements=[]),
                                   input_hashes=OrderedDict(sorted(input_hashes.items()))),
            processes=sorted_by_id(self.processes.values()), entities=sorted_by_id(self.entities.values()), stores=sorted_by_id(self.stores.values()),
            boundaries=sorted_by_id(self.boundaries.values()), flows=sorted_by_id(self.flows.values()), entry_points=sorted_by_id(self.entry_points.values()),
            controls=sorted_by_id(self.controls.values()), weaknesses=sorted_by_id(self.weaknesses.values()), schemas=sorted_by_id(self.schemas.values()),
            assets=sorted_by_id(self.assets.values()), threat_agents=sorted_by_id(self.agents.values()), gaps=self.gaps)
