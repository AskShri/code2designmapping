"""Synthesis: flat facts -> hierarchical IR. Deterministic; every element carries evidence."""
import os, re, subprocess, hashlib
from collections import OrderedDict, deque
from .model import sid, classify_field, sorted_by_id, TECH_PROTOCOL
from . import __version__

TECH_LABEL = {"postgres": "Postgres", "mysql": "MySQL", "sqlite": "SQLite", "mssql": "SQL Server", "mongodb": "MongoDB", "dynamodb": "DynamoDB", "redis": "Redis", "memcached": "Memcached", "elasticsearch": "Elasticsearch", "kafka": "Kafka", "rabbitmq": "RabbitMQ", "sqs": "SQS", "s3": "S3", "gcs": "GCS", "filesystem": "Filesystem", "unknown": "Database"}
WRAPPER_DIRS = {"src", "lib", "app", "server", "backend", "api", "source"}


def _git_commit(root):
    try:
        return subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10).stdout.strip() or "0" * 40
    except Exception:  # noqa
        return "0" * 40


def _join(prefix, path):
    if not prefix:
        return path
    if path in ("/", ""):
        return prefix
    return (prefix.rstrip("/") + "/" + path.lstrip("/"))


class Synth:
    def __init__(self, idx, facts, name=None, scope=None):
        self.idx, self.facts = idx, facts
        self.name = name or os.path.basename(idx.root.rstrip("/"))
        self.scope = scope or {}
        self.gaps = []
        self.ev_of = {f["id"]: f for f in facts.facts}

    # ---------------------------------------------------------------- grouping
    def _services(self):
        """service name -> context dir, from compose/k8s app containers (Dockerfile hints only fill gaps)."""
        by_ctx = OrderedDict()
        hints = sorted(self.facts.by_kind("boundary_hint"), key=lambda f: (0 if f.get("source") in ("compose", "k8s") else 1, f["name"]))
        for f in hints:
            if f.get("holds_store") or f.get("infra") or f.get("boundary_kind") != "container":
                continue
            ctx = f.get("context")
            if ctx is None:
                continue
            ctx = "." if ctx in ("", ".") else ctx.rstrip("/")
            if ctx != "." and not any(p == ctx or p.startswith(ctx + "/") for p in self.idx.files):
                continue
            if ctx in by_ctx:
                continue
            name = f["name"] if f.get("source") != "dockerfile" else (os.path.basename(ctx) if ctx != "." else self.name)
            by_ctx[ctx] = name
        svcs = OrderedDict((name, ctx) for ctx, name in by_ctx.items())
        # a root context swallows every nested one when it is the only app container
        if "." in by_ctx and len(by_ctx) > 1 and all(not any(p.startswith(c + "/") for p in self.idx.files) or c == "." for c in by_ctx):
            pass
        return svcs

    def _service_of(self, path, svcs):
        best = None
        for name, ctx in svcs.items():
            if ctx == "." or path == ctx or path.startswith(ctx + "/"):
                if best is None or len(ctx) > len(svcs[best]):
                    best = name
        return best

    def _l1_key(self, path, svcs):
        svc = self._service_of(path, svcs)
        if len(svcs) > 1 and svc is not None:
            return (svc, svcs[svc])
        base = svcs[svc] if svc is not None else "."
        rel = path if base == "." else path[len(base) + 1:]
        parts = rel.split("/")
        parts = parts[:-1]  # directories only
        while parts and parts[0] in WRAPPER_DIRS:
            parts = parts[1:]
        if not parts:
            return (svc or self.name, base)
        return (parts[0], os.path.normpath(os.path.join(base, *(rel.split("/")[:rel.split("/").index(parts[0]) + 1]))))

    # ---------------------------------------------------------------- build
    def build(self):
        facts = self.facts
        idx = self.idx
        svcs = self._services()
        host_to_service = {}
        for f in facts.by_kind("boundary_hint"):
            if f.get("host"):
                host_to_service[f["host"]] = f
        for f in facts.by_kind("service_host"):
            host_to_service.setdefault(f["host"], f)
        env_hosts = {}
        for f in facts.by_kind("boundary_hint"):
            for k, v in (f.get("env_hosts") or {}).items():
                env_hosts[k] = v.split(":")[0]

        processes, entities, stores, boundaries, flows, entry_points, controls, weaknesses, schemas, assets, agents = ({} for _ in range(11))
        root_mod = next((m for m in facts.by_kind("module") if m["path"] == "."), None)
        root_name = (root_mod["name"] if root_mod else self.name)
        P_ROOT = self._proc(processes, ("process", ".", root_name), root_name, 0, None, ".", root_mod["evidence"] if root_mod else [self._synthetic_ev()])

        # L1 per group
        l1_of_file = {}
        for path in idx.files:
            key = self._l1_key(path, svcs)
            l1_of_file[path] = key
        l1_ids = {}
        for path, (nm, mod) in sorted(l1_of_file.items()):
            if (nm, mod) in l1_ids:
                continue
            ev = [self._file_ev(path)]
            l1_ids[(nm, mod)] = self._proc(processes, ("process", mod, nm), nm, 1, P_ROOT, mod, ev)

        # entry points, mounts, app files
        app_files = {f["file"] for f in facts.by_kind("app_entry")}
        prefix_of = {f: "" for f in app_files}
        mounts = facts.by_kind("router_mount")
        q = deque(app_files)
        while q:
            cur = q.popleft()
            for m in mounts:
                if m["file"] == cur and m.get("target_file") and m["target_file"] not in prefix_of:
                    prefix_of[m["target_file"]] = _join(prefix_of[cur], m["prefix"])
                    q.append(m["target_file"])
        mounted_prefixes = {}
        for m in mounts:
            if m["file"] in prefix_of and m.get("target_file"):
                mounted_prefixes[m["target_file"]] = _join(prefix_of[m["file"]], m["prefix"])
        app_controls = [c for c in facts.by_kind("control") if c.get("scope") in ("app", "file")]
        router_controls = [c for c in facts.by_kind("control") if c.get("scope") == "router"]
        ctl_ids = {}

        def control_id(c):
            key = (c["control_kind"], c["name"], c["file"])
            if key not in ctl_ids:
                cid = sid("ctl", "control", c["control_kind"], f'{c["file"]}::{c["name"]}')
                controls[cid] = OrderedDict(id=cid, identity=["control", c["control_kind"], f'{c["file"]}::{c["name"]}'], origin="observed", kind=c["control_kind"], name=c["name"], applies_to=[], evidence=list(c["evidence"]))
                ctl_ids[key] = cid
            return ctl_ids[key]

        handler_proc_of_fact = {}
        listener_tls = any(l.get("tls") for l in facts.by_kind("listener"))
        for ep in facts.by_kind("entry_point"):
            f = ep["file"]
            if ep["protocol"] == "http":
                if f in prefix_of:
                    full = _join(prefix_of[f], ep["path"])
                elif f in mounted_prefixes:
                    full = _join(mounted_prefixes[f], ep["path"])
                elif ep.get("router") in ("django", "drf") or ep["file"].endswith(".py"):
                    full = ep["path"]
                else:
                    full = ep["path"]
                    self.gaps.append(OrderedDict(kind="unresolved", path=f, line=ep["evidence"][0]["start_line"], detail=f"router for {ep['method']} {ep['path']} is not mounted from a detected app entry; path shown without prefix"))
                label = f"{ep['method']} {full}"
            else:
                full = ep["path"]; label = f"gRPC {ep['path']}"
            l1 = l1_ids[l1_of_file[f]]
            pid = self._proc(processes, ("process", f, label), f"{label} handler", 2, l1, f, list(ep["evidence"]))
            handler_proc_of_fact[ep["id"]] = pid
            ctls = [control_id(self.ev_of[c]) for c in ep.get("route_controls", [])]
            for c in app_controls:
                if ep["protocol"] != "http":
                    continue
                if c.get("scope") == "file" and c["file"] != f and self._l1_key(c["file"], svcs) != l1_of_file[f]:
                    continue
                if c.get("path_prefix") and not full.startswith(_join(prefix_of.get(c["file"], ""), c["path_prefix"]).rstrip("/")):
                    continue
                if self._service_of(c["file"], svcs) != self._service_of(f, svcs):
                    continue
                ctls.append(control_id(c))
            for c in router_controls:
                if c["file"] == f:
                    ctls.append(control_id(c))
            ctls = sorted(set(ctls))
            eid = sid("ep", "entry_point", ep["protocol"], ep["method"], full, f)
            entry_points[eid] = OrderedDict(id=eid, identity=["entry_point", ep["protocol"], ep["method"], full, f], origin="observed", process=pid, protocol=ep["protocol"], method=ep["method"], path=full, controls=ctls, call_chain=[pid], evidence=list(ep["evidence"]))
            for c in ctls:
                controls[c]["applies_to"].append(eid)
        # module processes for fact-bearing files
        usage_kinds = ("store_access", "outbound_call")
        fact_files = {}
        for fct in facts.facts:
            if fct["kind"] in usage_kinds and fct.get("operation") not in ("client_init", "service_definition", "model_definition") and fct.get("file"):
                fact_files.setdefault(fct["file"], []).append(fct)
        module_proc = {}
        def module_process(f):
            if f in module_proc:
                return module_proc[f]
            l1 = l1_ids[l1_of_file[f]]
            nm = os.path.splitext(os.path.basename(f))[0]
            if nm in ("index", "main", "app", "server", "__init__"):
                nm = os.path.basename(os.path.dirname(f)) or nm
            pid = self._proc(processes, ("process", f, nm), nm, 2, l1, f, [self._file_ev(f)])
            module_proc[f] = pid
            return pid
        for f in sorted(fact_files):
            module_process(f)

        # entities & stores from usage facts -> flows
        def proc_for(fct):
            h = fct.get("handler")
            if h and h in handler_proc_of_fact:
                return handler_proc_of_fact[h]
            return module_process(fct["file"])
        inbound_clients = {}
        for eid, ep in entry_points.items():
            key = "http-client" if ep["protocol"] == "http" else "grpc-client"
            if key not in inbound_clients:
                cid = sid("ext", "external", key, "inbound")
                entities[cid] = OrderedDict(id=cid, identity=["external", key, "inbound"], origin="observed", name="HTTP client" if key == "http-client" else "gRPC client", kind="system", evidence=[])
                inbound_clients[key] = cid
            ent = entities[inbound_clients[key]]
            if len(ent["evidence"]) < 3:
                ent["evidence"].append(ep["evidence"][0])
            authn = [controls[c] for c in ep["controls"] if controls[c]["kind"] == "authn"]
            auth = "none"
            if authn:
                names = " ".join(a["name"].lower() for a in authn)
                auth = "token" if re.search(r"(jwt|bearer|token|oauth)", names) else ("session_id" if re.search(r"(session|login_required|isauthenticated|ensureauth)", names) else "credentials")
            payload = self._payload_for_handler(ep, schemas)
            proto_in = "grpc" if ep["protocol"] == "grpc" else ("https" if listener_tls else "http")
            fl = self._flow(flows, inbound_clients[key], ep["process"], proto_in, "request_response", auth, "tls" if listener_tls else "unknown", list(ep["evidence"]), controls=ep["controls"], payload=payload, purpose=f"{ep['method']} {ep['path']}")

        store_ids = {}
        compose_stores = {}
        for fct in facts.by_kind("store_access"):
            if fct.get("operation") == "service_definition":
                compose_stores.setdefault(fct["technology"], []).append(fct)
        declared_techs = sorted({t for t in compose_stores if t != "unknown"} | {f["technology"] for f in facts.by_kind("store_access") if f.get("operation") == "model_definition" and f["technology"] != "unknown"})
        display_logical = {}
        def store_for(tech, logical, ev):
            if tech == "unknown" and len(declared_techs) == 1:
                tech = declared_techs[0]  # the only database declared in compose/k8s/prisma
            norm = (logical or "").lower().rstrip("s") if logical and not logical.endswith("*") else (logical or "").lower()
            if norm and norm not in display_logical:
                display_logical[norm] = logical
            logical = display_logical.get(norm, logical) if norm else None
            key = (tech, norm)
            if key in store_ids:
                st = stores[store_ids[key]]
                if len(st["evidence"]) < 6 and ev not in st["evidence"]:
                    st["evidence"].append(ev)
                return store_ids[key]
            sidv = sid("store", "store", tech, norm)
            name = f"{TECH_LABEL.get(tech, tech)}: {logical}" if logical else TECH_LABEL.get(tech, tech)
            stores[sidv] = OrderedDict(id=sidv, identity=["store", tech, norm], origin="observed", name=name, technology=tech, logical_name=logical, data_classes=[], encryption_at_rest="unknown", evidence=[ev])
            if logical: stores[sidv]["logical_name"] = logical
            else: del stores[sidv]["logical_name"]
            store_ids[key] = sidv
            return sidv
        store_facts = sorted(facts.by_kind("store_access"), key=lambda f: (f.get("operation") == "service_definition", f["id"]))
        for fct in store_facts:
            op = fct.get("operation")
            if op == "client_init":
                continue
            if op == "service_definition":
                # a database declared in compose/k8s is a store even when no code access was detected,
                # but it merges into the code-level stores of the same technology when those exist
                key_tech = fct["technology"]
                if any(s_["technology"] == key_tech for s_ in stores.values()):
                    for s_ in stores.values():
                        if s_["technology"] == key_tech and len(s_["evidence"]) < 6:
                            s_["evidence"].append(fct["evidence"][0])
                    continue
                st = store_for(key_tech, None if len(compose_stores.get(key_tech, [])) == 1 else fct.get("logical_name"), fct["evidence"][0])
                stores[st]["description"] = f"declared as service '{fct.get('logical_name')}' in {fct['file']}"
                continue
            tech = fct["technology"]
            if op == "model_definition":
                st = store_for(tech, fct.get("logical_name"), fct["evidence"][0])
                continue
            st = store_for(tech, fct.get("logical_name"), fct["evidence"][0])
            src = proc_for(fct)
            proto = TECH_PROTOCOL.get(tech, "unknown")
            if op == "read":
                self._flow(flows, st, src, proto, "one_way", "unknown", "unknown", list(fct["evidence"]), purpose=f"{fct.get('method', 'read')}")
            elif op == "write":
                self._flow(flows, src, st, proto, "one_way", "unknown", "unknown", list(fct["evidence"]), purpose=f"{fct.get('method', 'write')}")
            else:
                self._flow(flows, src, st, proto, "unknown", "unknown", "unknown", list(fct["evidence"]), purpose=f"{fct.get('method', 'access')} (direction unknown)")
        # outbound
        ent_ids = {}
        def entity_for(name, host, kind, ev):
            key = name or host
            if key in ent_ids:
                e = entities[ent_ids[key]]
                if len(e["evidence"]) < 6 and ev not in e["evidence"]:
                    e["evidence"].append(ev)
                return ent_ids[key]
            eid = sid("ext", "external", key, "outbound")
            e = OrderedDict(id=eid, identity=["external", key, "outbound"], origin="observed", name=name or host, kind=kind or "system", evidence=[ev])
            if host and not host.startswith(("env:", "variable:")): e["host"] = host
            if name and name != host: e["sdk_service"] = name
            entities[eid] = e; ent_ids[key] = eid
            return eid
        secret_files = {f["file"] for f in facts.by_kind("config_value") if f.get("data_class") == "secret"}
        sdk_usage_files = {(f["file"], f.get("sdk_service")) for f in facts.by_kind("outbound_call") if f.get("operation") not in ("sdk_import",)}
        for fct in facts.by_kind("outbound_call"):
            if fct.get("operation") == "sdk_import" and (fct["file"], fct.get("sdk_service")) in sdk_usage_files:
                continue  # the usage fact carries the flow
            host = fct.get("host"); name = fct.get("sdk_service")
            if host and host.startswith("env:") and host[4:] in env_hosts:
                host = env_hosts[host[4:]]
            if host and host.lower() in ("localhost", "127.0.0.1", "0.0.0.0", "::1", "::", "[::]") and not name:
                continue  # loopback target: not an external dependency
            src = proc_for(fct) if fct.get("operation") != "sdk_import" else module_process(fct["file"])
            proto = fct.get("protocol") or "unknown"
            enc = "tls" if proto in ("https",) else ("none" if proto in ("http",) or fct.get("insecure") else "unknown")
            auth = "credentials" if (name and fct["file"] in secret_files) else "unknown"
            target = None
            # cross-service resolution via compose / k8s hostnames
            if host and host in host_to_service and host not in ("localhost",):
                hf = host_to_service[host]
                if hf.get("holds_store"):
                    target = store_for(hf["technology"], None, hf["evidence"][0])
                    self._flow(flows, src, target, TECH_PROTOCOL.get(hf["technology"], proto), "unknown", auth, enc, list(fct["evidence"]), purpose=fct.get("operation") or "access")
                    continue
                ctx = hf.get("context")
                tgt_key = next((k for k in l1_ids if ctx and (k[1] == ctx or k[1].startswith(ctx + "/"))), None) if ctx else None
                if tgt_key is None:
                    tgt_key = next((k for k in l1_ids if k[0] == hf["name"]), None)
                if tgt_key:
                    target = l1_ids[tgt_key]
                    self._flow(flows, src, target, "grpc" if proto == "grpc" else proto if proto != "unknown" else "http", "request_response", auth, enc, list(fct["evidence"]), purpose=f"{fct.get('operation') or 'call'} {host}")
                    continue
                # a known service host with no source in the repo: external system named by the host
                name = name or f"{hf['name']} service"
            if host and host.startswith("variable:"):
                self.gaps.append(OrderedDict(kind="unresolved", path=fct["file"], line=fct["evidence"][0]["start_line"], detail=f"outbound call target is a {host} expression; host not resolvable statically"))
                name = name or "Unresolved HTTP target"
            if host and host.startswith("env:"):
                name = name or f"Service at ${host[4:]}"
            if not host and not name:
                name = f"Unresolved {proto if proto != 'unknown' else 'HTTP'} target"
            eid = entity_for(name, host, fct.get("entity_kind"), fct["evidence"][0])
            self._flow(flows, src, eid, proto if proto in ("https", "http", "grpc", "smtp") else "unknown", "request_response", auth, enc, list(fct["evidence"]), purpose=fct.get("operation") or "call")

        # handlers that reference a controller in another file: flow handler -> that module only
        for fid, pid in handler_proc_of_fact.items():
            ep = self.ev_of[fid]
            hm = ep.get("handler_module")
            if hm and hm in idx.files:
                if hm not in module_proc:
                    reached = self._reach(idx, hm, set(module_proc), 2)
                    for g in reached:
                        self._flow(flows, pid, module_proc[g], "in_process", "request_response", "none", "none", [self._file_ev(ep["file"])], purpose=f"handler {ep.get('handler_ref')}")
                else:
                    self._flow(flows, pid, module_proc[hm], "in_process", "request_response", "none", "none", [self._file_ev(ep["file"])], purpose=f"handler {ep.get('handler_ref')}")
        # in-process flows along imports: handler/module -> imported fact-bearing module (depth 3)
        fact_bearing = set(module_proc)
        for f, sf in idx.files.items():
            sources = []
            if f in module_proc:
                sources.append((module_proc[f], None))
            for fid, pid in handler_proc_of_fact.items():
                ep = self.ev_of[fid]
                if ep["file"] == f:
                    span = ep.get("handler_span")
                    if span is None and ep.get("handler_module"):
                        continue  # already linked to its controller module above
                    sources.append((pid, sf.text[span[0]:span[1]] if span else (ep.get("handler_ref") or "")))
            if not sources:
                continue
            for local, spec in sorted(sf.bindings.items()):
                tgt = idx.resolve(sf, spec)
                if not tgt or tgt == f:
                    continue
                reached = self._reach(idx, tgt, fact_bearing, 3)
                for g in reached:
                    for pid, htxt in sources:
                        if htxt is not None and not re.search(r"\b" + re.escape(local.split(":")[0]) + r"\b", htxt):
                            continue
                        if module_proc[g] == pid:
                            continue
                        self._flow(flows, pid, module_proc[g], "in_process", "request_response", "none", "none", [self._file_ev(f, sf, local)], purpose=f"uses {local}")
        # call chains for entry points
        adj = {}
        for fl in flows.values():
            if fl["protocol"] == "in_process":
                adj.setdefault(fl["source"], []).append(fl["target"])
        for ep in entry_points.values():
            chain = [ep["process"]]; seen = {ep["process"]}; q = deque([ep["process"]])
            while q and len(chain) < 12:
                cur = q.popleft()
                for nx in sorted(adj.get(cur, [])):
                    if nx not in seen:
                        seen.add(nx); chain.append(nx); q.append(nx)
            ep["call_chain"] = chain

        # schemas -> store data classes
        for sc in schemas.values():
            classes = sorted({f["data_class"] for f in sc["fields"] if f.get("data_class") not in (None, "internal", "public")})
            if not classes:
                continue
            for st in stores.values():
                ln = (st.get("logical_name") or "").lower()
                if ln and (ln == sc["name"].lower() or ln.rstrip("s") == sc["name"].lower().rstrip("s") or sc["name"].lower().replace("schema", "") == ln.rstrip("s")):
                    st["data_classes"] = sorted(set(st["data_classes"]) | set(classes))
        for fl in flows.values():
            if fl["target"] in stores and fl.get("payload"):
                st = stores[fl["target"]]
                st["data_classes"] = sorted(set(st["data_classes"]) | {c for c in fl["payload"]["data_classes"] if c not in ("internal", "public")})
        # propagate request data classes from handlers along in-process edges (depth 3) to the store writes
        # and outbound calls those modules perform. File-level approximation; payload is named accordingly.
        classes_of = {}
        for fl in flows.values():
            if fl["source"] in inbound_clients.values() and fl.get("payload"):
                cls = {c for c in fl["payload"]["data_classes"] if c not in ("internal", "public")}
                if cls:
                    classes_of.setdefault(fl["target"], set()).update(cls)
        inproc = {}
        for fl in flows.values():
            if fl["protocol"] == "in_process":
                inproc.setdefault(fl["source"], []).append(fl["target"])
        frontier = list(classes_of.items())
        for _ in range(3):
            nxt = []
            for pid, cls in frontier:
                for t in inproc.get(pid, []):
                    before = set(classes_of.get(t, set()))
                    classes_of.setdefault(t, set()).update(cls)
                    if classes_of[t] != before:
                        nxt.append((t, classes_of[t]))
            frontier = nxt
        for fl in flows.values():
            if fl.get("payload") or fl["protocol"] == "in_process":
                continue
            src = fl["source"]
            if src in classes_of and (fl["target"] in stores or fl["target"] in entities):
                cls = sorted(classes_of[src])
                fl["payload"] = OrderedDict(name="request fields (propagated)", data_classes=cls)
                if fl["target"] in stores and fl["direction"] != "one_way" or (fl["target"] in stores and fl["source"] == src):
                    stores[fl["target"]]["data_classes"] = sorted(set(stores[fl["target"]]["data_classes"]) | set(cls))
        for fl in flows.values():
            if fl["source"] in stores and not fl.get("payload") and stores[fl["source"]]["data_classes"]:
                fl["payload"] = OrderedDict(name=stores[fl["source"]]["name"] + " record", data_classes=list(stores[fl["source"]]["data_classes"]))

        # boundaries
        all_l1 = set(l1_ids.values())
        proc_children = {}
        for p in processes.values():
            if p.get("parent"):
                proc_children.setdefault(p["parent"], []).append(p["id"])
        def subtree(pid):
            out = [pid]
            for c in proc_children.get(pid, []):
                out += subtree(c)
            return out
        bnd_hints = [b for b in facts.by_kind("boundary_hint") if b.get("boundary_kind") == "container"]
        if any(b.get("source") in ("compose", "k8s") and not b.get("holds_store") and not b.get("infra") for b in bnd_hints):
            bnd_hints = [b for b in bnd_hints if b.get("source") != "dockerfile"]
        made = set()
        for b in bnd_hints:
            if b.get("infra"):
                continue
            contains = []
            if b.get("holds_store"):
                contains = [s["id"] for s in stores.values() if s["technology"] == b.get("technology") and len(compose_stores.get(b.get("technology"), [])) == 1]
            else:
                ctx = b.get("context")
                for (nm, mod), pid in l1_ids.items():
                    if (len(svcs) > 1 and nm == b["name"]) or (len(svcs) <= 1 and (ctx in (".", None) or mod == ctx or mod.startswith(ctx + "/"))):
                        contains += subtree(pid)
                if len(svcs) <= 1 and ctx in (".", None):
                    contains = [P_ROOT] + [p for p in processes if p != P_ROOT]
            contains = sorted(set(contains))
            if not contains or (b.get("source") == "dockerfile" and any(x["name"] == b["name"] for x in boundaries.values())):
                continue
            bid = sid("bnd", "boundary", b["boundary_kind"], b["name"])
            if bid in boundaries:
                boundaries[bid]["contains"] = sorted(set(boundaries[bid]["contains"]) | set(contains))
                continue
            boundaries[bid] = OrderedDict(id=bid, identity=["boundary", b["boundary_kind"], b["name"]], origin="observed", name=f"container: {b['name']}", kind="container", contains=contains, evidence=list(b["evidence"]))
        placed = {x for b in boundaries.values() for x in b["contains"]}
        unplaced = [p for p in processes if p not in placed]
        if unplaced:
            bid = sid("bnd", "boundary", "repository", root_name)
            boundaries[bid] = OrderedDict(id=bid, identity=["boundary", "repository", root_name], origin="inferred", confidence=0.5, rationale="No container or IaC boundary covers these processes; the repository itself is used as the trust boundary", name=f"repository: {root_name}", kind="repository", contains=sorted(unplaced), evidence=[self._synthetic_ev()])
            if not bnd_hints:
                self.gaps.append(OrderedDict(kind="no_boundary_info", detail="No compose, Dockerfile or Kubernetes manifests found; the repository is the only trust boundary."))
        bnd_of = {}
        for b in boundaries.values():
            for x in b["contains"]:
                bnd_of.setdefault(x, set()).add(b["id"])
        for fl in flows.values():
            fl["crosses_boundary"] = sorted(bnd_of.get(fl["source"], set()) ^ bnd_of.get(fl["target"], set()))

        # weaknesses
        for w in facts.by_kind("weakness"):
            wid = sid("wk", "weakness", w["weakness_kind"], f'{w["file"]}:{w["evidence"][0]["start_line"]}')
            applies = []
            if w["file"] in module_proc: applies.append(module_proc[w["file"]])
            applies += [pid for fid, pid in handler_proc_of_fact.items() if self.ev_of[fid]["file"] == w["file"]]
            if not applies and w["file"] in l1_of_file: applies.append(l1_ids[l1_of_file[w["file"]]])
            if not applies: applies.append(P_ROOT)
            weaknesses[wid] = OrderedDict(id=wid, identity=["weakness", w["weakness_kind"], f'{w["file"]}:{w["evidence"][0]["start_line"]}'], origin="observed", kind=w["weakness_kind"], name=w["name"], applies_to=sorted(set(applies)), evidence=list(w["evidence"]))
        for ep in entry_points.values():
            if ep["protocol"] == "http" and not any(controls[c]["kind"] == "authn" for c in ep["controls"]):
                wid = sid("wk", "weakness", "unauthenticated_entry_point", ep["id"])
                weaknesses[wid] = OrderedDict(id=wid, identity=["weakness", "unauthenticated_entry_point", ep["id"]], origin="observed", kind="unauthenticated_entry_point", name=f"no authn control detected on {ep['method']} {ep['path']}", applies_to=[ep["id"]], evidence=list(ep["evidence"]))
        # secrets at import -> weakness + credential asset
        for cv in facts.by_kind("config_value"):
            if cv.get("data_class") != "secret":
                continue
            holder = module_proc.get(cv["file"]) or next((pid for fid, pid in handler_proc_of_fact.items() if self.ev_of[fid]["file"] == cv["file"]), None) or l1_ids.get(l1_of_file.get(cv["file"]), P_ROOT)
            aid = sid("asset", "asset", "credential", cv["name"])
            if aid not in assets:
                assets[aid] = OrderedDict(id=aid, identity=["asset", "credential", cv["name"]], origin="observed", name=f"Secret {cv['name']}", kind="credential", data_classes=["secret"], held_by=[holder], processed_by=[holder], evidence=[cv["evidence"][0]])
            elif holder not in assets[aid]["held_by"]:
                assets[aid]["held_by"].append(holder); assets[aid]["processed_by"].append(holder)
            if cv.get("at_import"):
                wid = sid("wk", "weakness", "secret_in_env_at_import", f'{cv["file"]}:{cv["evidence"][0]["start_line"]}')
                weaknesses[wid] = OrderedDict(id=wid, identity=["weakness", "secret_in_env_at_import", f'{cv["file"]}:{cv["evidence"][0]["start_line"]}'], origin="observed", kind="secret_in_env_at_import", name=f"{cv['name']} read at module import", applies_to=[holder], evidence=list(cv["evidence"]))
        # data assets
        for cls in ("pii", "financial", "health", "credential"):
            held = sorted(s["id"] for s in stores.values() if cls in s["data_classes"])
            proc = sorted({fl["source"] for fl in flows.values() if fl.get("payload") and cls in fl["payload"]["data_classes"] and fl["source"] in processes} | {fl["target"] for fl in flows.values() if fl.get("payload") and cls in fl["payload"]["data_classes"] and fl["target"] in processes})
            if not held and not proc:
                continue
            ev = [sc["evidence"][0] for sc in schemas.values() if any(f.get("data_class") == cls for f in sc["fields"])][:3] or [stores[held[0]]["evidence"][0]]
            aid = sid("asset", "asset", "data", cls)
            assets[aid] = OrderedDict(id=aid, identity=["asset", "data", cls], origin="observed", name={"pii": "Personal data (PII)", "financial": "Financial data", "health": "Health data", "credential": "User credentials"}[cls], kind="data", data_classes=[cls], held_by=held, processed_by=proc, evidence=ev)
        # threat agents
        for key, cid in inbound_clients.items():
            eps = [e for e in entry_points.values() if (e["protocol"] == "http") == (key == "http-client")]
            anon = [e for e in eps if not any(controls[c]["kind"] == "authn" for c in e["controls"])]
            aid = sid("agent", "agent", "anonymous", key)
            agents[aid] = OrderedDict(id=aid, identity=["agent", "anonymous", key], origin="inferred", confidence=0.9, rationale=f"{len(eps)} {key.split('-')[0]} entry points, {len(anon)} without a detected authn control", name=f"Anonymous {key.split('-')[0].upper()} caller", access="anonymous", entry=[cid], passes_controls=[], goals=["reach data or functions without authenticating"], evidence=[eps[0]["evidence"][0]] if eps else [self._synthetic_ev()])
            if len(anon) < len(eps):
                aid2 = sid("agent", "agent", "authenticated", key)
                agents[aid2] = OrderedDict(id=aid2, identity=["agent", "authenticated", key], origin="inferred", confidence=0.9, rationale="authn controls exist on some entry points; a valid credential holder is a distinct agent", name=f"Authenticated {key.split('-')[0].upper()} caller", access="authenticated", entry=[cid], passes_controls=["authn"], goals=["access other users' data", "abuse privileged functions"], evidence=[eps[0]["evidence"][0]])
        for b in boundaries.values():
            inside = [x for x in b["contains"] if x in processes and processes[x]["level"] == 2] or [x for x in b["contains"] if x in processes and processes[x]["level"] == 1]
            if not inside:
                continue
            aid = sid("agent", "agent", "insider", b["id"])
            agents[aid] = OrderedDict(id=aid, identity=["agent", "insider", b["id"]], origin="inferred", confidence=0.8, rationale="one insider agent per trust boundary, placed inside it", name=f"Insider with access to {b['name']}", access="insider", location=b["id"], entry=sorted(inside)[:20], passes_controls=["authn", "authz", "rate_limit", "input_validation", "csrf", "cors"], goals=["read stores directly", "exfiltrate secrets"], evidence=list(b["evidence"])[:1])
        for e in entities.values():
            if e["identity"][-1] != "outbound":
                continue
            aid = sid("agent", "agent", "third_party", e["id"])
            agents[aid] = OrderedDict(id=aid, identity=["agent", "third_party", e["id"]], origin="inferred", confidence=0.7, rationale="every outbound dependency is modeled as a potentially hostile responder", name=f"Compromised third party: {e['name']}", access="third_party", entry=[e["id"]], passes_controls=[], goals=["return malicious responses", "harvest data sent to it"], evidence=list(e["evidence"])[:1])

        touched = {f["source"] for f in flows.values()} | {f["target"] for f in flows.values()}
        for st in stores.values():
            if st["id"] not in touched:
                self.gaps.append(OrderedDict(kind="unresolved", path=st["evidence"][0]["path"], line=st["evidence"][0]["start_line"], detail=f"{st['name']} is declared but no code access to it was detected (unsupported language, dynamic client, or a missing recognizer)"))
        # gaps
        unsupported = {}
        for rel, why in idx.unsupported:
            unsupported.setdefault(why, []).append(rel)
        for why, files in sorted(unsupported.items()):
            self.gaps.append(OrderedDict(kind="unsupported_file", path=files[0], detail=f"{why}: {len(files)} file(s), e.g. {', '.join(files[:3])}"))
        for u in facts.by_kind("unresolved"):
            self.gaps.append(OrderedDict(kind="unresolved", path=u["file"], detail=u["detail"]))
        if entry_points and not listener_tls:
            ports = sorted({str(l.get("port")) for l in facts.by_kind("listener")})
            self.gaps.append(OrderedDict(kind="unknown_attribute", path=facts.by_kind("listener")[0]["file"] if facts.by_kind("listener") else ir_path_fallback(entry_points), detail=f"Question for the team: is TLS terminated in front of the HTTP listener{' on port ' + ', '.join(ports) if ports else ''}? Inbound flows are marked encryption=unknown until answered."))
        for fl in flows.values():
            if fl["protocol"] != "in_process" and (fl["authentication"] == "unknown" or fl["encryption"] == "unknown") and (fl["source"] in stores or fl["target"] in stores or fl["target"] in entities):
                tgt = stores.get(fl["target"]) or entities.get(fl["target"]) or stores.get(fl["source"])
                self.gaps.append(OrderedDict(kind="unknown_attribute", path=fl["evidence"][0]["path"], line=fl["evidence"][0]["start_line"], detail=f"Question for the team: how is the link to {tgt['name']} authenticated and is it encrypted in transit? (authentication={fl['authentication']}, encryption={fl['encryption']})"))
        # dedupe questions per target
        seen_q = set(); gaps = []
        for g in self.gaps:
            k = (g["kind"], g.get("detail", "")[:80])
            if k in seen_q: continue
            seen_q.add(k); gaps.append(g)
        self.gaps = gaps[:200]

        # provenance
        input_hashes = OrderedDict()
        for fct in facts.facts:
            for e in fct["evidence"]:
                p = e["path"]
                if p not in input_hashes:
                    try:
                        input_hashes[p] = "sha256:" + hashlib.sha256(open(os.path.join(idx.root, p), "rb").read()).hexdigest()
                    except OSError:
                        pass
        ir = OrderedDict(
            version="0.1",
            provenance=OrderedDict(tool_version=__version__, commit=_git_commit(idx.root), generated_from=self.name,
                                   detectors=sorted({f["detector"] for f in facts.facts}),
                                   scope=OrderedDict(include=list(self.scope.get("include", ["**"])), exclude=list(self.scope.get("exclude", [])), depth=2, out_of_scope_elements=[]),
                                   input_hashes=OrderedDict(sorted(input_hashes.items()))),
            processes=sorted_by_id(processes.values()), entities=sorted_by_id(entities.values()), stores=sorted_by_id(stores.values()),
            boundaries=sorted_by_id(boundaries.values()), flows=sorted_by_id(flows.values()), entry_points=sorted_by_id(entry_points.values()),
            controls=sorted_by_id(controls.values()), weaknesses=sorted_by_id(weaknesses.values()), schemas=sorted_by_id(schemas.values()),
            assets=sorted_by_id(assets.values()), threat_agents=sorted_by_id(agents.values()), gaps=self.gaps)
        for c in ir["controls"]:
            c["applies_to"] = sorted(set(c["applies_to"]))
        return ir

    # ---------------------------------------------------------------- helpers
    def _proc(self, processes, identity, name, level, parent, module, ev):
        pid = sid("proc", *identity)
        if pid not in processes:
            p = OrderedDict(id=pid, identity=list(identity), origin="observed", name=name, level=level, module=module, evidence=ev)
            if parent: p["parent"] = parent
            processes[pid] = p
        return pid

    def _flow(self, flows, src, dst, protocol, direction, auth, enc, ev, controls=None, payload=None, purpose=None):
        ptype = (payload or {}).get("name", "")
        fid = sid("flow", "flow", src, dst, protocol, ptype)
        if fid in flows:
            f = flows[fid]
            if len(f["evidence"]) < 6 and ev[0] not in f["evidence"]:
                f["evidence"].extend(ev)
            if controls: f["controls"] = sorted(set(f["controls"]) | set(controls))
            if f["direction"] == "one_way" and direction == "one_way" and f["source"] != src:
                pass
            return fid
        f = OrderedDict(id=fid, identity=["flow", src, dst, protocol, ptype], origin="observed", source=src, target=dst, protocol=protocol, direction=direction, authentication=auth, encryption=enc)
        if purpose: f["purpose"] = purpose[:80]
        if payload: f["payload"] = payload
        f["crosses_boundary"] = []; f["controls"] = sorted(set(controls or [])); f["evidence"] = ev
        flows[fid] = f
        return fid

    def _payload_for_handler(self, ep, schemas):
        f = ep["evidence"][0]["path"]
        epf = self.ev_of[[k for k, v in self.ev_of.items() if v["kind"] == "entry_point" and v["evidence"][0] == ep["evidence"][0]][0]]
        span = epf.get("handler_span")
        sf = self.idx.files.get(f)
        htxt = sf.text[span[0]:span[1]] if (sf and span) else ""
        classes = set(); refs = []
        for sc in self.facts.by_kind("schema"):
            use = False
            if sc["file"] == f and sc.get("schema_kind") == "validation":
                if sc["name"] == "request fields":
                    use = ep["evidence"][0]["start_line"] <= sc["evidence"][0]["start_line"] <= ep["evidence"][0]["end_line"]
                else:
                    use = bool(re.search(r"\b" + re.escape(sc["name"]) + r"\b", htxt)) or (htxt == "" and True)
            if use:
                scid = self._schema(schemas, sc)
                refs.append(scid)
                classes |= {x["data_class"] for x in schemas[scid]["fields"]}
        classes.discard("internal"); classes.discard("public")
        if not refs:
            return None
        return OrderedDict(schema_ref=refs[0], name=schemas[refs[0]]["name"], data_classes=sorted(classes) or ["internal"])

    def _schema(self, schemas, sc):
        scid = sid("sch", "schema", sc["file"], sc["name"])
        if scid not in schemas:
            fields = [OrderedDict(name=x["name"], type=x.get("type", "unknown")[:30], data_class=classify_field(x["name"])) for x in sc["fields"]]
            schemas[scid] = OrderedDict(id=scid, identity=["schema", sc["file"], sc["name"]], origin="observed", name=sc["name"], fields=fields, evidence=list(sc["evidence"]))
        return scid

    def _reach(self, idx, start, targets, depth):
        out = []; seen = {start}; q = deque([(start, 0)])
        while q:
            cur, d = q.popleft()
            if cur in targets:
                out.append(cur)
                continue  # stop at the first fact-bearing module on each path
            if d >= depth:
                continue
            sf = idx.files.get(cur)
            if not sf:
                continue
            for local, spec in sorted(sf.bindings.items()):
                t = idx.resolve(sf, spec)
                if t and t not in seen:
                    seen.add(t); q.append((t, d + 1))
        return sorted(set(out))

    def _file_ev(self, path, sf=None, local=None):
        from .model import evidence
        sf = sf or self.idx.files[path]
        line = 1
        if local:
            for spec_, ln, names in sf.imports:
                if local in names or local.split(":")[0] in names:
                    line = ln; break
        return evidence(sf, line, line, "synth@0.3")

    def _synthetic_ev(self):
        from collections import OrderedDict as OD
        from .model import span_hash
        return OD(path=".", start_line=1, end_line=1, detector="synth@0.3", content_hash=span_hash([self.name]))


def ir_path_fallback(entry_points):
    return next(iter(entry_points.values()))["evidence"][0]["path"]


def synthesize(idx, facts, name=None, scope=None):
    s = Synth(idx, facts, name, scope)
    ir = s.build()
    # schema facts that were never referenced by a handler still belong in the IR
    for sc in facts.by_kind("schema"):
        scid = sid("sch", "schema", sc["file"], sc["name"])
        if not any(x["id"] == scid for x in ir["schemas"]):
            tmp = {}
            s._schema(tmp, sc)
            ir["schemas"].append(tmp[scid])
    ir["schemas"] = sorted_by_id(ir["schemas"])
    return ir
