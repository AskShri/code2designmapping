"""Generate the orders-service worked example: facts, IR, diagrams, STRIDE table.

This is a hand-driven stand-in for the detectors/synthesis/renderers described in
docs/design.md. The ID scheme, rollup and rendering rules are the real ones.
"""
import base64, hashlib, json, sys, pathlib
from collections import OrderedDict

ROOT = pathlib.Path(sys.argv[1]).resolve()
OUT = ROOT / "examples/orders-service/output"
OUT.mkdir(parents=True, exist_ok=True)
COMMIT = "0" * 40  # placeholder: example is not tied to a real commit

def sid(kind, *identity):
    h = hashlib.sha256(json.dumps([kind, *identity]).encode()).digest()
    return f"{kind}:{base64.b32encode(h).decode().lower()[:10]}"

APP = ROOT / "examples/orders-service/app"
def span_hash(path, start, end):
    lines = (APP / path).read_text().splitlines()[start - 1:end]
    return "sha256:" + hashlib.sha256(" ".join(" ".join(l.split()) for l in lines).encode()).hexdigest()

def ev(path, start, end, detector, symbol=None, fact_id=None):
    e = OrderedDict(path=path, start_line=start, end_line=end, detector=detector, content_hash=span_hash(path, start, end))
    if symbol: e["symbol"] = symbol
    if fact_id: e["fact_id"] = fact_id
    return e

# ---------------------------------------------------------------- facts
facts = []
def fact(fkind, **kw):
    fid = f"fact_{len(facts)+1:03d}"
    facts.append(OrderedDict(id=fid, kind=fkind, **kw))
    return fid

f_pkg   = fact("module", path=".", name="orders-service", evidence=ev("package.json", 2, 2, "npm-manifest@1.0"))
f_mod_o = fact("module", path="src/orders", name="orders", evidence=ev("src/orders/routes.ts", 1, 24, "ts-modules@1.0"))
f_mod_p = fact("module", path="src/payments", name="payments", evidence=ev("src/payments/stripe.ts", 1, 7, "ts-modules@1.0"))
f_mount = fact("config_value", name="router_mount", value="/orders", evidence=ev("src/index.ts", 10, 10, "express-routes@1.2"))
f_ep_post = fact("entry_point", protocol="http", method="POST", path="/orders", symbol="src/orders/routes.ts::ordersRouter.post#/",
                 evidence=ev("src/orders/routes.ts", 14, 18, "express-routes@1.2"))
f_ep_get  = fact("entry_point", protocol="http", method="GET", path="/orders/:id", symbol="src/orders/routes.ts::ordersRouter.get#/:id",
                 evidence=ev("src/orders/routes.ts", 20, 24, "express-routes@1.2"))
f_ctl_jwt = fact("control", control_kind="authn", name="requireJwt (JWT bearer)", scope="app", registered_at=ev("src/index.ts", 8, 8, "express-middleware@1.1"),
                 evidence=ev("src/infra/auth.ts", 4, 11, "express-middleware@1.1", symbol="src/infra/auth.ts::requireJwt"))
f_ctl_rl  = fact("control", control_kind="rate_limit", name="express-rate-limit 100/min", scope="app",
                 evidence=ev("src/index.ts", 9, 9, "express-middleware@1.1"))
f_ctl_val = fact("control", control_kind="input_validation", name="zod CreateOrderRequest.parse", scope=f_ep_post,
                 evidence=ev("src/orders/routes.ts", 15, 15, "zod-validation@1.0"))
f_sch_req = fact("schema", name="CreateOrderRequest",
                 fields=[{"name":"customerEmail","type":"string"},{"name":"shippingAddress","type":"string"},
                         {"name":"items","type":"{sku:string,qty:number}[]"},{"name":"cardToken","type":"string"}],
                 evidence=ev("src/orders/routes.ts", 5, 10, "zod-schemas@1.0", symbol="src/orders/routes.ts::CreateOrderRequest"))
f_sch_row = fact("schema", name="orders (row)",
                 fields=[{"name":"user_id","type":"text"},{"name":"customer_email","type":"text"},{"name":"shipping_address","type":"text"},
                         {"name":"total_cents","type":"int"},{"name":"charge_id","type":"text"}],
                 evidence=ev("src/orders/service.ts", 14, 14, "sql-literals@1.0"))
f_sch_chg = fact("schema", name="StripeChargeRequest",
                 fields=[{"name":"amount","type":"number"},{"name":"currency","type":"string"},{"name":"source","type":"string"}],
                 evidence=ev("src/payments/stripe.ts", 6, 6, "stripe-sdk@1.0"))
f_store_pg_client = fact("store_access", technology="postgres", operation="client_init", env="DATABASE_URL",
                 evidence=ev("src/infra/db.ts", 3, 3, "pg-driver@1.1", symbol="src/infra/db.ts::pool"))
f_pg_ins  = fact("store_access", technology="postgres", logical_name="orders", operation="write", caller="src/orders/service.ts::createOrder",
                 evidence=ev("src/orders/service.ts", 13, 16, "pg-driver@1.1"))
f_pg_sel  = fact("store_access", technology="postgres", logical_name="orders", operation="read", caller="src/orders/service.ts::getOrder",
                 evidence=ev("src/orders/service.ts", 24, 24, "pg-driver@1.1"))
f_redis_client = fact("store_access", technology="redis", operation="client_init", env="REDIS_URL",
                 evidence=ev("src/infra/cache.ts", 3, 3, "ioredis@1.0", symbol="src/infra/cache.ts::redis"))
f_redis_set = fact("store_access", technology="redis", logical_name="order:*", operation="write", caller="src/orders/service.ts::createOrder",
                 evidence=ev("src/orders/service.ts", 17, 17, "ioredis@1.0"))
f_redis_get = fact("store_access", technology="redis", logical_name="order:*", operation="read", caller="src/orders/service.ts::getOrder",
                 evidence=ev("src/orders/service.ts", 22, 22, "ioredis@1.0"))
f_out_stripe = fact("outbound_call", sdk_service="stripe", host="api.stripe.com", protocol="https", operation="charges.create",
                 caller="src/payments/stripe.ts::chargeCard", uses_result=True,
                 evidence=ev("src/payments/stripe.ts", 6, 6, "stripe-sdk@1.0"))
f_secret = fact("config_value", name="STRIPE_SECRET_KEY", data_class="secret", evidence=ev("src/payments/stripe.ts", 3, 3, "env-secrets@1.0"))
f_ce = {}
for (frm, to, path, s, e) in [
    ("src/orders/routes.ts::ordersRouter.post#/", "src/orders/service.ts::createOrder", "src/orders/routes.ts", 16, 16),
    ("src/orders/routes.ts::ordersRouter.get#/:id", "src/orders/service.ts::getOrder", "src/orders/routes.ts", 21, 21),
    ("src/orders/service.ts::createOrder", "src/payments/stripe.ts::chargeCard", "src/orders/service.ts", 12, 12),
]:
    f_ce[(frm, to)] = fact("call_edge", **{"from": frm, "to": to}, evidence=ev(path, s, e, "scip-typescript@0.3"))
f_bnd_api = fact("boundary_hint", boundary_kind="container", name="api", evidence=ev("docker-compose.yml", 2, 7, "compose@1.0"))
f_bnd_db  = fact("boundary_hint", boundary_kind="container", name="db", evidence=ev("docker-compose.yml", 8, 9, "compose@1.0"))
f_bnd_c   = fact("boundary_hint", boundary_kind="container", name="cache", evidence=ev("docker-compose.yml", 10, 11, "compose@1.0"))

(OUT / "facts.jsonl").write_text("\n".join(json.dumps(f) for f in facts) + "\n")

# ---------------------------------------------------------------- IR
def node(nkind, identity, origin="observed", **kw):
    n = OrderedDict(id=sid(nkind, *identity), identity=list(identity), origin=origin)
    n.update(kw)
    return n

P_ROOT = node("proc", ("process", ".", "orders-service"), name="orders-service", level=0, module=".",
              evidence=[ev("package.json", 2, 2, "npm-manifest@1.0", fact_id=f_pkg)])
P_ORD  = node("proc", ("process", "src/orders", "orders"), name="orders", level=1, parent=P_ROOT["id"], module="src/orders",
              evidence=[ev("src/orders/routes.ts", 1, 24, "ts-modules@1.0", fact_id=f_mod_o)])
P_PAY  = node("proc", ("process", "src/payments", "payments"), name="payments", level=1, parent=P_ROOT["id"], module="src/payments",
              evidence=[ev("src/payments/stripe.ts", 1, 7, "ts-modules@1.0", fact_id=f_mod_p)])
P_POST = node("proc", ("process", "src/orders/routes.ts", "ordersRouter.post#/"), name="POST /orders handler", level=2, parent=P_ORD["id"],
              module="src/orders/routes.ts", evidence=[ev("src/orders/routes.ts", 14, 18, "express-routes@1.2", symbol="src/orders/routes.ts::ordersRouter.post#/", fact_id=f_ep_post)])
P_GET  = node("proc", ("process", "src/orders/routes.ts", "ordersRouter.get#/:id"), name="GET /orders/:id handler", level=2, parent=P_ORD["id"],
              module="src/orders/routes.ts", evidence=[ev("src/orders/routes.ts", 20, 24, "express-routes@1.2", symbol="src/orders/routes.ts::ordersRouter.get#/:id", fact_id=f_ep_get)])
P_CRE  = node("proc", ("process", "src/orders/service.ts", "createOrder"), name="create order", level=2, parent=P_ORD["id"], module="src/orders/service.ts",
              origin="observed", description="Charges the card, inserts the order row, warms the cache",
              evidence=[ev("src/orders/service.ts", 5, 19, "scip-typescript@0.3", symbol="src/orders/service.ts::createOrder")])
P_GETO = node("proc", ("process", "src/orders/service.ts", "getOrder"), name="get order", level=2, parent=P_ORD["id"], module="src/orders/service.ts",
              evidence=[ev("src/orders/service.ts", 21, 26, "scip-typescript@0.3", symbol="src/orders/service.ts::getOrder")])
P_CHG  = node("proc", ("process", "src/payments/stripe.ts", "chargeCard"), name="charge card", level=2, parent=P_PAY["id"], module="src/payments/stripe.ts",
              evidence=[ev("src/payments/stripe.ts", 5, 7, "scip-typescript@0.3", symbol="src/payments/stripe.ts::chargeCard")])
# description on P_CRE came from the LLM stage in a real run; mark it so.
P_CRE["origin"] = "inferred"; P_CRE["confidence"] = 0.9
P_CRE["rationale"] = "Function body calls chargeCard, INSERT INTO orders, redis.set in sequence (fact_019, fact_014, fact_017)"

E_CLIENT = node("ext", ("external", "http-client", "inbound"), name="API client (JWT bearer)", kind="system",
                evidence=[ev("src/orders/routes.ts", 14, 14, "express-routes@1.2", fact_id=f_ep_post), ev("src/orders/routes.ts", 20, 20, "express-routes@1.2", fact_id=f_ep_get)])
E_STRIPE = node("ext", ("external", "stripe", "outbound"), name="Stripe API", kind="system", host="api.stripe.com", sdk_service="stripe",
                evidence=[ev("src/payments/stripe.ts", 6, 6, "stripe-sdk@1.0", fact_id=f_out_stripe)])

S_PG = node("store", ("store", "postgres", "orders"), name="Postgres: orders", technology="postgres", logical_name="orders", encryption_at_rest="unknown",
            data_classes=["pii", "financial"],
            evidence=[ev("src/infra/db.ts", 3, 3, "pg-driver@1.1", fact_id=f_store_pg_client), ev("src/orders/service.ts", 13, 16, "pg-driver@1.1", fact_id=f_pg_ins), ev("src/orders/service.ts", 24, 24, "pg-driver@1.1", fact_id=f_pg_sel)])
S_RD = node("store", ("store", "redis", "order:*"), name="Redis: order:*", technology="redis", logical_name="order:*", encryption_at_rest="unknown",
            data_classes=["pii", "financial"],
            evidence=[ev("src/infra/cache.ts", 3, 3, "ioredis@1.0", fact_id=f_redis_client), ev("src/orders/service.ts", 17, 17, "ioredis@1.0", fact_id=f_redis_set), ev("src/orders/service.ts", 22, 22, "ioredis@1.0", fact_id=f_redis_get)])

B_API = node("bnd", ("boundary", "container", "api"), name="container: api", kind="container",
             contains=[P_ROOT["id"], P_ORD["id"], P_PAY["id"], P_POST["id"], P_GET["id"], P_CRE["id"], P_GETO["id"], P_CHG["id"]],
             evidence=[ev("docker-compose.yml", 2, 7, "compose@1.0", fact_id=f_bnd_api)])
B_DB  = node("bnd", ("boundary", "container", "db"), name="container: db", kind="container", contains=[S_PG["id"]],
             evidence=[ev("docker-compose.yml", 8, 9, "compose@1.0", fact_id=f_bnd_db)])
B_C   = node("bnd", ("boundary", "container", "cache"), name="container: cache", kind="container", contains=[S_RD["id"]],
             evidence=[ev("docker-compose.yml", 10, 11, "compose@1.0", fact_id=f_bnd_c)])

C_JWT = node("ctl", ("control", "authn", "src/infra/auth.ts::requireJwt"), kind="authn", name="JWT bearer (requireJwt)",
             evidence=[ev("src/infra/auth.ts", 4, 11, "express-middleware@1.1", symbol="src/infra/auth.ts::requireJwt", fact_id=f_ctl_jwt), ev("src/index.ts", 8, 8, "express-middleware@1.1")])
C_RL  = node("ctl", ("control", "rate_limit", "src/index.ts::rateLimit"), kind="rate_limit", name="rate limit 100/min",
             evidence=[ev("src/index.ts", 9, 9, "express-middleware@1.1", fact_id=f_ctl_rl)])
C_VAL = node("ctl", ("control", "input_validation", "src/orders/routes.ts::CreateOrderRequest.parse"), kind="input_validation", name="zod CreateOrderRequest",
             evidence=[ev("src/orders/routes.ts", 15, 15, "zod-validation@1.0", fact_id=f_ctl_val)])

W_SECRET = node("wk", ("weakness", "secret_in_env_at_import", "src/payments/stripe.ts:3"), kind="secret_in_env_at_import",
                name="STRIPE_SECRET_KEY read at module import", applies_to=[E_STRIPE["id"]],
                evidence=[ev("src/payments/stripe.ts", 3, 3, "env-secrets@1.0", fact_id=f_secret)])

SCH_REQ = node("sch", ("schema", "src/orders/routes.ts", "CreateOrderRequest"), name="CreateOrderRequest",
               fields=[{"name":"customerEmail","type":"string","data_class":"pii"},{"name":"shippingAddress","type":"string","data_class":"pii"},
                       {"name":"items","type":"{sku:string,qty:number}[]","data_class":"internal"},{"name":"cardToken","type":"string","data_class":"financial"}],
               evidence=[ev("src/orders/routes.ts", 5, 10, "zod-schemas@1.0", symbol="src/orders/routes.ts::CreateOrderRequest", fact_id=f_sch_req)])
SCH_ROW = node("sch", ("schema", "sql", "orders"), name="orders (row)",
               fields=[{"name":"user_id","type":"text","data_class":"internal"},{"name":"customer_email","type":"text","data_class":"pii"},
                       {"name":"shipping_address","type":"text","data_class":"pii"},{"name":"total_cents","type":"int","data_class":"financial"},{"name":"charge_id","type":"text","data_class":"internal"}],
               evidence=[ev("src/orders/service.ts", 14, 14, "sql-literals@1.0", fact_id=f_sch_row)])
SCH_CHG = node("sch", ("schema", "stripe", "charges.create"), name="StripeChargeRequest",
               fields=[{"name":"amount","type":"number","data_class":"financial"},{"name":"currency","type":"string","data_class":"public"},{"name":"source","type":"string","data_class":"financial"}],
               evidence=[ev("src/payments/stripe.ts", 6, 6, "stripe-sdk@1.0", fact_id=f_sch_chg)])

def payload(sch, classes, name=None):
    p = OrderedDict()
    if sch: p["schema_ref"] = sch["id"]
    if name: p["name"] = name
    p["data_classes"] = classes
    return p

def flow(src, dst, protocol, direction, evidence, crosses=(), controls=(), authentication="unknown", encryption="unknown", **kw):
    ptype = kw.get("payload", {}).get("name") or (kw.get("payload", {}).get("schema_ref") or "")
    f = node("flow", ("flow", src["id"], dst["id"], protocol, ptype), source=src["id"], target=dst["id"], protocol=protocol, direction=direction,
             authentication=authentication, encryption=encryption)
    f.update(kw)
    f["crosses_boundary"] = list(crosses); f["controls"] = list(controls)
    f["evidence"] = evidence
    return f

flows = [
    flow(E_CLIENT, P_POST, "https", "request_response", [ev("src/orders/routes.ts", 14, 18, "express-routes@1.2", fact_id=f_ep_post)],
         crosses=[B_API["id"]], controls=[C_JWT["id"], C_RL["id"], C_VAL["id"]], purpose="Create an order", authentication="token", encryption="tls",
         payload=payload(SCH_REQ, ["pii", "financial"]), response_payload=payload(SCH_ROW, ["pii", "financial"])),
    flow(E_CLIENT, P_GET, "https", "request_response", [ev("src/orders/routes.ts", 20, 24, "express-routes@1.2", fact_id=f_ep_get)],
         crosses=[B_API["id"]], controls=[C_JWT["id"], C_RL["id"]], purpose="Fetch an order by id", authentication="token", encryption="tls",
         payload=payload(None, ["internal"], name="order id"), response_payload=payload(SCH_ROW, ["pii", "financial"])),
    flow(P_POST, P_CRE, "in_process", "request_response", [ev("src/orders/routes.ts", 16, 16, "scip-typescript@0.3", fact_id=f_ce[("src/orders/routes.ts::ordersRouter.post#/", "src/orders/service.ts::createOrder")])],
         authentication="none", encryption="none", payload=payload(SCH_REQ, ["pii", "financial"])),
    flow(P_GET, P_GETO, "in_process", "request_response", [ev("src/orders/routes.ts", 21, 21, "scip-typescript@0.3", fact_id=f_ce[("src/orders/routes.ts::ordersRouter.get#/:id", "src/orders/service.ts::getOrder")])],
         authentication="none", encryption="none", payload=payload(None, ["internal"], name="order id")),
    flow(P_CRE, P_CHG, "in_process", "request_response", [ev("src/orders/service.ts", 12, 12, "scip-typescript@0.3", fact_id=f_ce[("src/orders/service.ts::createOrder", "src/payments/stripe.ts::chargeCard")])],
         authentication="none", encryption="none", payload=payload(None, ["financial"], name="card token, amount")),
    flow(P_CHG, E_STRIPE, "https", "request_response", [ev("src/payments/stripe.ts", 6, 6, "stripe-sdk@1.0", fact_id=f_out_stripe)],
         crosses=[B_API["id"]], purpose="Charge the card", authentication="credentials", encryption="tls", payload=payload(SCH_CHG, ["financial"]), response_payload=payload(None, ["internal"], name="charge id")),
    flow(P_CRE, S_PG, "sql", "one_way", [ev("src/orders/service.ts", 13, 16, "pg-driver@1.1", fact_id=f_pg_ins)],
         crosses=[B_API["id"], B_DB["id"]], purpose="Insert order", payload=payload(SCH_ROW, ["pii", "financial"])),
    flow(P_CRE, S_RD, "redis", "one_way", [ev("src/orders/service.ts", 17, 17, "ioredis@1.0", fact_id=f_redis_set)],
         crosses=[B_API["id"], B_C["id"]], purpose="Cache order for 300s", payload=payload(SCH_ROW, ["pii", "financial"])),
    flow(S_RD, P_GETO, "redis", "one_way", [ev("src/orders/service.ts", 22, 22, "ioredis@1.0", fact_id=f_redis_get)],
         crosses=[B_C["id"], B_API["id"]], purpose="Read cached order", payload=payload(SCH_ROW, ["pii", "financial"])),
    flow(S_PG, P_GETO, "sql", "one_way", [ev("src/orders/service.ts", 24, 24, "pg-driver@1.1", fact_id=f_pg_sel)],
         crosses=[B_DB["id"], B_API["id"]], purpose="Read order row", payload=payload(SCH_ROW, ["pii", "financial"])),
]

EP_POST = node("ep", ("entry_point", "http", "POST", "/orders"), process=P_POST["id"], protocol="http", method="POST", path="/orders",
               controls=[C_JWT["id"], C_RL["id"], C_VAL["id"]], call_chain=[P_POST["id"], P_CRE["id"], P_CHG["id"]],
               evidence=[ev("src/orders/routes.ts", 14, 18, "express-routes@1.2", fact_id=f_ep_post), ev("src/index.ts", 10, 10, "express-routes@1.2", fact_id=f_mount)])
EP_GET = node("ep", ("entry_point", "http", "GET", "/orders/:id"), process=P_GET["id"], protocol="http", method="GET", path="/orders/:id",
              controls=[C_JWT["id"], C_RL["id"]], call_chain=[P_GET["id"], P_GETO["id"]],
              evidence=[ev("src/orders/routes.ts", 20, 24, "express-routes@1.2", fact_id=f_ep_get), ev("src/index.ts", 10, 10, "express-routes@1.2", fact_id=f_mount)])
for c in (C_JWT, C_RL): c["applies_to"] = [EP_POST["id"], EP_GET["id"]]
C_VAL["applies_to"] = [EP_POST["id"]]

by_id = lambda xs: sorted(xs, key=lambda x: x["id"])
ir = OrderedDict(
    version="0.1",
    provenance=OrderedDict(tool_version="0.2.0-design", commit=COMMIT, generated_from="examples/orders-service/app",
        input_hashes=OrderedDict(sorted((f["evidence"]["path"], "sha256:" + hashlib.sha256((APP / f["evidence"]["path"]).read_bytes()).hexdigest()) for f in facts)),
        detectors=sorted({e["detector"] for f in facts for e in [f["evidence"]]}),
        llm=OrderedDict(model="claude-sonnet-5-5", prompt_hash="sha256:examplepromptpin", proposals_accepted=1, proposals_rejected=0)),
    processes=by_id([P_ROOT, P_ORD, P_PAY, P_POST, P_GET, P_CRE, P_GETO, P_CHG]),
    entities=by_id([E_CLIENT, E_STRIPE]),
    stores=by_id([S_PG, S_RD]),
    boundaries=by_id([B_API, B_DB, B_C]),
    flows=by_id(flows),
    entry_points=by_id([EP_POST, EP_GET]),
    controls=by_id([C_JWT, C_RL, C_VAL]),
    weaknesses=by_id([W_SECRET]),
    schemas=by_id([SCH_REQ, SCH_ROW, SCH_CHG]),
    gaps=[OrderedDict(kind="no_boundary_info", detail="No IaC found for the public ingress; 'container: api' used as the outermost boundary."),
          OrderedDict(kind="unresolved", path="src/infra/auth.ts", line=8, detail="JWT_PUBLIC_KEY read from env; key source (secret store vs. file) not determinable statically."),
          OrderedDict(kind="unknown_attribute", path="src/infra/db.ts", line=3, detail="Question for the team: is the Postgres link TLS (sslmode) and is the volume encrypted at rest?"),
          OrderedDict(kind="unknown_attribute", path="src/infra/cache.ts", line=3, detail="Question for the team: is the Redis link TLS (rediss://) and does the cache require AUTH?")],
)
(OUT / "model.ir.json").write_text(json.dumps(ir, indent=2) + "\n")

import jsonschema
schema = json.loads((ROOT / "schema/dfd-ir.schema.json").read_text())
jsonschema.Draft202012Validator(schema).validate(ir)
print("IR validates against schema")

# ---------------------------------------------------------------- lint (subset)
ids = {n["id"] for k in ("processes","entities","stores","boundaries","flows","entry_points","controls","weaknesses","schemas") for n in ir[k]}
for f in ir["flows"]:
    assert f["source"] in ids and f["target"] in ids, f
    kinds = (f["source"].split(":")[0], f["target"].split(":")[0])
    assert kinds not in {("store","store"), ("ext","ext")}, f
    if f["crosses_boundary"] and not f["controls"] and f["source"].startswith("ext"):
        print("lint warning: boundary crossing without control", f["id"])
    if "pii" in f.get("payload", {}).get("data_classes", []) and f["protocol"] == "http":
        print("lint warning: pii over plain http", f["id"])
print("lint ok")

# ---------------------------------------------------------------- renderers
procs = {p["id"]: p for p in ir["processes"]}
nodes = {**procs, **{e["id"]: e for e in ir["entities"]}, **{s["id"]: s for s in ir["stores"]}}
stores_ids = {s["id"] for s in ir["stores"]}
sch = {s["id"]: s for s in ir["schemas"]}

def ancestor_at(pid, level):
    p = procs[pid]
    while p["level"] > level: p = procs[p["parent"]]
    return p["id"]

def mm_node(n):
    nid = n["id"].replace(":", "_")
    label = n["name"].replace('"', "'")
    if n["id"].startswith("proc"): return f'{nid}(["{label}"])'
    if n["id"].startswith("store"): return f'{nid}[("{label}")]'
    return f'{nid}["{label}"]'

def edge_label(f):
    p = f.get("payload", {})
    name = p.get("name") or (sch[p["schema_ref"]]["name"] if p.get("schema_ref") else "")
    dc = ",".join(c for c in p.get("data_classes", []) if c not in ("internal", "public"))
    lbl = f'{f["protocol"]}: {name}' + (f" [{dc}]" if dc else "")
    return lbl.replace('"', "'")

def render_dfd(level, title):
    # roll flows up to the requested level; keep entities/stores as is
    rolled = OrderedDict()
    for f in ir["flows"]:
        s = ancestor_at(f["source"], level) if f["source"].startswith("proc") else f["source"]
        t = ancestor_at(f["target"], level) if f["target"].startswith("proc") else f["target"]
        if s == t: continue
        key = (s, t, f["protocol"])
        rolled.setdefault(key, []).append(f)
    shown = {s for (s, t, _) in rolled} | {t for (s, t, _) in rolled}
    out = [f"%% {title}", "flowchart LR"]
    # boundaries as subgraphs, elements grouped by boundary at this level
    placed = set()
    for b in ir["boundaries"]:
        members = [m for m in b["contains"] if m in shown and m not in placed]
        if not members: continue
        out.append(f'  subgraph {b["id"].replace(":", "_")}["{b["name"]}"]')
        for m in sorted(members): out.append("    " + mm_node(nodes[m])); placed.add(m)
        out.append("  end")
    for m in sorted(shown - placed): out.append("  " + mm_node(nodes[m]))
    for (s, t, _), fs in sorted(rolled.items()):
        labels = sorted({edge_label(f) for f in fs})
        out.append(f'  {s.replace(":", "_")} -->|"{"<br/>".join(labels)}"| {t.replace(":", "_")}')
    inferred = [n for n in nodes.values() if n["origin"] == "inferred" and n["id"] in shown]
    for n in inferred: out.append(f'  style {n["id"].replace(":", "_")} stroke-dasharray: 5 5')
    for b in ir["boundaries"]:
        if any(m in shown for m in b["contains"]): out.append(f'  style {b["id"].replace(":", "_")} stroke-dasharray: 8 4,fill:none')
    out += ['  subgraph legend["Legend"]', '    lg_e["External entity"]', '    lg_p(["Process"])', '    lg_s[("Data store")]', '  end',
            '  style legend stroke-dasharray: 8 4,fill:none']
    return "\n".join(out) + "\n"

(OUT / "dfd-l0.mmd").write_text(render_dfd(0, "L0 context diagram: orders-service"))
(OUT / "dfd-l1.mmd").write_text(render_dfd(1, "L1 diagram: orders-service"))
(OUT / "dfd-l2-orders.mmd").write_text(render_dfd(2, "L2 diagram: all L2 processes (small enough to fit the budget)"))

# control-flow view: recursive walk of each entry point's call chain, in source-line order
ctl = {c["id"]: c for c in ir["controls"]}
def mmid(x): return x.replace(":", "_")
def render_flow(ep):
    out = [f"%% Control flow: {ep['method']} {ep['path']}", "sequenceDiagram", "  autonumber",
           f'  participant C as {E_CLIENT["name"]}']
    for cid in ep["controls"]: out.append(f'  participant {mmid(cid)} as {ctl[cid]["name"]}')
    lines, seen = [], []
    def participant(x):
        if x not in seen: seen.append(x)
    def walk(pid):
        participant(pid)
        outgoing = [f for f in ir["flows"] if f["source"] == pid and f["target"] != E_CLIENT["id"]]
        reads = [f for f in ir["flows"] if f["target"] == pid and f["source"] in stores_ids]
        for f in sorted(outgoing + reads, key=lambda f: (f["evidence"][0]["path"], f["evidence"][0]["start_line"])):
            if f["target"] == pid:  # read from store
                participant(f["source"]); lines.append(f'  {mmid(f["source"])}-->>{mmid(pid)}: {edge_label(f)}'); continue
            participant(f["target"]); lines.append(f'  {mmid(pid)}->>{mmid(f["target"])}: {edge_label(f)}')
            if f["target"].startswith("proc"): walk(f["target"])
            if f["direction"] == "request_response":
                rp = f.get("response_payload")
                lbl = (rp.get("name") or sch[rp["schema_ref"]]["name"]) if rp else "result"
                lines.append(f'  {mmid(f["target"])}-->>{mmid(pid)}: {lbl}')
    first = ep["call_chain"][0]
    walk(first)
    for x in seen: out.append(f'  participant {mmid(x)} as {nodes[x]["name"]}')
    prev = "C"
    for cid in ep["controls"]:
        out.append(f'  {prev}->>{mmid(cid)}: {ep["method"]} {ep["path"]} ({ctl[cid]["kind"]})'); prev = mmid(cid)
    out.append(f'  {prev}->>{mmid(first)}: dispatch')
    out += lines
    status = "201" if ep["method"] == "POST" else "200"
    out.append(f'  {mmid(first)}-->>C: {status} orders (row) [pii,financial]')
    return "\n".join(out) + "\n"

(OUT / "flow-post-orders.mmd").write_text(render_flow(EP_POST))
(OUT / "flow-get-order.mmd").write_text(render_flow(EP_GET))

# STRIDE per element table
STRIDE = {"ext": "S R", "proc": "S T R I D E", "store": "T R I D", "flow": "T I D"}
rows = ["| Element | Type | STRIDE | Data classes | Boundary crossings | Existing controls | Priority hint |", "|---|---|---|---|---|---|---|"]
def fmt_ctls(ids_): return ", ".join(ctl[c]["name"] for c in ids_) or "none"
hint_rows = []
for e in ir["entities"]:
    if e["identity"][-1] == "inbound":
        hint = "inbound caller; verify JWT issuer, audience and expiry in requireJwt"
    else:
        hint = "outbound dependency; API key STRIPE_SECRET_KEY read from env (src/payments/stripe.ts:3); confirm secret storage and timeouts"
    hint_rows.append((0, f'| {e["name"]} | External entity | {STRIDE["ext"]} | - | - | - | {hint} |'))
for p in ir["processes"]:
    if p["level"] != 2: continue
    eps = [x for x in ir["entry_points"] if x["process"] == p["id"]]
    c = fmt_ctls(eps[0]["controls"]) if eps else "n/a (internal)"
    hint_rows.append((1, f'| {p["name"]} | Process | {STRIDE["proc"]} | - | - | {c} | {"entry point" if eps else ""} |'))
for s in ir["stores"]:
    inb = ", ".join(b["name"] for b in ir["boundaries"] if s["id"] in b["contains"])
    hint_rows.append((0, f'| {s["name"]} | Data store | {STRIDE["store"]} | {", ".join(s["data_classes"])} | in {inb} | none detected (encryption at rest unknown) | holds pii+financial; confirm encryption at rest and retention |'))
bnames = {b["id"]: b["name"] for b in ir["boundaries"]}
for w in ir["weaknesses"]:
    hint_rows.append((0, f'| {w["name"]} | Weakness | - | - | - | - | {w["kind"]} at {w["evidence"][0]["path"]}:{w["evidence"][0]["start_line"]}; applies to {", ".join(nodes[a]["name"] for a in w["applies_to"])} |'))
SENSITIVE = ("pii", "financial", "credential", "secret")
for f in ir["flows"]:
    if f["protocol"] == "in_process": continue
    dc = ", ".join(f.get("payload", {}).get("data_classes", []))
    hint = []
    if f["target"].startswith("ext") and any(c in dc for c in SENSITIVE):
        hint.append("EXIT POINT: sensitive data leaves the system" + (" to an LLM API" if nodes[f["target"]].get("kind") == "llm_api" else ""))
    if f["crosses_boundary"] and not f["controls"]: hint.append("crosses boundary without a control")
    if f["crosses_boundary"] and (f["authentication"] == "unknown" or f["encryption"] == "unknown"):
        hint.append(f"authentication={f['authentication']}, encryption={f['encryption']}: question for the team")
    hint_rows.append((0 if hint else 2, f'| {nodes[f["source"]]["name"]} -> {nodes[f["target"]]["name"]} | Data flow | {STRIDE["flow"]} | {dc} | {", ".join(bnames[b] for b in f["crosses_boundary"])} | {fmt_ctls(f["controls"])} | {"; ".join(hint)} |'))
rows += [r for _, r in sorted(hint_rows, key=lambda x: x[0])]
# data asset view: where each data class is processed and stored
assets = ["", "## Data assets", "", "| Data class | Processed by | Stored in | Leaves the system via |", "|---|---|---|---|"]
for dc in ("pii", "financial", "credential", "secret"):
    proc_ = sorted({nodes[f["target"]]["name"] for f in ir["flows"] if dc in f.get("payload", {}).get("data_classes", []) and f["target"].startswith("proc")} |
                   {nodes[f["source"]]["name"] for f in ir["flows"] if dc in f.get("payload", {}).get("data_classes", []) and f["source"].startswith("proc")})
    stored = sorted(s_["name"] for s_ in ir["stores"] if dc in s_.get("data_classes", []))
    exits = sorted(nodes[f["target"]]["name"] for f in ir["flows"] if f["target"].startswith("ext") and dc in f.get("payload", {}).get("data_classes", []))
    if proc_ or stored or exits:
        assets.append(f'| {dc} | {", ".join(proc_) or "-"} | {", ".join(stored) or "-"} | {", ".join(exits) or "-"} |')
(OUT / "stride-table.md").write_text("# STRIDE per element: orders-service\n\nRows are ordered by priority hint (exit points and weaknesses first).\n\n" + "\n".join(rows) + "\n" + "\n".join(assets) + "\n")
print("wrote", sorted(p.name for p in OUT.iterdir()))
