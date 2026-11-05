"""JavaScript / TypeScript detectors: Express-style routes and middleware, store clients, outbound
HTTP and SDK clients, gRPC, schemas (mongoose, zod, joi, sequelize), secrets and weaknesses.
Coverage: literal route paths on app/router objects; dynamically built routers are reported as unresolved.
"""
import re
from urllib.parse import urlparse
from ..model import classify_control, classify_field, SECRET_ENV_RX, LOCAL_HOSTS
from ..index import walk

DET = "js@0.3"
HTTP_VERBS = {"get", "post", "put", "patch", "delete", "all", "head", "options"}
HTTP_CLIENT_PKGS = {"axios", "got", "node-fetch", "superagent", "undici", "request", "request-promise", "ky", "cross-fetch", "isomorphic-fetch", "needle", "phin"}

STORE_PKGS = {
    "pg": "postgres", "pg-promise": "postgres", "postgres": "postgres", "@vercel/postgres": "postgres",
    "mysql": "mysql", "mysql2": "mysql", "mariadb": "mysql",
    "sqlite3": "sqlite", "better-sqlite3": "sqlite", "sqlite": "sqlite",
    "mssql": "mssql", "tedious": "mssql",
    "mongoose": "mongodb", "mongodb": "mongodb", "monk": "mongodb",
    "redis": "redis", "ioredis": "redis", "connect-redis": "redis", "bull": "redis", "bullmq": "redis", "bee-queue": "redis",
    "memcached": "memcached", "memjs": "memcached",
    "@elastic/elasticsearch": "elasticsearch", "elasticsearch": "elasticsearch",
    "kafkajs": "kafka", "kafka-node": "kafka", "node-rdkafka": "kafka",
    "amqplib": "rabbitmq", "amqp": "rabbitmq", "rascal": "rabbitmq",
    "@aws-sdk/client-sqs": "sqs", "@aws-sdk/client-s3": "s3", "@aws-sdk/lib-storage": "s3", "@aws-sdk/client-dynamodb": "dynamodb", "@aws-sdk/lib-dynamodb": "dynamodb",
    "@google-cloud/storage": "gcs", "@google-cloud/pubsub": "unknown", "connect-mongo": "mongodb", "@keyv/mongo": "mongodb", "@langchain/mongodb": "mongodb", "@langchain/langgraph-checkpoint-mongodb": "mongodb",
    "@prisma/client": "unknown", "sequelize": "unknown", "typeorm": "unknown", "knex": "unknown", "objection": "unknown", "drizzle-orm": "unknown", "mikro-orm": "unknown",
}
SDK_PKGS = {  # package -> (service name, host, kind)
    "stripe": ("Stripe API", "api.stripe.com", "system"), "twilio": ("Twilio API", "api.twilio.com", "system"),
    "@sendgrid/mail": ("SendGrid API", "api.sendgrid.com", "system"), "mailgun-js": ("Mailgun API", "api.mailgun.net", "system"), "mailgun.js": ("Mailgun API", "api.mailgun.net", "system"),
    "nodemailer": ("SMTP mail relay", None, "system"), "postmark": ("Postmark API", "api.postmarkapp.com", "system"),
    "openai": ("OpenAI API", "api.openai.com", "llm_api"), "@anthropic-ai/sdk": ("Anthropic API", "api.anthropic.com", "llm_api"), "@google/generative-ai": ("Google Gemini API", "generativelanguage.googleapis.com", "llm_api"), "@aws-sdk/client-bedrock-runtime": ("AWS Bedrock", None, "llm_api"), "cohere-ai": ("Cohere API", "api.cohere.ai", "llm_api"), "@langchain/openai": ("OpenAI API", "api.openai.com", "llm_api"), "@langchain/anthropic": ("Anthropic API", "api.anthropic.com", "llm_api"), "@langchain/google-genai": ("Google Gemini API", "generativelanguage.googleapis.com", "llm_api"), "@langchain/groq": ("Groq API", "api.groq.com", "llm_api"), "@huggingface/inference": ("Hugging Face Inference API", "api-inference.huggingface.co", "llm_api"), "@google-cloud/vertexai": ("Google Vertex AI", None, "llm_api"), "@lob/lob-typescript-sdk": ("Lob API", "api.lob.com", "system"), "@googleapis/drive": ("Google Drive API", "www.googleapis.com", "system"), "@googleapis/sheets": ("Google Sheets API", "sheets.googleapis.com", "system"),
    "aws-sdk": ("AWS SDK (v2)", None, "system"), "@aws-sdk/client-ses": ("AWS SES", None, "system"), "@aws-sdk/client-sns": ("AWS SNS", None, "system"), "@aws-sdk/client-secrets-manager": ("AWS Secrets Manager", None, "system"), "@aws-sdk/client-lambda": ("AWS Lambda", None, "system"),
    "firebase-admin": ("Firebase", None, "system"), "firebase": ("Firebase", None, "system"), "@google-cloud/vision": ("Google Cloud Vision", None, "system"), "@google-cloud/translate": ("Google Cloud Translate", None, "system"),
    "@slack/web-api": ("Slack API", "slack.com", "system"), "@octokit/rest": ("GitHub API", "api.github.com", "system"), "octokit": ("GitHub API", "api.github.com", "system"),
    "algoliasearch": ("Algolia API", None, "system"), "cloudinary": ("Cloudinary API", "api.cloudinary.com", "system"), "pusher": ("Pusher API", None, "system"),
    "paypal-rest-sdk": ("PayPal API", "api.paypal.com", "system"), "@paypal/checkout-server-sdk": ("PayPal API", "api.paypal.com", "system"), "braintree": ("Braintree API", None, "system"),
    "@sentry/node": ("Sentry", None, "system"), "newrelic": ("New Relic", None, "system"), "dd-trace": ("Datadog", None, "system"), "@opentelemetry/exporter-trace-otlp-http": ("OTLP collector", None, "system"),
    "lob": ("Lob API", "api.lob.com", "system"), "twitter": ("Twitter API", "api.twitter.com", "system"), "twitter-lite": ("Twitter API", "api.twitter.com", "system"), "instagram-node": ("Instagram API", None, "system"), "node-foursquare": ("Foursquare API", None, "system"), "lastfm": ("Last.fm API", None, "system"), "steam-web": ("Steam API", None, "system"), "pdfkit": None,
    "googleapis": ("Google APIs", "www.googleapis.com", "system"), "@googlemaps/google-maps-services-js": ("Google Maps API", "maps.googleapis.com", "system"),
}
IDP_RX = re.compile(r"^passport-(?P<p>[a-z0-9-]+)$")
GRPC_PKGS = {"@grpc/grpc-js", "grpc"}
READ_OPS = {"find", "findOne", "findById", "findMany", "findUnique", "findFirst", "get", "hget", "hgetall", "mget", "lrange", "smembers", "query", "select", "aggregate", "count", "countDocuments", "exists", "scan", "search", "all", "first", "where", "read", "getItem", "getObject", "listObjects", "receiveMessage", "lindex", "zrange", "keys", "exec"}
WRITE_OPS = {"save", "create", "insert", "insertOne", "insertMany", "update", "updateOne", "updateMany", "findOneAndUpdate", "findByIdAndUpdate", "upsert", "set", "hset", "hmset", "mset", "lpush", "rpush", "sadd", "zadd", "incr", "incrby", "decr", "del", "delete", "deleteOne", "deleteMany", "findOneAndDelete", "findByIdAndDelete", "remove", "destroy", "run", "put", "putItem", "putObject", "deleteObject", "upload", "sendMessage", "publish", "send", "produce", "expire", "setex", "add", "bulkCreate", "truncate", "drop"}
SQL_TABLE_RX = re.compile(r"\b(?:FROM|INTO|UPDATE|JOIN|TABLE)\s+[`\"']?([A-Za-z_][A-Za-z0-9_.]*)", re.I)
SECRET_LITERAL_RX = re.compile(r"(secret|password|passwd|api_?key|private_?key|token)\s*[:=]\s*['\"]([^'\"]{6,})['\"]", re.I)


def _callee_parts(sf, fn):
    """Return (root identifier, [member names]) for a callee expression. For chained calls such as
    Router().use(a).use the root is the innermost callee ("Router") and members the trailing names."""
    t = re.sub(r"\s+", "", sf.node_text(fn))
    if "(" in t:
        head = t.split("(")[0]
        tail = t.rsplit(")", 1)[-1].lstrip(".")
        parts = [p for p in re.split(r"[.?!]+", head) if p]
        tail_parts = [p for p in re.split(r"[.?!]+", tail) if p]
        if not parts:
            return None, []
        return parts[0], (parts[1:] + tail_parts)
    parts = [p for p in re.split(r"[.?!]+", t) if p]
    if not parts:
        return None, []
    return parts[0], parts[1:]


def _enclosing_function(node):
    p = node.parent
    while p is not None:
        if p.type in ("function_declaration", "function_expression", "arrow_function", "method_definition", "generator_function_declaration", "function"):
            return p
        p = p.parent
    return None


def _string_value(sf, node):
    if node is None:
        return None
    if node.type == "string":
        return sf.node_text(node)[1:-1]
    if node.type == "template_string":
        return sf.node_text(node)[1:-1]
    return None


def _host_from_url(url):
    if url is None:
        return None, None
    m = re.match(r"^(https?)://([^/:${}`'\"\s]+)", url)
    if m:
        return m.group(2).lower(), m.group(1)
    return None, None


def run(idx, facts):
    for sf in idx.files.values():
        if sf.lang not in ("javascript", "typescript", "tsx") or sf.is_test:
            continue
        _file(idx, sf, facts)


def _file(idx, sf, facts):
    root = sf.tree.root_node
    pkg_of = sf.bindings  # local name -> spec
    store_locals = {nm: STORE_PKGS[spec] for nm, spec in pkg_of.items() if spec in STORE_PKGS}
    client_locals = {nm for nm, spec in pkg_of.items() if spec in HTTP_CLIENT_PKGS}
    sdk_locals = {nm: spec for nm, spec in pkg_of.items() if spec in SDK_PKGS and SDK_PKGS[spec]}
    grpc_locals = {nm for nm, spec in pkg_of.items() if spec in GRPC_PKGS}
    model_locals = {}   # mongoose models / sequelize models / prisma client vars
    express_locals = set()
    router_locals = set()
    has_express = any(spec in ("express", "fastify", "koa", "@koa/router", "koa-router", "hono", "restify", "@hapi/hapi", "polka") for spec in pkg_of.values())
    is_app_file = False
    middleware_order = []
    raw_mounts = []   # (source_local, prefix, target_local, target_file, line)

    # imports as facts: store clients / sdk clients / idp
    for spec, line, names in sf.imports:
        if spec in STORE_PKGS:
            facts.add("store_access", DET, [_ev(sf, line, line)],
                      technology=STORE_PKGS[spec], operation="client_init", package=spec, file=sf.path)
        if spec in SDK_PKGS and SDK_PKGS[spec]:
            name, host, kind = SDK_PKGS[spec]
            facts.add("outbound_call", DET, [_ev(sf, line, line)], sdk_service=name, host=host, entity_kind=kind, protocol="https", package=spec, file=sf.path, operation="sdk_import", handler=None)
        m = IDP_RX.match(spec)
        if m and m.group("p") not in ("local", "jwt", "http", "http-bearer", "anonymous", "custom", "oauth2", "oauth"):
            facts.add("outbound_call", DET, [_ev(sf, line, line)], sdk_service=f"{m.group('p').replace('-', ' ').title()} identity provider", host=None, entity_kind="system", protocol="https", package=spec, file=sf.path, operation="oauth", handler=None)
            facts.add("control", DET, [_ev(sf, line, line)], control_kind="authn", name=f"OAuth via {spec}", scope="file", file=sf.path)
        if spec == "@prisma/client":
            model_locals["__prisma__"] = "prisma"

    # cross-file: a local imported from a project file that itself binds a store/sdk package
    for local, spec in list(pkg_of.items()):
        if not spec.startswith("."):
            continue
        tgt = idx.resolve(sf, spec)
        if not tgt:
            continue
        tf = idx.files[tgt]
        techs = sorted({STORE_PKGS[v] for v in tf.bindings.values() if v in STORE_PKGS})
        if not techs:  # one more hop: models/index.js -> ./tutorial.model.js -> mongoose
            for v in tf.bindings.values():
                t2 = idx.resolve(tf, v) if v.startswith(".") else None
                if t2:
                    techs += [STORE_PKGS[x] for x in idx.files[t2].bindings.values() if x in STORE_PKGS]
            techs = sorted(set(techs))
        sdks = sorted({v for v in tf.bindings.values() if v in SDK_PKGS and SDK_PKGS[v]})
        hint = local.lower()
        if techs and local not in store_locals:
            pick = next((t for t in techs if (t == "redis" and ("redis" in hint or "cache" in hint)) or (t in ("postgres", "mysql", "sqlite", "mssql") and ("pool" in hint or "db" in hint or "sql" in hint or "pg" in hint or "knex" in hint)) or (t == "mongodb" and ("mongo" in hint or "db" in hint or hint[:1].isupper())) or (t == "kafka" and "kafka" in hint) or (t == "rabbitmq" and ("amqp" in hint or "rabbit" in hint or "channel" in hint)) or (t == "s3" and "s3" in hint)), None)
            if pick or len(techs) == 1:
                store_locals[local] = pick or techs[0]
        if sdks and local not in sdk_locals and not local[:1].islower():
            sdk_locals[local] = sdks[0]
        if sdks and local not in sdk_locals and local[:1].islower() and not techs and any(local.lower().startswith(k) for k in ("stripe", "twilio", "mailer", "openai", "anthropic", "sendgrid", "slack", "s3", "ses", "sns")):
            sdk_locals[local] = sdks[0]

    # alias pass (run twice so chains resolve): const pool = new Pool(); const stripe = new Stripe(); const Tutorial = db.tutorials
    for _pass in (0, 1):
      for n in walk(root):
          if n.type == "variable_declarator":
              nm = n.child_by_field_name("name"); val = n.child_by_field_name("value")
              if nm is None or val is None or nm.type != "identifier":
                  continue
              v = val
              while v is not None and v.type in ("await_expression", "parenthesized_expression", "as_expression", "non_null_expression"):
                  v = v.named_children[0] if v.named_children else None
              if v is None:
                  continue
              rootname = None
              if v.type == "new_expression":
                  c = v.child_by_field_name("constructor"); rootname = sf.node_text(c).split(".")[0] if c is not None else None
              elif v.type == "call_expression":
                  f = v.child_by_field_name("function"); rootname = sf.node_text(f).split(".")[0].split("(")[0] if f is not None else None
              elif v.type == "member_expression":
                  rootname = sf.node_text(v).split(".")[0]
                  if rootname in store_locals and sf.node_text(nm) not in model_locals:
                      model_locals[sf.node_text(nm)] = (sf.node_text(v).split(".")[-1], store_locals[rootname])
              if not rootname:
                  continue
              local = sf.node_text(nm)
              if rootname in store_locals and local not in store_locals:
                  store_locals[local] = store_locals[rootname]
              elif rootname in sdk_locals and local not in sdk_locals:
                  sdk_locals[local] = sdk_locals[rootname]
              elif rootname in client_locals:
                  client_locals.add(local)
              elif rootname in grpc_locals:
                  grpc_locals.add(local)
    # pass 1: find handler function spans for route calls, express() app var, routers
    routes = []
    for n in walk(root):
        if n.type != "call_expression":
            continue
        fn = n.child_by_field_name("function"); args = n.child_by_field_name("arguments")
        if fn is None or args is None:
            continue
        ftxt = re.sub(r"\s+", "", sf.node_text(fn))
        # app = express()
        if ftxt in ("express", "fastify", "Fastify", "polka", "restify.createServer", "Hapi.server", "Hapi.Server", "new Hono", "new Koa") or ftxt.endswith(".createServer") and "http" not in ftxt:
            p = n.parent
            if p is not None and p.type == "variable_declarator":
                nm = p.child_by_field_name("name")
                if nm is not None:
                    express_locals.add(sf.node_text(nm)); is_app_file = True
        inner = n
        while inner is not None and inner.type == "call_expression":
            f_ = inner.child_by_field_name("function")
            if f_ is not None and f_.type == "member_expression" and f_.child_by_field_name("object") is not None and f_.child_by_field_name("object").type == "call_expression":
                inner = f_.child_by_field_name("object")
            else:
                break
        innermost = re.sub(r"\s+", "", sf.node_text(inner.child_by_field_name("function"))) if inner is not None and inner.child_by_field_name("function") is not None else ""
        if ftxt in ("express.Router", "Router", "new Router", "express.Router()", "new Hono", "new KoaRouter") or innermost in ("express.Router", "Router"):
            p = n.parent
            while p is not None and p.type in ("call_expression", "member_expression"):
                p = p.parent
            if p is not None and p.type == "variable_declarator":
                nm = p.child_by_field_name("name")
                if nm is not None:
                    router_locals.add(sf.node_text(nm))
            if innermost in ("express.Router", "Router"):
                router_locals.add("Router"); router_locals.add("express")
    if "app" in sf.bindings and sf.bindings["app"].startswith("."):
        pass
    # mongoose models: const User = mongoose.model('User', schema) / model('User', ...)
    for n in walk(root):
        if n.type == "call_expression":
            fn = n.child_by_field_name("function"); args = n.child_by_field_name("arguments")
            if fn is None or args is None: continue
            ftxt = re.sub(r"\s+", "", sf.node_text(fn))
            if ftxt in ("mongoose.model", "model", "sequelize.define", "db.define", "db.model") and args.named_child_count >= 1:
                nm = _string_value(sf, args.named_children[0])
                p = n.parent
                while p is not None and p.type in ("member_expression", "call_expression", "parenthesized_expression"):
                    p = p.parent
                if p is not None and p.type == "variable_declarator":
                    v = p.child_by_field_name("name")
                    if v is not None and nm:
                        tech = "mongodb" if "mongoose" in sf.bindings.values() or ftxt.startswith("mongoose") else ("unknown")
                        model_locals[sf.node_text(v)] = (nm, tech)
                # module.exports = mongoose.model('User', userSchema)
                elif p is not None and p.type == "assignment_expression" and nm:
                    model_locals["__default_model__"] = (nm, "mongodb")
    # imported models from other files: const User = require('../models/user') -> we cannot know the model name, use file basename
    for nm, spec in pkg_of.items():
        if spec.startswith(".") and re.search(r"model", spec, re.I) and nm[:1].isupper():
            model_locals.setdefault(nm, (nm, "mongodb" if "mongoose" in idx.files.get(idx.resolve(sf, spec) or "", sf).bindings.values() or any("mongoose" in v for v in idx.files[idx.resolve(sf, spec)].bindings.values()) else "unknown") if idx.resolve(sf, spec) else (nm, "unknown"))

    # variables assigned from env: const addr = process.env.X || 'localhost:1'
    env_of_var = {}
    for n in walk(root):
        if n.type == "variable_declarator":
            nm = n.child_by_field_name("name"); val = n.child_by_field_name("value")
            if nm is not None and val is not None and nm.type == "identifier" and "process.env." in sf.node_text(val):
                env_of_var[sf.node_text(nm)] = sf.node_text(val)
    # pass 2: everything else
    for n in walk(root):
        # secrets from env
        if n.type == "member_expression" and sf.node_text(n).startswith("process.env."):
            name = sf.node_text(n).split("process.env.", 1)[1].split(".")[0].split("[")[0]
            if SECRET_ENV_RX.search(name) and not name.endswith(("_URL", "_URI")):
                facts.add("config_value", DET, [_ev(sf, sf.line(n), sf.line(n))], name=name, data_class="secret", at_import=_enclosing_function(n) is None, file=sf.path)
        if n.type == "subscript_expression" and sf.node_text(n).startswith("process.env["):
            name = sf.node_text(n)[len("process.env["):].strip("]'\" ")
            if SECRET_ENV_RX.search(name) and not name.endswith(("_URL", "_URI")):
                facts.add("config_value", DET, [_ev(sf, sf.line(n), sf.line(n))], name=name, data_class="secret", at_import=_enclosing_function(n) is None, file=sf.path)
        # weaknesses: rejectUnauthorized:false, hard-coded secrets, http:// to non-local hosts
        if n.type == "pair":
            ptxt = re.sub(r"\s+", "", sf.node_text(n))
            if ptxt.startswith("rejectUnauthorized:false"):
                facts.add("weakness", DET, [_ev(sf, sf.line(n), sf.line(n))], weakness_kind="tls_verification_disabled", name="rejectUnauthorized: false", file=sf.path)
            m = SECRET_LITERAL_RX.match(sf.node_text(n))
            if m and not re.search(r"(process\.env|\$\{|example|changeme|your[-_ ]?)", sf.node_text(n), re.I):
                facts.add("weakness", DET, [_ev(sf, sf.line(n), sf.line(n))], weakness_kind="plaintext_credentials", name=f"hard-coded {m.group(1).lower()} literal", file=sf.path)
        if n.type == "new_expression":
            ctor = n.child_by_field_name("constructor")
            if ctor is not None and sf.node_text(ctor) in ("Schema", "mongoose.Schema"):
                args = n.child_by_field_name("arguments")
                if args is not None and args.named_child_count >= 1 and args.named_children[0].type == "object":
                    fields = _object_fields(sf, args.named_children[0])
                    if fields:
                        p = n.parent
                        while p is not None and p.type not in ("variable_declarator", "program", "assignment_expression"): p = p.parent
                        nm = sf.node_text(p.child_by_field_name("name")) if p is not None and p.type == "variable_declarator" else "schema"
                        facts.add("schema", DET, [_ev(sf, sf.line(n), sf.end_line(n))], name=nm, fields=fields, file=sf.path, schema_kind="mongoose")
            if ctor is not None and sf.node_text(ctor) in grpc_locals | {f"{g}.Client" for g in grpc_locals} or (ctor is not None and sf.node_text(ctor).endswith("Client") and n.child_by_field_name("arguments") is not None and any("grpc" in v for v in sf.bindings.values())):
                args = n.child_by_field_name("arguments")
                a0 = args.named_children[0] if args is not None and args.named_child_count else None
                addr = _string_value(sf, a0) if a0 is not None and a0.type == "string" else None
                if a0 is not None and addr is None:
                    m = re.search(r"process\.env\.([A-Z0-9_]+)", sf.node_text(a0)) or (re.search(r"process\.env\.([A-Z0-9_]+)", env_of_var.get(sf.node_text(a0), "")) if a0.type == "identifier" else None)
                    addr = ("env:" + m.group(1)) if m else None
                host = addr if (addr and addr.startswith("env:")) else ((addr or "").split(":")[0] or None)
                facts.add("outbound_call", DET, [_ev(sf, sf.line(n), sf.line(n))], sdk_service=None, host=host, entity_kind="system", protocol="grpc", package="grpc", file=sf.path, operation="grpc_client", handler=_handler_of(n, routes), insecure="credentials.createInsecure" in sf.text)
        if n.type == "object":
            kv = {}
            for pr in n.named_children:
                if pr.type == "pair":
                    kv[sf.node_text(pr.child_by_field_name("key")).strip("'\"")] = pr.child_by_field_name("value")
            if "path" in kv and "route" in kv and kv["path"].type == "string" and kv["route"].type == "identifier":
                at = sf.node_text(kv["route"])
                target = idx.resolve(sf, sf.bindings[at]) if at in sf.bindings else None
                if target:
                    facts.add("router_mount", DET, [_ev(sf, sf.line(n), sf.end_line(n))], prefix=_string_value(sf, kv["path"]), target_file=target, target_local=at, file=sf.path)
        if n.type != "call_expression":
            continue
        fn = n.child_by_field_name("function"); args = n.child_by_field_name("arguments")
        if fn is None or args is None:
            continue
        ftxt = re.sub(r"\s+", "", sf.node_text(fn))
        rootid, members = _callee_parts(sf, fn)
        nargs = args.named_children
        # zod / joi schemas
        if ftxt in ("z.object", "Joi.object", "joi.object", "yup.object", "Joi.object().keys") and nargs and nargs[0].type == "object":
            fields = _object_fields(sf, nargs[0])
            p = n.parent
            while p is not None and p.type not in ("variable_declarator", "pair", "program"): p = p.parent
            nm = sf.node_text(p.child_by_field_name("name")) if p is not None and p.type == "variable_declarator" else (sf.node_text(p.child_by_field_name("key")) if p is not None and p.type == "pair" else "schema")
            if fields:
                facts.add("schema", DET, [_ev(sf, sf.line(n), sf.end_line(n))], name=nm, fields=fields, file=sf.path, schema_kind="validation")
        # express-validator body('email') etc.
        if ftxt in ("body", "check", "param", "query") and nargs and nargs[0].type == "string":
            facts.add("schema", DET, [_ev(sf, sf.line(n), sf.line(n))], name="request fields", fields=[{"name": _string_value(sf, nargs[0]), "type": "string"}], file=sf.path, schema_kind="validation")
        # gRPC server: server.addService(X.service, impl)
        if members and members[-1] == "addService" and nargs:
            facts.add("entry_point", DET, [_ev(sf, sf.line(n), sf.end_line(n))], protocol="grpc", method="grpc", path=sf.node_text(nargs[0]).replace(".service", ""), file=sf.path, handler_span=None, route_controls=[])
        # routes: X.<verb>('/path', ...mw, handler)
        verb = members[-1] if members else None
        if verb in HTTP_VERBS | {"use", "route"} and nargs and nargs[0].type in ("string", "template_string") and (rootid in express_locals or rootid in router_locals or rootid in ("Router",) or (has_express and rootid not in client_locals and rootid not in store_locals and rootid not in sdk_locals and rootid in ("app", "router", "server", "api", "routes", "r") )):
            path = _string_value(sf, nargs[0])
            if not (path.startswith("/") or path == "*"):
                pass
            else:
                fn_args = [a for a in nargs[1:] if a.type in ("arrow_function", "function_expression", "function")]
                ref_args = [a for a in nargs[1:] if a.type in ("identifier", "member_expression", "call_expression")]
                if verb == "use":
                    # mount of imported router or middleware with path
                    for a in nargs[1:]:
                        if a.type in ("arrow_function", "function_expression", "function"):
                            continue
                        at = sf.node_text(a).split("\n")[0][:80]
                        target = idx.resolve(sf, sf.bindings[at]) if at in sf.bindings else (idx.resolve(sf, sf.bindings[at.split(".")[0]]) if at.split(".")[0] in sf.bindings else None)
                        file_is_router = bool(target and re.search(r"(Router\(|\.route\(|\.(get|post|put|patch|delete)\(\s*['\"`/])", idx.files[target].text))
                        looks_router = at in router_locals or file_is_router or re.search(r"rout", at, re.I)
                        if a.type == "identifier" and looks_router and (file_is_router or at in router_locals or not classify_control(at.split("(")[0])):
                            raw_mounts.append((_chain_owner(sf, n, rootid), path, at, target, sf.line(n)))
                        else:
                            kind = classify_control(at.split("(")[0])
                            middleware_order.append((at, sf.line(n), kind, path))
                            if kind:
                                facts.add("control", DET, [_ev(sf, sf.line(n), sf.line(n))], control_kind=kind, name=at.split("(")[0], scope="app" if rootid in express_locals else "router", path_prefix=path, file=sf.path, order=len(middleware_order))
                    continue
                if verb == "route":
                    continue  # app.route('/x').get(...) handled by the chained call below
                if not fn_args and not ref_args:
                    continue
                controls = []
                for a in nargs[1:-1] if (fn_args or ref_args) else []:
                    if a.type in ("identifier", "member_expression", "call_expression"):
                        at = sf.node_text(a).split("\n")[0][:80]; kind = classify_control(at.split("(")[0])
                        if kind:
                            cid = facts.add("control", DET, [_ev(sf, sf.line(a), sf.line(a))], control_kind=kind, name=at.split("(")[0][:60], scope="route", file=sf.path)
                            controls.append(cid)
                handler = nargs[-1]
                span = (handler.start_byte, handler.end_byte) if handler.type in ("arrow_function", "function_expression", "function") else None
                href = sf.node_text(handler) if span is None else None
                hmod = None
                if href:
                    hroot = href.split(".")[0].split("(")[0]
                    hmod = idx.resolve(sf, sf.bindings[hroot]) if hroot in sf.bindings else None
                fid = facts.add("entry_point", DET, [_ev(sf, sf.line(n), sf.end_line(n) if span else sf.line(n))], protocol="http", method=verb.upper() if verb != "all" else "ANY", path=path, file=sf.path, router=rootid, handler_span=span, route_controls=controls, handler_ref=href, handler_module=hmod, handler_symbol=(href.split(".")[-1] if href else None))
                routes.append((span, fid))
        # app.route('/x').get(handler)
        if verb in HTTP_VERBS and fn.type == "member_expression":
            obj = fn.child_by_field_name("object")
            # descend through chained verb calls until the .route(path) call
            hops = 0
            while obj is not None and obj.type == "call_expression" and hops < 8 and not sf.node_text(obj.child_by_field_name("function")).endswith(".route"):
                f2 = obj.child_by_field_name("function")
                obj = f2.child_by_field_name("object") if f2 is not None and f2.type == "member_expression" else None
                hops += 1
            if obj is not None and obj.type == "call_expression" and sf.node_text(obj.child_by_field_name("function")).endswith(".route"):
                oargs = obj.child_by_field_name("arguments")
                if oargs is not None and oargs.named_child_count and oargs.named_children[0].type == "string":
                    path = _string_value(sf, oargs.named_children[0]); handler = nargs[-1] if nargs else None
                    span = (handler.start_byte, handler.end_byte) if handler is not None and handler.type in ("arrow_function", "function_expression") else None
                    controls = []
                    for a in nargs[:-1]:
                        at = sf.node_text(a); kind = classify_control(at.split("(")[0])
                        if kind: controls.append(facts.add("control", DET, [_ev(sf, sf.line(a), sf.line(a))], control_kind=kind, name=at.split("(")[0][:60], scope="route", file=sf.path))
                    fid = facts.add("entry_point", DET, [_ev(sf, sf.line(n), sf.end_line(n))], protocol="http", method=verb.upper(), path=path, file=sf.path, router=_callee_parts(sf, obj.child_by_field_name("function"))[0], handler_span=span, route_controls=controls, handler_ref=None)
                    routes.append((span, fid))
        # app-level middleware without path: app.use(mw)
        if verb == "use" and (rootid in express_locals or rootid in router_locals) and nargs and nargs[0].type not in ("string", "template_string"):
            for a in nargs:
                if a.type in ("arrow_function", "function_expression", "function"):
                    middleware_order.append(("<inline function>", sf.line(n), None, None)); continue
                at = sf.node_text(a).split("\n")[0][:80]; kind = classify_control(at.split("(")[0])
                if a.type == "identifier":
                    target = idx.resolve(sf, sf.bindings[at]) if at in sf.bindings else None
                    if (target and (at in router_locals or re.search(r"(Router\(|\.route\(|\.(get|post|put|patch|delete)\(\s*['\"`/])", idx.files[target].text))) or at in router_locals:
                        raw_mounts.append((_chain_owner(sf, n, rootid), "", at, target, sf.line(n)))
                        continue
                middleware_order.append((at, sf.line(n), kind, None))
                if kind:
                    facts.add("control", DET, [_ev(sf, sf.line(n), sf.line(n))], control_kind=kind, name=re.sub(r"\(.*", "", at)[:60], scope="app" if rootid in express_locals else "router", path_prefix=None, file=sf.path, order=len(middleware_order))
                if re.match(r"cors\(\s*\)", at) or re.search(r"origin:\s*['\"]\*['\"]", at):
                    facts.add("weakness", DET, [_ev(sf, sf.line(n), sf.line(n))], weakness_kind="permissive_cors", name="cors() with default or wildcard origin", file=sf.path)
        # listen / https
        if verb == "listen" and rootid in express_locals | {"server", "httpServer"}:
            port = sf.node_text(nargs[0]) if nargs else "?"
            facts.add("listener", DET, [_ev(sf, sf.line(n), sf.line(n))], port=port[:40], tls=("https.createServer" in sf.text), file=sf.path)
        # store usage: <local>.<op>(...) where local bound to a store pkg or a model
        if rootid in store_locals or rootid in model_locals or (rootid == "prisma" or (rootid in sf.bindings and sf.bindings[rootid].endswith("prisma"))) or rootid in ("db", "pool", "client", "knex", "redis", "redisClient", "cache", "sequelize", "connection", "conn", "collection", "Model") and (store_locals or model_locals or any(s in sf.bindings.values() for s in STORE_PKGS)):
            op = members[-1] if members else None
            if op in READ_OPS or op in WRITE_OPS or (members and members[0] in ("query", "collection") and len(members) >= 1):
                operation = "read" if op in READ_OPS and op not in WRITE_OPS else ("write" if op in WRITE_OPS else "unknown")
                if op == "query" or op == "run" or op == "exec" or op == "execute":
                    sqltxt = sf.node_text(nargs[0]) if nargs else ""
                    operation = "write" if re.search(r"\b(INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\b", sqltxt, re.I) else ("read" if re.search(r"\bSELECT\b", sqltxt, re.I) else "unknown")
                tech = store_locals.get(rootid) or (model_locals.get(rootid, (None, None))[1] if rootid in model_locals else None) or ("unknown")
                logical = None
                if rootid in model_locals:
                    logical = model_locals[rootid][0]
                elif rootid in ("prisma",) or (rootid in sf.bindings and sf.bindings[rootid].endswith("prisma")):
                    logical = members[0] if len(members) >= 2 else None; tech = "unknown"
                elif op in ("query", "run", "exec", "execute") and nargs:
                    m = SQL_TABLE_RX.search(sf.node_text(nargs[0])); logical = m.group(1) if m else None
                elif tech == "redis" and nargs and nargs[0].type in ("string", "template_string"):
                    key = _string_value(sf, nargs[0]) or ""; logical = (re.split(r"[:$]", key)[0] + ":*") if key else None
                elif members and members[0] == "collection" and fn.type == "member_expression":
                    inner = fn.child_by_field_name("object")
                    if inner is not None and inner.type == "call_expression":
                        ia = inner.child_by_field_name("arguments")
                        if ia is not None and ia.named_child_count and ia.named_children[0].type == "string":
                            logical = _string_value(sf, ia.named_children[0]); tech = "mongodb"
                if tech == "unknown" and any(v in STORE_PKGS for v in sf.bindings.values()):
                    tech = sorted({STORE_PKGS[v] for v in sf.bindings.values() if v in STORE_PKGS})[0]
                facts.add("store_access", DET, [_ev(sf, sf.line(n), sf.line(n))], technology=tech, operation=operation, logical_name=logical, method=op, file=sf.path, handler=_handler_of(n, routes), local=rootid)
        # SQL literals with column lists -> table schema
        for a in nargs[:1]:
            if a.type in ("string", "template_string"):
                sql = sf.node_text(a)
                m = re.search(r"INSERT\s+INTO\s+[`\"']?([A-Za-z_][\w.]*)[`\"']?\s*\(([^)]*)\)", sql, re.I) or re.search(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"']?([A-Za-z_][\w.]*)[`\"']?\s*\(([^;]*)\)", sql, re.I | re.S)
                if m:
                    cols = [c.strip().strip('`"').split()[0] for c in m.group(2).split(",") if c.strip() and not c.strip().upper().startswith(("PRIMARY", "FOREIGN", "UNIQUE", "CONSTRAINT", "KEY", "INDEX"))]
                    if cols:
                        facts.add("schema", DET, [_ev(sf, sf.line(a), sf.end_line(a))], name=m.group(1), fields=[{"name": c, "type": "column"} for c in cols], file=sf.path, schema_kind="sql")
        # outbound http: axios.get(url) / fetch(url) / got(url) / http(s).request
        is_fetch = ftxt in ("fetch", "window.fetch", "globalThis.fetch")
        if rootid in client_locals or is_fetch or ftxt in ("http.request", "https.request", "http.get", "https.get"):
            url = _string_value(sf, nargs[0]) if nargs else None
            if url is None and nargs and nargs[0].type == "object":
                for pr in nargs[0].named_children:
                    if pr.type == "pair" and sf.node_text(pr.child_by_field_name("key")).strip("'\"") in ("url", "uri", "hostname", "host", "baseURL"):
                        url = _string_value(sf, pr.child_by_field_name("value"))
            host, scheme = _host_from_url(url)
            if url and not host and nargs[0].type == "template_string" and "process.env." in url:
                host = "env:" + re.search(r"process\.env\.([A-Z0-9_]+)", url).group(1)
            if url and not host and url.startswith("/"):
                continue  # relative URL: same-origin call from frontend code, not an outbound dependency
            if url is None and nargs and nargs[0].type in ("identifier", "member_expression"):
                host = "variable:" + sf.node_text(nargs[0])[:40]
            facts.add("outbound_call", DET, [_ev(sf, sf.line(n), sf.line(n))], sdk_service=None, host=host, entity_kind="system", protocol=(scheme or "https") if host and not host.startswith(("env:", "variable:")) else "unknown", package=sf.bindings.get(rootid, "fetch"), file=sf.path, operation=(members[-1] if members else "request"), handler=_handler_of(n, routes), url=url[:120] if url else None)
            if scheme == "http" and host and not host.startswith(LOCAL_HOSTS):
                facts.add("weakness", DET, [_ev(sf, sf.line(n), sf.line(n))], weakness_kind="unencrypted_transport", name=f"plain http:// to {host}", file=sf.path)
        # sdk usage: stripe.charges.create(...) etc.
        if rootid in sdk_locals and members:
            name, host, kind = SDK_PKGS[sdk_locals[rootid]]
            facts.add("outbound_call", DET, [_ev(sf, sf.line(n), sf.line(n))], sdk_service=name, host=host, entity_kind=kind, protocol="https" if name != "SMTP mail relay" else "smtp", package=sdk_locals[rootid], file=sf.path, operation=".".join(members)[:60], handler=_handler_of(n, routes))
        # nodemailer transport / sendMail
        if members and members[-1] == "sendMail":
            facts.add("outbound_call", DET, [_ev(sf, sf.line(n), sf.line(n))], sdk_service="SMTP mail relay", host=None, entity_kind="system", protocol="smtp", package="nodemailer", file=sf.path, operation="sendMail", handler=_handler_of(n, routes))
        # jwt.sign(payload, 'literal')
        if ftxt in ("jwt.sign", "jwt.verify") and len(nargs) >= 2 and nargs[1].type == "string":
            facts.add("weakness", DET, [_ev(sf, sf.line(n), sf.line(n))], weakness_kind="plaintext_credentials", name="JWT secret is a string literal", file=sf.path)
    # compose mounts through same-file routers: X.use('/p', localRouter) where localRouter.use(fileRouter)
    by_source = {}
    for src, prefix, tgt, tfile, line in raw_mounts:
        by_source.setdefault(src, []).append((prefix, tgt, tfile, line))
    def expand(local, depth=0):
        out = []
        for prefix, tgt, tfile, line in by_source.get(local, []):
            if tfile:
                out.append((prefix, tgt, tfile, line))
            elif depth < 4 and tgt in by_source:
                for p2, t2, f2, l2 in expand(tgt, depth + 1):
                    out.append((("/" + prefix.strip("/") if prefix.strip("/") else "") + ("/" + p2.strip("/") if p2.strip("/") else ""), t2, f2, l2))
        return out
    emitted = set()
    roots = [r for r in by_source if r in express_locals or r == "__default__"]
    # anonymous/exported routers ("Router", "express") and any local router that nothing else mounts are roots too
    mounted_locals = {tgt for lst in by_source.values() for _, tgt, tfile, _ in lst if not tfile}
    roots += [r for r in by_source if r not in express_locals and r != "__default__" and r not in mounted_locals]
    for r in roots:
        for prefix, tgt, tfile, line in expand(r):
            key = (prefix, tfile)
            if key in emitted:
                continue
            emitted.add(key)
            facts.add("router_mount", DET, [_ev(sf, line, line)], prefix=prefix or "", target_file=tfile, target_local=tgt, file=sf.path)
    if is_app_file:
        facts.add("app_entry", DET, [_ev(sf, 1, 1)], file=sf.path, middleware=[(m[0][:60], m[1], m[2], m[3]) for m in middleware_order])


def _chain_owner(sf, node, rootid):
    """For Router().use(...) chains, the variable the chain is assigned to, '__default__' for
    `export default Router()...`, else the callee root."""
    if rootid not in ("Router", "express"):
        return rootid
    p = node.parent
    while p is not None and p.type in ("call_expression", "member_expression", "parenthesized_expression"):
        p = p.parent
    if p is not None and p.type == "variable_declarator":
        nm = p.child_by_field_name("name")
        return sf.node_text(nm) if nm is not None else rootid
    if p is not None and p.type in ("export_statement",):
        return "__default__"
    if p is not None and p.type == "assignment_expression" and sf.node_text(p.child_by_field_name("left")).startswith("module.exports"):
        return "__default__"
    return rootid


def _handler_of(node, routes):
    for span, fid in routes:
        if span and span[0] <= node.start_byte and node.end_byte <= span[1]:
            return fid
    return None


def _object_fields(sf, obj):
    fields = []
    for pr in obj.named_children:
        if pr.type == "pair":
            k = sf.node_text(pr.child_by_field_name("key")).strip("'\"")
            v = pr.child_by_field_name("value")
            vt = sf.node_text(v)[:40] if v is not None else ""
            typ = re.sub(r"\s+", "", vt).split("(")[0].split(",")[0][:30]
            fields.append({"name": k, "type": typ or "unknown"})
        elif pr.type == "shorthand_property_identifier":
            fields.append({"name": sf.node_text(pr), "type": "unknown"})
    return fields


def _ev(sf, s, e):
    from ..model import evidence
    return evidence(sf, s, e, DET)
