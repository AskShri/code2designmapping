"""JavaScript / TypeScript detector (function-style code): Express-family routing (apps, routers,
mounts, mount tables, chained and anonymous routers, fastify plugins), middleware as controls,
store clients and models, outbound HTTP and SDK clients, gRPC, schemas, secrets and weaknesses.
Class/decorator frameworks (NestJS, TypeORM repositories) are handled in nest.py.
Coverage statement: literal route paths only; routers built in loops over non-literal tables are
reported as unresolved by synthesis.
"""
import json, os, re
from ..model import classify_control, is_secret_name, evidence
from ..index import walk, JS_LANGS
from .common import sql_operation, sql_table, sql_schema, host_of_url, is_local, looks_like_secret_literal, grpc_service_name

DET = "js@0.5"
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
    "@prisma/client": "sql", "sequelize": "sql", "typeorm": "sql", "knex": "sql", "objection": "sql", "drizzle-orm": "sql", "mikro-orm": "sql",
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
    "lob": ("Lob API", "api.lob.com", "system"), "twitter": ("Twitter API", "api.twitter.com", "system"), "twitter-lite": ("Twitter API", "api.twitter.com", "system"), "instagram-node": ("Instagram API", None, "system"), "node-foursquare": ("Foursquare API", None, "system"), "lastfm": ("Last.fm API", None, "system"), "steam-web": ("Steam API", None, "system"), 
    "googleapis": ("Google APIs", "www.googleapis.com", "system"), "@googlemaps/google-maps-services-js": ("Google Maps API", "maps.googleapis.com", "system"),
}
IDP_RX = re.compile(r"^passport-(?P<p>[a-z0-9-]+)$")
GRPC_PKGS = {"@grpc/grpc-js", "grpc"}
READ_OPS = {"find", "findOne", "findById", "findMany", "findUnique", "findFirst", "paginate", "findAndCountAll", "findAll", "findByPk", "findOneAndUpdate", "get", "hget", "hgetall", "mget", "lrange", "smembers", "query", "select", "aggregate", "count", "countDocuments", "exists", "scan", "search", "all", "first", "where", "read", "getItem", "getObject", "listObjects", "receiveMessage", "lindex", "zrange", "keys", "exec"}
WRITE_OPS = {"save", "create", "insert", "insertOne", "insertMany", "update", "updateOne", "updateMany", "findByIdAndUpdate", "upsert", "set", "hset", "hmset", "mset", "lpush", "rpush", "sadd", "zadd", "incr", "incrby", "decr", "del", "delete", "deleteOne", "deleteMany", "findOneAndDelete", "findByIdAndDelete", "remove", "destroy", "run", "put", "putItem", "putObject", "deleteObject", "upload", "sendMessage", "publish", "send", "produce", "expire", "setex", "add", "bulkCreate", "truncate", "drop"}

SECRET_LITERAL_RX = re.compile(r"^\s*['\"]?(\w*(?:secret|password|passwd|api_?key|private_?key|token)\w*)['\"]?\s*:\s*(['\"`])([^'\"`]{6,})\2", re.I)
APP_FACTORIES = ("express", "fastify", "Fastify", "polka", "restify.createServer", "new Hono", "Hono", "new Koa", "Koa", "jsonServer.create")
FUNC_NODES = ("arrow_function", "function_expression", "function")
ROUTERISH = ("app", "router", "server", "api", "routes", "fastify", "r")
SERVER_PKGS = ("express", "fastify", "koa", "@koa/router", "koa-router", "hono", "restify", "@hapi/hapi", "polka", "json-server")
ROUTER_FILE_RX = re.compile(r"(Router\(|\.route\(|\b(\w*[rR]oute[rs]?\w*|app|server|api|fastify)\.(get|post|put|patch|delete)\(\s*['\"`/])")


def run(idx, facts):
    for sf in idx.files.values():
        if sf.lang in JS_LANGS and not sf.is_test:
            _JsFile(idx, sf, facts).run()


def _txt(sf, node):
    return re.sub(r"\s+", "", sf.node_text(node)) if node is not None else ""


def _str(sf, node):
    if node is not None and node.type in ("string", "template_string"):
        return sf.node_text(node)[1:-1]
    return None


def _callee_parts(text):
    """'Router().use' -> ('Router', ['use']); 'a.b.c' -> ('a', ['b', 'c']); chains keep head root + tail names."""
    if "(" in text:
        head = text.split("(")[0]; tail = text.rsplit(")", 1)[-1].lstrip(".")
        parts = [p for p in re.split(r"[.?!]+", head) if p]
        return (parts[0], parts[1:] + [p for p in re.split(r"[.?!]+", tail) if p]) if parts else (None, [])
    parts = [p for p in re.split(r"[.?!]+", text) if p]
    return (parts[0], parts[1:]) if parts else (None, [])


def _in_function(node):
    p = node.parent
    while p is not None:
        if p.type in FUNC_NODES + ("function_declaration", "method_definition", "generator_function_declaration"):
            return True
        p = p.parent
    return False


def _in_condition(node):
    p = node.parent
    while p is not None and p.type not in ("program",) + FUNC_NODES + ("function_declaration", "method_definition"):
        if p.type in ("if_statement", "ternary_expression", "conditional_expression"):
            return True
        p = p.parent
    return False


def _object_pairs(sf, obj):
    out = {}
    for pr in obj.named_children:
        if pr.type == "pair":
            out[sf.node_text(pr.child_by_field_name("key")).strip("'\"")] = pr.child_by_field_name("value")
    return out


def _object_fields(sf, obj):
    fields = []
    for pr in obj.named_children:
        if pr.type == "pair":
            v = pr.child_by_field_name("value")
            typ = re.sub(r"\s+", "", sf.node_text(v)[:40]).split("(")[0].split(",")[0][:30] if v is not None else ""
            fields.append({"name": sf.node_text(pr.child_by_field_name("key")).strip("'\""), "type": typ or "unknown"})
        elif pr.type == "shorthand_property_identifier":
            fields.append({"name": sf.node_text(pr), "type": "unknown"})
    return fields


URLISH_ENV = re.compile(r"(URL|URI|HOST|ADDR|ADDRESS|ENDPOINT|BASE|SERVER|API_ROOT|DOMAIN)", re.I)


def _env_host(text):
    """The environment variable that supplies the host of a URL expression, if any: the variable in
    host position (`${process.env.API_URL}/x`, process.env.API_URL + '/x'), or one named like a URL.
    An API key interpolated into a query string is not a host."""
    m = re.match(r"^\s*[`'\"]?\s*(?:\$\{\s*)?process\.env\.([A-Za-z0-9_]+)", text)
    if m:
        return "env:" + m.group(1)
    for name in re.findall(r"process\.env\.([A-Za-z0-9_]+)", text):
        if URLISH_ENV.search(name):
            return "env:" + name
    return None


def _repo_has_server(idx):
    if not hasattr(idx, "_js_server_dep"):
        idx._js_server_dep = False
        for f in idx.config_files:
            if f.endswith("package.json"):
                try:
                    with open(os.path.join(idx.root, f), encoding="utf-8", errors="replace") as fh:
                        deps = json.load(fh)
                except Exception:  # noqa: BLE001
                    continue
                if isinstance(deps, dict) and any(isinstance(deps.get(k), dict) and any(p in SERVER_PKGS for p in deps[k]) for k in ("dependencies", "devDependencies")):
                    idx._js_server_dep = True
                    break
    return idx._js_server_dep


class _JsFile:
    def __init__(self, idx, sf, facts):
        self.idx, self.sf, self.facts = idx, sf, facts
        b = sf.bindings
        self.store_locals = {nm: STORE_PKGS[spec] for nm, spec in b.items() if spec in STORE_PKGS}
        self.client_locals = {nm for nm, spec in b.items() if spec in HTTP_CLIENT_PKGS}
        self.sdk_locals = {nm: spec for nm, spec in b.items() if SDK_PKGS.get(spec)}
        self.grpc_locals = {nm for nm, spec in b.items() if spec in GRPC_PKGS}
        self.model_locals = {}      # local -> (logical name, technology)
        self.instance_locals = {}   # local -> (logical name, technology) for model instances (doc.save())
        self.app_locals, self.router_locals = set(), set()
        self.has_server = any(spec in SERVER_PKGS for spec in b.values())
        if not self.has_server and _repo_has_server(idx) and re.search(r"(?:async\s+)?(?:function\s*\w*\s*)?\(\s*(fastify|app|router|server|instance)\b[^)]*\)\s*(?:=>|\{)", sf.text):
            self.has_server = True        # a plugin or route module that receives the server instance as a parameter
        self.env_of_var, self.base_url_of = {}, {}
        self.calls = [n for n in walk(sf.tree.root_node) if n.type == "call_expression"]
        self.declarators = [n for n in walk(sf.tree.root_node) if n.type == "variable_declarator"]

    def ev(self, node_or_line, end=None):
        if isinstance(node_or_line, int):
            return evidence(self.sf, node_or_line, end or node_or_line, DET)
        return evidence(self.sf, self.sf.line(node_or_line), end or self.sf.line(node_or_line), DET)

    def resolve_local(self, name):
        root = name.split(".")[0]
        return self.idx.resolve(self.sf, self.sf.bindings[root]) if root in self.sf.bindings else None

    # ------------------------------------------------------------------ driver
    def run(self):
        self._imports()
        self._cross_file_locals()
        self._models()
        self._inline_validation()
        self._aliases(); self._aliases()
        self._env_and_clients()
        self._routers()
        self._nextjs_routes()
        self._request_fields()
        self._secrets_and_literals()
        for n in self.calls:
            fn = n.child_by_field_name("function"); args = n.child_by_field_name("arguments")
            if fn is None or args is None:
                continue
            ftxt = _txt(self.sf, fn)
            root, members = _callee_parts(ftxt)
            nargs = args.named_children
            self._schemas(n, ftxt, nargs)
            self._routes(n, fn, ftxt, root, members, nargs)
            self._stores(n, fn, ftxt, root, members, nargs)
            self._outbound(n, ftxt, root, members, nargs)
        self.mount_tables_and_calls()
        self.grpc_clients()

    # ------------------------------------------------------------------ imports and locals
    def _imports(self):
        sf, facts = self.sf, self.facts
        for spec, line, names in sf.imports:
            if spec in STORE_PKGS:
                facts.add("store_access", DET, self.ev(line), file=sf.path, technology=STORE_PKGS[spec], operation="client_init", package=spec)
            if SDK_PKGS.get(spec):
                name, host, kind = SDK_PKGS[spec]
                facts.add("outbound_call", DET, self.ev(line), file=sf.path, protocol="smtp" if "SMTP" in name else "https", operation="sdk_import", sdk_service=name, host=host, entity_kind=kind, package=spec)
            m = IDP_RX.match(spec)
            if m and m.group("p") not in ("local", "jwt", "http", "http-bearer", "anonymous", "custom", "oauth2", "oauth", "oauth1", "oauth2-refresh"):
                facts.add("outbound_call", DET, self.ev(line), file=sf.path, protocol="https", operation="sdk_import", sdk_service=f"{m.group('p').replace('-', ' ').title()} identity provider", host=None, entity_kind="system", package=spec)

    def _cross_file_locals(self):
        """A local imported from a project file that itself wraps a store or SDK package."""
        idx, sf = self.idx, self.sf
        for local, spec in sorted(sf.bindings.items()):
            tgt = idx.resolve(sf, spec)
            if not tgt or tgt == sf.path:
                continue
            tf = idx.files[tgt]
            techs = {STORE_PKGS[v] for v in tf.bindings.values() if v in STORE_PKGS}
            if not techs:   # one more hop: models/index.js -> ./user.model.js -> mongoose
                for v in tf.bindings.values():
                    t2 = idx.resolve(tf, v)
                    if t2:
                        techs |= {STORE_PKGS[x] for x in idx.files[t2].bindings.values() if x in STORE_PKGS}
            techs = sorted(techs - {"unknown"}) or sorted(techs)
            hint = local.lower()
            if techs and local not in self.store_locals:
                rules = [("redis", ("redis", "cache")), ("postgres", ("pool", "db", "sql", "pg", "knex")), ("mysql", ("pool", "db", "sql", "knex")), ("sqlite", ("db", "sql")), ("mssql", ("pool", "db", "sql")),
                         ("mongodb", ("mongo", "db")), ("kafka", ("kafka",)), ("rabbitmq", ("amqp", "rabbit", "channel")), ("s3", ("s3", "bucket"))]
                pick = next((t for t, keys in rules if t in techs and (any(k in hint for k in keys) or (t == "mongodb" and local[:1].isupper()))), None)
                if pick or len(techs) == 1:
                    self.store_locals[local] = pick or techs[0]
            sdks = sorted(v for v in set(tf.bindings.values()) if SDK_PKGS.get(v))
            if sdks and local not in self.sdk_locals and (local[:1].isupper() or (not techs and any(hint.startswith(k) for k in ("stripe", "twilio", "mailer", "openai", "anthropic", "sendgrid", "slack", "s3", "ses", "sns")))):
                self.sdk_locals[local] = sdks[0]

    def _models(self):
        sf, idx = self.sf, self.idx
        mongoose_here = "mongoose" in sf.bindings.values()
        for n in self.calls:
            fn = n.child_by_field_name("function"); args = n.child_by_field_name("arguments")
            if fn is None or args is None or not args.named_child_count:
                continue
            ftxt = _txt(sf, fn)
            if ftxt not in ("mongoose.model", "model", "sequelize.define", "db.define", "db.model", "connection.model"):
                continue
            name = _str(sf, args.named_children[0])
            if not name:
                continue
            tech = "mongodb" if (mongoose_here or ftxt.startswith("mongoose")) and "define" not in ftxt else "sql"
            p = n.parent
            while p is not None and p.type in ("member_expression", "call_expression", "parenthesized_expression"):
                p = p.parent
            if p is not None and p.type == "variable_declarator" and p.child_by_field_name("name") is not None:
                self.model_locals[sf.node_text(p.child_by_field_name("name"))] = (name, tech)
            self.facts.add("store_access", DET, self.ev(n), file=sf.path, technology=tech, operation="model_definition", logical_name=name)
        # models imported from other files: the model's declared name when resolvable, else the local name
        for local, spec in sorted(sf.bindings.items()):
            if local in self.model_locals or not local[:1].isupper():
                continue
            tgt = self._follow_reexport(idx.resolve(sf, spec), local)
            if not tgt or not re.search(r"model", spec + tgt, re.I):
                continue
            ttext = idx.files[tgt].text
            m = re.search(r"(?:mongoose\.)?model\(\s*['\"](\w+)['\"]", ttext)
            uses_mongoose = "mongoose" in ttext
            if m or uses_mongoose or "sequelize" in ttext.lower():
                self.model_locals[local] = (m.group(1) if m and len(re.findall(r"\bmodel\(\s*['\"]", ttext)) == 1 else local, "mongodb" if uses_mongoose else "sql")
        if "@prisma/client" in sf.bindings.values():
            for local, spec in sf.bindings.items():
                if spec == "@prisma/client":
                    self.store_locals.setdefault(local, "sql")

    def _inline_validation(self):
        """Schema.parse(req.body), schema.validate(req.query), validationResult(req) inside a handler:
        input validation that runs in the handler rather than as middleware."""
        sf = self.sf
        for n in self.calls:
            fn = n.child_by_field_name("function"); args = n.child_by_field_name("arguments")
            if fn is None or args is None:
                continue
            ftxt = _txt(sf, fn)
            atxt = sf.node_text(args)
            on_request = re.search(r"\b(req|request|ctx\.request)\.(body|query|params|headers)\b", atxt)
            m = re.match(r"^([\w.]+)\.(parse|safeParse|parseAsync|safeParseAsync|validate|validateAsync|validateSync|assert)$", ftxt)
            if (m and on_request) or (ftxt in ("validationResult", "matchedData") and re.match(r"^\(\s*req\s*\)", atxt)):
                name = ftxt if len(ftxt) <= 60 else ftxt[-60:]
                self.facts.add("control", DET, self.ev(n), file=sf.path, control_kind="input_validation", name=name, scope="handler", handler_file=sf.path)

    def _follow_reexport(self, tgt, name, depth=0):
        """models/index.js: module.exports.User = require('./user.model'), export { default as User } from './user.model',
        or const User = require('./user.model'); module.exports = { User }. Returns the defining file."""
        idx = self.idx
        if not tgt or depth > 3 or tgt not in idx.files:
            return tgt
        tsf = idx.files[tgt]
        t = tsf.text
        n = re.escape(name)
        m = (re.search(r"(?:module\.)?exports\." + n + r"\s*=\s*require\(\s*['\"]([^'\"]+)['\"]", t)
             or re.search(r"export\s*\{[^}]*\b(?:default\s+as\s+)?" + n + r"\b[^}]*\}\s*from\s*['\"]([^'\"]+)['\"]", t))
        if m:
            nxt = idx.resolve(tsf, m.group(1))
            return self._follow_reexport(nxt, name, depth + 1) if nxt and nxt != tgt else tgt
        if name in tsf.bindings and re.search(r"(module\.exports\s*=\s*\{[^}]*\b" + n + r"\b|export\s*\{[^}]*\b" + n + r"\b)", t):
            nxt = idx.resolve(tsf, tsf.bindings[name])
            return self._follow_reexport(nxt, name, depth + 1) if nxt and nxt != tgt else tgt
        return tgt

    def _aliases(self):
        """const pool = new Pool(); const doc = await Model.findOne(); const Tutorial = db.tutorials"""
        sf = self.sf
        for n in self.declarators:
            nm = n.child_by_field_name("name"); v = n.child_by_field_name("value")
            if nm is None or v is None or nm.type != "identifier":
                continue
            while v is not None and v.type in ("await_expression", "parenthesized_expression", "as_expression", "non_null_expression"):
                v = v.named_children[0] if v.named_children else None
            if v is None:
                continue
            local = sf.node_text(nm)
            root = None
            if v.type == "new_expression":
                c = v.child_by_field_name("constructor"); root = sf.node_text(c).split(".")[0] if c is not None else None
            elif v.type == "call_expression":
                f = v.child_by_field_name("function")
                ft = _txt(sf, f)
                root = ft.split(".")[0].split("(")[0].strip() if f is not None else None
                last = ft.split("(")[0].split(".")[-1]
                if root in self.model_locals and local not in self.model_locals and (last in READ_OPS or last in ("create",)):
                    self.instance_locals[local] = self.model_locals[root]     # const doc = await Model.findOne(...)
                    continue
                if last in READ_OPS or last in WRITE_OPS or last in ("get", "post", "put", "patch", "delete", "request", "fetch", "json", "then") or ft == "fetch":
                    continue      # a query or response result is not a client
                if "createQueryBuilder" in ft or root in ("getRepository", "getManager", "getConnection", "getMongoRepository"):
                    continue      # a TypeORM query builder: the ORM detector records the access with its entity
            elif v.type == "member_expression":
                root = sf.node_text(v).split(".")[0]
                if root in self.store_locals and self.store_locals[root] == "mongodb" and local not in self.model_locals and root not in self.model_locals and local[:1].isupper():
                    self.model_locals[local] = (sf.node_text(v).split(".")[-1], self.store_locals[root])
                else:
                    continue
            if not root or root == local:
                continue
            if root in self.model_locals and v.type == "new_expression" and local not in self.model_locals:
                self.instance_locals[local] = self.model_locals[root]         # const todo = new Todo(...)
                continue
            if root in self.store_locals and local not in self.store_locals:
                self.store_locals[local] = self.store_locals[root]
            elif root in self.sdk_locals and local not in self.sdk_locals:
                self.sdk_locals[local] = self.sdk_locals[root]
            elif root in self.client_locals:
                self.client_locals.add(local)
            elif root in self.grpc_locals:
                self.grpc_locals.add(local)

    def _env_and_clients(self):
        sf = self.sf
        for n in self.declarators:
            nm = n.child_by_field_name("name"); v = n.child_by_field_name("value")
            if nm is None or v is None or nm.type != "identifier":
                continue
            vt = sf.node_text(v)
            if "process.env." in vt:
                self.env_of_var[sf.node_text(nm)] = vt
            if v.type == "call_expression" and _txt(sf, v.child_by_field_name("function")) in ("axios.create", "got.extend", "ky.create", "ky.extend"):
                self.client_locals.add(sf.node_text(nm))
                a = v.child_by_field_name("arguments")
                if a is not None and a.named_child_count and a.named_children[0].type == "object":
                    for k, val in _object_pairs(sf, a.named_children[0]).items():
                        if k in ("baseURL", "prefixUrl", "baseUrl") and val is not None:
                            t = sf.node_text(val)
                            h, _ = host_of_url(t.strip("'\"`"))
                            m = re.search(r"process\.env\.([A-Z0-9_]+)", t)
                            self.base_url_of[sf.node_text(nm)] = h or ("env:" + m.group(1) if m else "variable:" + t[:30])

    # ------------------------------------------------------------------ routers
    def _chain_owner(self, node, root):
        """The router object a call chain belongs to: the declared variable for `const x = Router().use(...)`,
        '__default__' for an exported anonymous chain, else the callee root."""
        if root not in ("Router", "express") and not root.startswith("require"):
            return root
        p = node.parent
        while p is not None and p.type in ("call_expression", "member_expression", "parenthesized_expression"):
            p = p.parent
        if p is not None and p.type == "variable_declarator" and p.child_by_field_name("name") is not None:
            return self.sf.node_text(p.child_by_field_name("name"))
        if p is not None and (p.type == "export_statement" or (p.type == "assignment_expression" and self.sf.node_text(p.child_by_field_name("left")).startswith("module.exports"))):
            return "__default__"
        return root

    NEXT_PAGES_RX = re.compile(r"(?:^|/)pages/(api/.*)\.(?:js|jsx|ts|tsx|mjs)$")
    NEXT_APP_RX = re.compile(r"(?:^|/)app/(.*?)/?route\.(?:js|ts|mjs)$")

    @staticmethod
    def _next_path(rel):
        segs = []
        for seg in rel.split("/"):
            if not seg or (seg.startswith("(") and seg.endswith(")")) or seg.startswith("@"):
                continue                                    # route groups and parallel-route slots are not URL segments
            m = re.fullmatch(r"\[{1,2}(?:\.\.\.)?(\w+)\]{1,2}", seg)
            segs.append("{" + m.group(1) + "}" if m else seg)
        if segs and segs[-1] == "index":
            segs.pop()
        return "/" + "/".join(segs)

    def _nextjs_routes(self):
        """Next.js file-system routing: pages/api/** default exports and app/**/route.ts method exports."""
        sf, idx = self.sf, self.idx
        if not getattr(idx, "_is_next", None):
            idx._is_next = any(f.endswith("package.json") and re.search(r'"next"\s*:', open(os.path.join(idx.root, f), encoding="utf-8", errors="replace").read())
                               for f in idx.config_files) or any(re.search(r"(^|/)next\.config\.(js|mjs|ts)$", f) for f in idx.files) or "no"
        if idx._is_next == "no":
            return
        mp, ma = self.NEXT_PAGES_RX.search(sf.path), self.NEXT_APP_RX.search(sf.path)
        if not (mp or ma):
            return
        path = self._next_path(mp.group(1) if mp else ma.group(1))
        self.facts.add("router", DET, self.ev(1), file=sf.path, local="<next>", own_prefix="", root=True)
        for n in walk(sf.tree.root_node):
            if n.type != "export_statement":
                continue
            text = sf.node_text(n)
            decl = n.child_by_field_name("declaration")
            if mp and text.startswith("export default"):
                val = n.child_by_field_name("value") or decl
                h = dict(handler_span=(sf.line(n), sf.end_line(n))) if val is None or val.type != "identifier" else dict(handler_ref=sf.node_text(val))
                self.facts.add("entry_point", DET, self.ev(n), file=sf.path, protocol="http", method="ANY", path=path, router="<next>", route_controls=[], **h)
            elif ma:
                m = re.match(r"export\s+(?:async\s+)?(?:function\s+|const\s+)(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b", text)
                if m:
                    self.facts.add("entry_point", DET, self.ev(n), file=sf.path, protocol="http", method=m.group(1), path=path, router="<next>", route_controls=[],
                                   handler_span=(sf.line(n), sf.end_line(n)))

    def _routers(self):
        sf, facts = self.sf, self.facts
        declared = {}
        for n in self.calls:
            fn = n.child_by_field_name("function")
            ftxt = _txt(sf, fn)
            inner = n   # innermost call of a chain: Router().use(a).use(b)
            while True:
                f_ = inner.child_by_field_name("function")
                obj = f_.child_by_field_name("object") if f_ is not None and f_.type == "member_expression" else None
                if obj is not None and obj.type == "call_expression":
                    inner = obj
                else:
                    break
            itxt = _txt(sf, inner.child_by_field_name("function"))
            is_app = (ftxt in APP_FACTORIES and self.has_server) or bool(re.match(r"^require\(['\"](express|fastify|polka)['\"]\)$", ftxt))
            is_router = itxt in ("express.Router", "Router", "newRouter", "KoaRouter", "newKoaRouter") or itxt.endswith(".Router") or (itxt in ("Hono",) and False)
            if not (is_app or is_router):
                continue
            p = n.parent
            if p is not None and p.type == "new_expression":
                p = p.parent
            while p is not None and p.type in ("call_expression", "member_expression", "parenthesized_expression", "await_expression"):
                p = p.parent
            local = None
            if p is not None and p.type == "variable_declarator" and p.child_by_field_name("name") is not None and p.child_by_field_name("name").type == "identifier":
                local = sf.node_text(p.child_by_field_name("name"))
            elif is_router and p is not None and (p.type == "export_statement" or (p.type == "assignment_expression" and sf.node_text(p.child_by_field_name("left")).startswith("module.exports"))):
                local = "__default__"
            if not local or local in declared:
                continue
            declared[local] = is_app
            (self.app_locals if is_app else self.router_locals).add(local)
        # `new Hono()` / `new Koa()` style apps
        for n in self.declarators:
            v = n.child_by_field_name("value"); nm = n.child_by_field_name("name")
            if v is not None and nm is not None and v.type == "new_expression" and self.has_server:
                ctor = _txt(sf, v.child_by_field_name("constructor"))
                if ctor in ("Hono", "Koa", "Elysia") and sf.node_text(nm) not in declared:
                    declared[sf.node_text(nm)] = True; self.app_locals.add(sf.node_text(nm))
                elif ctor in ("Router", "KoaRouter") and sf.node_text(nm) not in declared:
                    declared[sf.node_text(nm)] = False; self.router_locals.add(sf.node_text(nm))
        for local, is_app in sorted(declared.items()):
            line = 1
            facts.add("router", DET, self.ev(line), file=sf.path, local=local, own_prefix="", root=bool(is_app))
        if self.app_locals:
            facts.add("app", DET, self.ev(1), file=sf.path, framework="express-family")
        self._declared_routers = set(declared)

    def _ensure_router(self, local, node):
        """Routes registered on a function parameter (module.exports = app => {...}, fastify plugins)."""
        if local not in self._declared_routers:
            self._declared_routers.add(local)
            self.router_locals.add(local)
            self.facts.add("router", DET, self.ev(node), file=self.sf.path, local=local, own_prefix="", root=False)

    def _is_routerish(self, root):
        if root in self.app_locals or root in self.router_locals or root in ("Router",):
            return True
        if not (self.has_server and root in ROUTERISH and root not in self.client_locals and root not in self.store_locals and root not in self.sdk_locals):
            return False
        spec = self.sf.bindings.get(root)
        if spec is None:
            return True
        if not spec.startswith("."):
            return spec.split("/")[0] in SERVER_PKGS            # `import api from "axios"` is a client
        tgt = self.idx.resolve(self.sf, spec)               # an imported object is a router only if its file builds one
        return bool(tgt and re.search(r"\b(express|Router|fastify|Koa|new\s+Hono|restify\.createServer)\s*\(", self.idx.files[tgt].text))

    def _file_is_router(self, target):
        return bool(target and ROUTER_FILE_RX.search(self.idx.files[target].text))

    def _control(self, node, text, scope, router=None, path_prefix=None):
        text = text.split("\n")[0][:80]
        name = text.split("(")[0]
        args = text[len(name):].strip("()") if "(" in text else ""
        kind = classify_control(name, args)
        if not kind:
            return None
        attrs = dict(file=self.sf.path, control_kind=kind, name=name[:60], scope=scope)
        if scope == "router":
            attrs.update(router=router, path_prefix=path_prefix, ordered=True, conditional=_in_condition(node))
        return self.facts.add("control", DET, self.ev(node), **attrs)

    def _handler(self, handler):
        """Entry-point handler attributes for an inline function or a reference."""
        sf = self.sf
        if handler is None:
            return {}
        if handler.type in FUNC_NODES:
            return dict(handler_span=(sf.line(handler), sf.end_line(handler)))
        if handler.type == "call_expression":      # wrapper(handlerRef) or wrapper(async () => ...)
            a = handler.child_by_field_name("arguments")
            inner = [x for x in (a.named_children if a is not None else []) if x.type in FUNC_NODES + ("identifier", "member_expression")]
            if inner:
                return self._handler(inner[-1])
        if handler.type in ("identifier", "member_expression"):
            return dict(handler_ref=sf.node_text(handler)[:120])
        return {}

    def _routes(self, n, fn, ftxt, root, members, nargs):
        sf, facts = self.sf, self.facts
        if root is None or not members:
            return
        verb = members[-1]
        # gRPC server registration
        if verb == "addService" and nargs:
            facts.add("entry_point", DET, self.ev(n), file=sf.path, protocol="grpc", method="grpc", path=grpc_service_name(sf.node_text(nargs[0]).replace(".service", "")), router="<grpc>", handler_scope="file")
            return
        if verb == "listen" and (root in self.app_locals or root in ("server", "httpServer", "app")) and self.has_server:
            facts.add("listener", DET, self.ev(n), file=sf.path, port=sf.node_text(nargs[0])[:40] if nargs else "?", tls=("https.createServer" in sf.text))
            return
        # fastify.register(plugin, { prefix }) and routesFn(app) / require('./routes')(app)
        if verb == "register" and root in self.app_locals | self.router_locals and nargs:
            a0 = nargs[0]
            if a0.type == "call_expression" and _txt(sf, a0.child_by_field_name("function")) == "require":   # register(require('./x'), ...)
                ra = a0.child_by_field_name("arguments")
                spec = _str(sf, ra.named_children[0]) if ra is not None and ra.named_child_count else None
                target = self.idx.resolve(sf, spec) if spec else None
            else:
                target = self.resolve_local(sf.node_text(a0))
            prefix = ""
            if len(nargs) > 1 and nargs[1].type == "object":
                pv = _object_pairs(sf, nargs[1]).get("prefix"); prefix = _str(sf, pv) or ""
            if target:
                facts.add("router_mount", DET, self.ev(n), file=sf.path, parent=root, prefix=prefix, child_file=target, child_local=None)
            else:
                self._control(n, sf.node_text(nargs[0]), "router", router=root)
            return
        if not members[:-1] and nargs and all(a.type == "identifier" and sf.node_text(a) in self.app_locals | self.router_locals for a in nargs[:1]) and verb == root:
            pass
        if verb == "addHook" and len(nargs) >= 2 and _str(sf, nargs[0]) in ("onRequest", "preHandler", "preValidation", "preParsing"):
            owner = self._chain_owner(n, root)
            if owner not in self._declared_routers:
                self._ensure_router(owner, n)
            self._control(n, sf.node_text(nargs[1]).split("\n")[0][:80], "router", router=owner)   # fastify.addHook('onRequest', fastify.authenticate)
            return
        if verb not in HTTP_VERBS and verb not in ("use", "route"):
            # routesFn(app): a function imported from a project file receives the app or a router
            return
        owner = self._chain_owner(n, root)
        if not self._is_routerish(owner) and not self._is_routerish(root):
            return
        first_str = nargs and nargs[0].type in ("string", "template_string")
        chained_route = None
        if verb in HTTP_VERBS and fn.type == "member_expression":
            obj = fn.child_by_field_name("object"); hops = 0
            while obj is not None and obj.type == "call_expression" and hops < 8 and not _txt(sf, obj.child_by_field_name("function")).endswith(".route"):
                f2 = obj.child_by_field_name("function")
                obj = f2.child_by_field_name("object") if f2 is not None and f2.type == "member_expression" else None
                hops += 1
            if obj is not None and obj.type == "call_expression" and _txt(sf, obj.child_by_field_name("function")).endswith(".route"):
                oa = obj.child_by_field_name("arguments")
                if oa is not None and oa.named_child_count and oa.named_children[0].type in ("string", "template_string"):
                    chained_route = _str(sf, oa.named_children[0])
        if verb == "use":
            path = _str(sf, nargs[0]) if first_str else None
            rest = nargs[1:] if first_str else nargs
            if owner not in self._declared_routers:
                self._ensure_router(owner, n)
            flat = []
            for a in rest:
                flat += list(a.named_children) if a.type == "array" else [a]
            for a in flat:
                if a.type in FUNC_NODES:
                    continue
                at = sf.node_text(a).split("\n")[0][:80]
                if a.type == "call_expression" and _txt(sf, a.child_by_field_name("function")) == "require":
                    ra = a.child_by_field_name("arguments")
                    spec = _str(sf, ra.named_children[0]) if ra is not None and ra.named_child_count else None
                    tfile = self.idx.resolve(sf, spec) if spec else None
                    if tfile:
                        facts.add("router_mount", DET, self.ev(n), file=sf.path, parent=owner, prefix=path or "", child_file=tfile, child_local=None)
                        continue
                target = self.resolve_local(at) if a.type in ("identifier", "member_expression") else None
                local_router = a.type == "identifier" and at in self.router_locals
                if a.type == "identifier" and (local_router or self._file_is_router(target) or (path and re.search(r"rout", at, re.I) and not classify_control(at))):
                    facts.add("router_mount", DET, self.ev(n), file=sf.path, parent=owner, prefix=path or "", child_file=sf.path if local_router and not target else (target or sf.path), child_local=at if (local_router and not target) else None)
                else:
                    self._control(n, at, "router", router=owner, path_prefix=path)
                    if re.match(r"cors\(\s*\)", at) or re.search(r"origin:\s*(['\"]\*['\"]|true)", sf.node_text(a)):
                        facts.add("weakness", DET, self.ev(n), file=sf.path, weakness_kind="permissive_cors", name="cors() with default or wildcard origin")
            return
        if verb == "route":
            return
        path = chained_route if chained_route is not None else (_str(sf, nargs[0]) if first_str else None)
        if path is None or not (path.startswith("/") or path in ("*", "")):
            return
        handlers = list(nargs if chained_route is not None else nargs[1:])
        if not handlers:
            return
        if owner not in self._declared_routers:
            self._ensure_router(owner, n)
        mids = []
        for a in handlers[:-1]:
            mids += list(a.named_children) if a.type == "array" else [a]
        for a in [x for x in mids if x.type == "object"]:          # fastify route options: { preHandler: [auth], onRequest: auth }
            for k, v in _object_pairs(sf, a).items():
                if k in ("preHandler", "onRequest", "preValidation"):
                    mids += list(v.named_children) if v.type == "array" else [v]
        controls = [c for c in (self._control(a, sf.node_text(a), "route") for a in mids if a.type in ("identifier", "member_expression", "call_expression")) if c]
        attrs = self._handler(handlers[-1])
        if not attrs and verb == "options" and handlers[-1].type == "call_expression":
            attrs = dict(handler_ref=_txt(sf, handlers[-1].child_by_field_name("function")))   # app.options('*', cors()): preflight
        if not attrs:
            return
        facts.add("entry_point", DET, self.ev(n, sf.end_line(n) if "handler_span" in attrs else None), file=sf.path, protocol="http",
                  method=verb.upper() if verb != "all" else "ANY", path=path, router=owner, route_controls=controls, **attrs)

    def mount_tables_and_calls(self):
        """{ path: '/auth', route: authRoute } tables and routesFn(app) calls."""
        sf, facts, idx = self.sf, self.facts, self.idx
        for n in walk(sf.tree.root_node):
            if n.type == "object":
                kv = _object_pairs(sf, n)
                if "path" in kv and "route" in kv and kv["path"] is not None and kv["route"] is not None and kv["path"].type == "string" and kv["route"].type == "identifier":
                    target = self.resolve_local(sf.node_text(kv["route"]))
                    if target:
                        parent = sorted(self.router_locals | self.app_locals)[0] if (self.router_locals | self.app_locals) else "router"
                        cond = False
                        p = n.parent
                        while p is not None and p.type != "variable_declarator":
                            p = p.parent
                        table = sf.node_text(p.child_by_field_name("name")) if p is not None and p.child_by_field_name("name") is not None else None
                        if table:   # the table is conditional when its forEach sits inside an if
                            for c in self.calls:
                                if _txt(sf, c.child_by_field_name("function")) == f"{table}.forEach" and _in_condition(c):
                                    cond = True
                        facts.add("router_mount", DET, self.ev(n, sf.end_line(n)), file=sf.path, parent=parent, prefix=_str(sf, kv["path"]) or "", child_file=target, child_local=None, conditional=cond)
        for n in self.calls:
            fn = n.child_by_field_name("function"); args = n.child_by_field_name("arguments")
            if fn is None or args is None or not args.named_child_count:
                continue
            a0 = args.named_children[0]
            if a0.type != "identifier" or sf.node_text(a0) not in self.app_locals | self.router_locals:
                continue
            target = None
            if fn.type == "identifier":
                target = self.resolve_local(sf.node_text(fn))
            elif fn.type == "call_expression" and _txt(sf, fn.child_by_field_name("function")) == "require":
                ra = fn.child_by_field_name("arguments")
                spec = _str(sf, ra.named_children[0]) if ra is not None and ra.named_child_count else None
                target = idx.resolve(sf, spec) if spec else None
            if target and self._file_is_router(target):
                facts.add("router_mount", DET, self.ev(n), file=sf.path, parent=sf.node_text(a0), prefix="", child_file=target, child_local=None)

    # ------------------------------------------------------------------ schemas, secrets, weaknesses
    def _schemas(self, n, ftxt, nargs):
        sf = self.sf
        if ftxt in ("z.object", "Joi.object", "joi.object", "yup.object", "Joi.object().keys", "Yup.object") and nargs and nargs[0].type == "object":
            fields = _object_fields(sf, nargs[0])
            p = n.parent
            while p is not None and p.type not in ("variable_declarator", "pair", "program"):
                p = p.parent
            name = "schema"
            if p is not None and p.type == "variable_declarator" and p.child_by_field_name("name") is not None:
                name = sf.node_text(p.child_by_field_name("name"))
            elif p is not None and p.type == "pair":
                name = sf.node_text(p.child_by_field_name("key")).strip("'\"")
                gp = p.parent
                while gp is not None and gp.type not in ("variable_declarator", "program"):
                    gp = gp.parent
                if gp is not None and gp.type == "variable_declarator" and gp.child_by_field_name("name") is not None:
                    name = sf.node_text(gp.child_by_field_name("name")) + "." + name
            if fields:
                self.facts.add("schema", DET, self.ev(n, sf.end_line(n)), file=sf.path, name=name, fields=fields, schema_kind="validation")
        elif ftxt in ("body", "check", "param", "query") and nargs and nargs[0].type == "string" and "express-validator" in sf.bindings.values():
            self.facts.add("schema", DET, self.ev(n), file=sf.path, name="request fields", fields=[{"name": _str(sf, nargs[0]), "type": "string"}], schema_kind="request")
        elif nargs and nargs[0].type in ("string", "template_string"):
            hit = sql_schema(sf.node_text(nargs[0]))
            if hit:
                self.facts.add("schema", DET, self.ev(nargs[0], sf.end_line(nargs[0])), file=sf.path, name=hit[0], fields=[{"name": c, "type": "column"} for c in hit[1]], schema_kind="sql")

    def _request_fields(self):
        """req.body.email, const { email, password } = req.body, req.query.q -> one request schema per line."""
        sf = self.sf
        by_line = {}
        for n in walk(sf.tree.root_node):
            if n.type == "member_expression":
                t = _txt(sf, n)
                if re.match(r"^(req|request|ctx\.request)\.(body|query)\.\w+$", t):
                    by_line.setdefault(sf.line(n), set()).add(t.split(".")[-1])
            elif n.type == "variable_declarator":
                v = n.child_by_field_name("value"); nm = n.child_by_field_name("name")
                if v is not None and nm is not None and nm.type == "object_pattern" and re.match(r"^(req|request|ctx\.request)\.(body|query)$", _txt(sf, v)):
                    by_line.setdefault(sf.line(n), set()).update(sf.node_text(c) for c in walk(nm) if c.type == "shorthand_property_identifier_pattern")
        for line, fields in sorted(by_line.items()):
            if fields:
                self.facts.add("schema", DET, self.ev(line), file=sf.path, name="request fields", fields=[{"name": f, "type": "request"} for f in sorted(fields)], schema_kind="request")

    def _secrets_and_literals(self):
        sf, facts = self.sf, self.facts
        seen = set()
        for n in walk(sf.tree.root_node):
            if n.type == "member_expression" and sf.node_text(n).startswith("process.env.") and n.parent is not None and n.parent.type != "member_expression":
                name = sf.node_text(n).split("process.env.", 1)[1].split(".")[0].split("[")[0]
            elif n.type == "subscript_expression" and sf.node_text(n).startswith("process.env["):
                name = sf.node_text(n)[len("process.env["):].strip("]'\" ")
            elif n.type == "pair":
                t = sf.node_text(n)
                if _txt(sf, n).startswith("rejectUnauthorized:false"):
                    facts.add("weakness", DET, self.ev(n), file=sf.path, weakness_kind="tls_verification_disabled", name="rejectUnauthorized: false")
                m = SECRET_LITERAL_RX.match(t)
                if m and looks_like_secret_literal(m.group(3)) and not re.search(r"(regex|pattern|message|label|placeholder|description|type|name|field|header|key)$", m.group(1), re.I):
                    facts.add("weakness", DET, self.ev(n), file=sf.path, weakness_kind="plaintext_credentials", name=f"hard-coded {m.group(1)} literal")
                continue
            else:
                continue
            if is_secret_name(name) and name not in seen:
                seen.add(name)
                facts.add("config_value", DET, self.ev(n), file=sf.path, name=name, data_class="secret")

    # ------------------------------------------------------------------ stores
    def _stores(self, n, fn, ftxt, root, members, nargs):
        sf = self.sf
        if root is None or not members or root in ("this",):
            return
        is_prisma = root == "prisma" or (root in sf.bindings and sf.bindings[root].lower().endswith("prisma")) or self.store_locals.get(root) == "sql" and len(members) >= 2 and "@prisma/client" in " ".join(self.idx.files[self.resolve_local(root)].bindings.values() if self.resolve_local(root) else sf.bindings.values())
        if root in self.instance_locals and root not in self.model_locals and root not in self.store_locals:
            if len(members) == 1 and members[0] in ("save", "remove", "delete", "deleteOne", "updateOne", "update", "destroy"):
                logical, tech = self.instance_locals[root]
                self.facts.add("store_access", DET, self.ev(n), file=sf.path, technology=tech, operation="write", logical_name=logical, method=members[0])
            return
        if members[-1] in ("exec", "then", "catch", "lean", "toArray") and "(" in ftxt:
            return   # the access is the call this one is chained on
        if root in ("getRepository", "getManager", "getConnection", "getMongoRepository") or "createQueryBuilder" in ftxt:
            return   # TypeORM: the ORM detector records the access with its entity
        known = root in self.store_locals or root in self.model_locals or is_prisma
        generic = root in ("db", "pool", "client", "knex", "redis", "redisClient", "cache", "sequelize", "connection", "conn", "collection") and (self.store_locals or self.model_locals or any(v in STORE_PKGS for v in sf.bindings.values()))
        if not (known or generic):
            return
        op = members[-1]
        if not (op in READ_OPS or op in WRITE_OPS):
            return
        operation = "read" if op in READ_OPS and op not in WRITE_OPS else "write"
        tech = self.store_locals.get(root) or (self.model_locals[root][1] if root in self.model_locals else None)
        logical = None
        if root in self.model_locals:
            logical = self.model_locals[root][0]
        elif is_prisma:
            logical = members[0] if len(members) >= 2 else None
            tech = "sql"
        elif op in ("query", "run", "exec", "execute", "all", "get") and nargs and nargs[0].type in ("string", "template_string") and re.search(r"\b(SELECT|INSERT|UPDATE|DELETE|CREATE)\b", sf.node_text(nargs[0]), re.I):
            sql = sf.node_text(nargs[0]); operation = sql_operation(sql); logical = sql_table(sql)
        elif tech == "redis" and nargs and nargs[0].type in ("string", "template_string"):
            key = _str(sf, nargs[0]) or ""
            logical = (re.split(r"[:$]", key)[0] + ":*") if re.split(r"[:$]", key)[0] and re.search(r"[:$]", key) else None
        elif "collection" in members and fn.type == "member_expression":
            m = re.search(r"\.collection\(\s*['\"](\w+)['\"]", ftxt)
            if m:
                logical = m.group(1); tech = "mongodb"
        if not tech:
            techs = sorted({STORE_PKGS[v] for v in sf.bindings.values() if v in STORE_PKGS} - {"unknown"})
            tech = techs[0] if len(techs) == 1 else "unknown"
        if tech == "unknown" and root in ("knex", "sequelize", "db", "pool", "connection", "conn"):
            tech = "sql"
        self.facts.add("store_access", DET, self.ev(n), file=sf.path, technology=tech, operation=operation, logical_name=logical, method=op)

    # ------------------------------------------------------------------ outbound
    def _outbound(self, n, ftxt, root, members, nargs):
        sf, facts = self.sf, self.facts
        if root is None:
            return
        # gRPC clients: new proto.Service(addr, credentials)
        is_fetch = ftxt in ("fetch", "window.fetch", "globalThis.fetch")
        http_method = (not members) or members[-1] in ("get", "post", "put", "patch", "delete", "head", "options", "request", "fetch", "paginate", "stream")
        if (root in self.client_locals and http_method) or is_fetch or ftxt in ("http.request", "https.request", "http.get", "https.get"):
            a0 = nargs[0] if nargs else None
            url = _str(sf, a0)
            if url is None and a0 is not None and a0.type == "object":
                for k, v in _object_pairs(sf, a0).items():
                    if k in ("url", "uri", "hostname", "host", "baseURL"):
                        url = _str(sf, v) or url
            if url is None and a0 is not None and a0.type == "binary_expression":
                m = re.search(r"['\"`](https?://[^'\"`]+)", sf.node_text(a0)); url = m.group(1) if m else None
            host, scheme = host_of_url(url)
            if url and not host:
                env = _env_host(url)
                if env:
                    host = env
                else:
                    for var in re.findall(r"\$\{\s*([A-Za-z_]\w*)", url):
                        if var in self.env_of_var:
                            m2 = re.search(r"process\.env\.([A-Z0-9_]+)", self.env_of_var[var])
                            if m2: host = "env:" + m2.group(1); break
                        if var in self.base_url_of:
                            host = self.base_url_of[var]; break
            if url is None and root in self.base_url_of:
                host = self.base_url_of[root]
            if not host and url is not None and (url.startswith("/") or not re.match(r"^\s*(\$\{|https?:)", url)):
                return   # relative URL: a same-origin call, not an outbound dependency
            if not host and url is None and a0 is not None and a0.type in ("identifier", "member_expression"):
                v = sf.node_text(a0)
                val = self.env_of_var.get(v, v)
                lit_host, lit_scheme = host_of_url((re.search(r"https?://[A-Za-z0-9.-]+[^'\"`\s]*", val) or [None])[0]) if re.search(r"https?://[A-Za-z0-9.-]", val) else (None, None)
                if lit_host:
                    host, scheme = lit_host, lit_scheme
                else:
                    host = _env_host(val) or "variable:" + v[:40]
            if not host:
                host = "variable:" + (url or "?")[:40]
            resolved = not host.startswith(("env:", "variable:"))
            facts.add("outbound_call", DET, self.ev(n), file=sf.path, protocol=(scheme or "https") if resolved else "unknown", operation=members[-1] if members else "request",
                      sdk_service=None, host=host, entity_kind="system", package=sf.bindings.get(root, "fetch"))
            if scheme == "http" and resolved and not is_local(host):
                facts.add("weakness", DET, self.ev(n), file=sf.path, weakness_kind="unencrypted_transport", name=f"plain http:// to {host}")
            return
        if root in self.sdk_locals and members:
            name, host, kind = SDK_PKGS[self.sdk_locals[root]]
            facts.add("outbound_call", DET, self.ev(n), file=sf.path, protocol="smtp" if "SMTP" in name else "https", operation=".".join(members)[:60], sdk_service=name, host=host, entity_kind=kind, package=self.sdk_locals[root])
            return
        if members and members[-1] == "sendMail":
            facts.add("outbound_call", DET, self.ev(n), file=sf.path, protocol="smtp", operation="sendMail", sdk_service="SMTP mail relay", host=None, entity_kind="system", package="nodemailer")
            return
        if ftxt in ("jwt.sign", "jwt.verify") and len(nargs) >= 2 and nargs[1].type == "string" and looks_like_secret_literal(sf.node_text(nargs[1])):
            facts.add("weakness", DET, self.ev(n), file=sf.path, weakness_kind="plaintext_credentials", name="JWT secret is a string literal")

    def grpc_clients(self):
        sf, facts = self.sf, self.facts
        if not any("grpc" in v for v in sf.bindings.values()):
            return
        for n in walk(sf.tree.root_node):
            if n.type != "new_expression":
                continue
            ctor = n.child_by_field_name("constructor"); args = n.child_by_field_name("arguments")
            ct = sf.node_text(ctor) if ctor is not None else ""
            if not (ct.split(".")[0] in self.grpc_locals or ct.endswith("Client") or re.search(r"Service$", ct)) or args is None or not args.named_child_count:
                continue
            if ct.split(".")[-1] in ("Server", "Metadata"):
                continue
            a0 = args.named_children[0]
            addr = _str(sf, a0)
            if addr is None:
                m = re.search(r"process\.env\.([A-Z0-9_]+)", self.env_of_var.get(sf.node_text(a0), sf.node_text(a0)))
                addr = ("env:" + m.group(1)) if m else None
            if addr is None:
                continue
            host = addr if addr.startswith("env:") else addr.split(":")[0]
            facts.add("outbound_call", DET, self.ev(n), file=sf.path, protocol="grpc", operation="grpc client", sdk_service=None, host=host, entity_kind="system", package="grpc",
                      insecure="createInsecure" in sf.text, service_hint=ct.split(".")[-1])
