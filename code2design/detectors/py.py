"""Python detectors: Flask / FastAPI / Django-REST routes and auth decorators, store clients,
outbound HTTP and SDK clients, gRPC, pydantic/marshmallow/Django models, secrets and weaknesses."""
import re
from ..model import classify_control, classify_field, SECRET_ENV_RX, LOCAL_HOSTS, evidence
from ..index import walk

DET = "py@0.3"
STORE_PKGS = {"psycopg2": "postgres", "psycopg": "postgres", "asyncpg": "postgres", "aiopg": "postgres", "pymysql": "mysql", "mysql.connector": "mysql", "mysql": "mysql", "MySQLdb": "mysql", "aiomysql": "mysql", "sqlite3": "sqlite", "aiosqlite": "sqlite", "pyodbc": "mssql", "pymongo": "mongodb", "motor": "mongodb", "mongoengine": "mongodb", "flask_pymongo": "mongodb", "flask_mongoengine": "mongodb", "redis": "redis", "aioredis": "redis", "flask_caching": "unknown", "pymemcache": "memcached", "elasticsearch": "elasticsearch", "kafka": "kafka", "confluent_kafka": "kafka", "aiokafka": "kafka", "pika": "rabbitmq", "aio_pika": "rabbitmq", "kombu": "rabbitmq", "celery": "unknown", "sqlalchemy": "unknown", "flask_sqlalchemy": "unknown", "sqlmodel": "unknown", "peewee": "unknown", "tortoise": "unknown", "django.db": "unknown", "databases": "unknown", "langchain_google_alloydb_pg": "postgres", "langchain_postgres": "postgres", "pgvector": "postgres", "chromadb": "unknown", "pinecone": "unknown", "qdrant_client": "unknown", "weaviate": "unknown"}
SDK_PKGS = {"stripe": ("Stripe API", "api.stripe.com", "system"), "twilio": ("Twilio API", "api.twilio.com", "system"), "sendgrid": ("SendGrid API", "api.sendgrid.com", "system"), "openai": ("OpenAI API", "api.openai.com", "llm_api"), "anthropic": ("Anthropic API", "api.anthropic.com", "llm_api"), "google.generativeai": ("Google Gemini API", "generativelanguage.googleapis.com", "llm_api"), "cohere": ("Cohere API", "api.cohere.ai", "llm_api"), "langchain_openai": ("OpenAI API", "api.openai.com", "llm_api"), "langchain_anthropic": ("Anthropic API", "api.anthropic.com", "llm_api"), "langchain_google_genai": ("Google Gemini API", "generativelanguage.googleapis.com", "llm_api"), "langchain_google_vertexai": ("Google Vertex AI", None, "llm_api"), "vertexai": ("Google Vertex AI", None, "llm_api"), "google.genai": ("Google Gemini API", "generativelanguage.googleapis.com", "llm_api"), "groq": ("Groq API", "api.groq.com", "llm_api"), "mistralai": ("Mistral API", "api.mistral.ai", "llm_api"), "huggingface_hub": ("Hugging Face API", "huggingface.co", "llm_api"), "boto3": ("AWS SDK", None, "system"), "botocore": ("AWS SDK", None, "system"), "google.cloud": ("Google Cloud APIs", None, "system"), "slack_sdk": ("Slack API", "slack.com", "system"), "github": ("GitHub API", "api.github.com", "system"), "sentry_sdk": ("Sentry", None, "system"), "smtplib": ("SMTP mail relay", None, "system"), "flask_mail": ("SMTP mail relay", None, "system"), "opentelemetry.exporter": ("OTLP collector", None, "system")}
HTTP_CLIENT_PKGS = {"requests", "httpx", "aiohttp", "urllib3", "urllib.request", "urllib"}
WRITE_RX = re.compile(r"^(add_texts|add_documents|from_documents|add|add_all|commit|insert|insert_one|insert_many|update|update_one|update_many|replace_one|delete|delete_one|delete_many|save|create|bulk_create|set|hset|setex|lpush|rpush|sadd|incr|delete|execute|put_object|upload_file|put_item|send_message|publish|produce|basic_publish|index|remove|merge|flush)$")
READ_RX = re.compile(r"^(similarity_search|similarity_search_with_score|max_marginal_relevance_search|as_retriever|from_instance|get|query|filter|all|first|one|find|find_one|find_many|aggregate|count|count_documents|fetchone|fetchall|fetch|select|hget|hgetall|mget|lrange|smembers|get_object|get_item|scan|search|exists|keys)$")
SQL_TABLE_RX = re.compile(r"\b(?:FROM|INTO|UPDATE|JOIN|TABLE)\s+[`\"']?([A-Za-z_][A-Za-z0-9_.]*)", re.I)


def _ev(sf, s, e):
    return evidence(sf, s, e, DET)


def _enclosing_function(node):
    p = node.parent
    while p is not None:
        if p.type in ("function_definition", "lambda"):
            return p
        p = p.parent
    return None


def _str(sf, node):
    if node is not None and node.type == "string":
        t = sf.node_text(node)
        return re.sub(r"^[rbfu]*['\"]{1,3}|['\"]{1,3}$", "", t)
    return None


def run(idx, facts):
    for sf in idx.files.values():
        if sf.lang != "python" or sf.is_test:
            continue
        _file(idx, sf, facts)


def _file(idx, sf, facts):
    root = sf.tree.root_node
    specs = {v.split(":")[0] for v in sf.bindings.values()} | {s for s, _, _ in sf.imports}
    store_specs = {s: t for s, t in STORE_PKGS.items() if any(x == s or x.startswith(s + ".") for x in specs)}
    local_store = {}
    for nm, spec in sf.bindings.items():
        base = spec.split(":")[0]
        for s, t in STORE_PKGS.items():
            if base == s or base.startswith(s + "."):
                local_store[nm] = t
    local_sdk = {nm: s for nm, spec in sf.bindings.items() for s in SDK_PKGS if spec.split(":")[0] == s or spec.split(":")[0].startswith(s + ".")}
    local_http = {nm for nm, spec in sf.bindings.items() if spec.split(":")[0] in HTTP_CLIENT_PKGS}
    is_web = any(s.startswith(("flask", "fastapi", "django", "starlette", "sanic", "aiohttp.web", "bottle", "falcon", "tornado")) for s in specs)
    for spec, line, names in sf.imports:
        base = spec.split(":")[0]
        for s, t in STORE_PKGS.items():
            if base == s or base.startswith(s + "."):
                facts.add("store_access", DET, [_ev(sf, line, line)], technology=t, operation="client_init", package=s, file=sf.path)
                break
        for s, (name, host, kind) in SDK_PKGS.items():
            if base == s or base.startswith(s + "."):
                facts.add("outbound_call", DET, [_ev(sf, line, line)], sdk_service=name, host=host, entity_kind=kind, protocol="https" if "SMTP" not in name else "smtp", package=s, file=sf.path, operation="sdk_import", handler=None)
                break
        if base == "grpc":
            pass
    # alias pass (twice): client = Redis(...); conn = mysql.connector.connect(); cur = conn.cursor(); db = client.mydb
    for _pass in (0, 1):
        for n in walk(root):
            if n.type != "assignment":
                continue
            left = n.child_by_field_name("left"); right = n.child_by_field_name("right")
            if left is None or right is None or left.type not in ("identifier", "attribute"):
                continue
            rt = sf.node_text(right)
            rparts = rt.split("(")[0].strip().split(".")
            rootname = next((".".join(rparts[:k]) for k in (3, 2, 1) if ".".join(rparts[:k]) in local_store or ".".join(rparts[:k]) in local_sdk or ".".join(rparts[:k]) in local_http), rparts[0])
            local = sf.node_text(left)
            if rootname in local_store and local not in local_store:
                local_store[local] = local_store[rootname]
            elif rootname in local_sdk and local not in local_sdk:
                local_sdk[local] = local_sdk[rootname]
            elif rootname in local_http:
                local_http.add(local)
    env_of_var = {}
    for n in walk(root):
        if n.type == "assignment":
            left = n.child_by_field_name("left"); right = n.child_by_field_name("right")
            if left is not None and right is not None and left.type == "identifier" and re.search(r"(environ|getenv)", sf.node_text(right)):
                m = re.search(r"['\"]([A-Z0-9_]+)['\"]", sf.node_text(right))
                if m: env_of_var[sf.node_text(left)] = m.group(1)
    # request fields read by handlers: request.json['x'], request.form.get('x'), request.args['q']
    req_fields = {}
    for m in re.finditer(r"request\.(json|form|args|values|get_json\(\))(?:\.get\(|\[)\s*['\"](\w+)['\"]", sf.text):
        line = sf.text[:m.start()].count("\n") + 1
        req_fields.setdefault(line, []).append(m.group(2))
    for line, flds in sorted(req_fields.items()):
        facts.add("schema", DET, [_ev(sf, line, line)], name="request fields", fields=[{"name": f_, "type": "request"} for f_ in sorted(set(flds))], file=sf.path, schema_kind="validation")
    routes = []
    app_controls = []
    for n in walk(root):
        if n.type == "decorated_definition":
            fn = n.child_by_field_name("definition")
            if fn is None or fn.type != "function_definition":
                continue
            decos = [c for c in n.children if c.type == "decorator"]
            route = None; ctrls = []
            for d in decos:
                dt = sf.node_text(d)[1:]
                m = re.match(r"(\w+)\.(route|get|post|put|patch|delete|api_route|websocket)\((.*)\)$", dt, re.S)
                if m and m.group(3).strip().startswith(("'", '"')):
                    path = re.match(r"['\"]([^'\"]*)['\"]", m.group(3).strip()).group(1)
                    verb = m.group(2).upper()
                    if m.group(2) == "route":
                        mm = re.search(r"methods\s*=\s*[\[(]([^\])]*)", m.group(3))
                        verb = ",".join(re.findall(r"['\"](\w+)['\"]", mm.group(1))) if mm else "GET"
                    elif m.group(2) == "websocket":
                        verb = "WS"
                    route = (path, verb, m.group(1))
                    continue
                m2 = re.match(r"(\w+)\.(get|post|put|patch|delete)\(\)$", dt)
                if m2:
                    route = ("/" + sf.node_text(fn.child_by_field_name("name")), m2.group(2).upper(), m2.group(1)); continue
                m3 = re.match(r"api_view\(\s*\[([^\]]*)\]", dt)
                if m3:
                    route = ("/" + sf.node_text(fn.child_by_field_name("name")), ",".join(re.findall(r"['\"](\w+)['\"]", m3.group(1))), "drf"); continue
                kind = classify_control(dt.split("(")[0])
                if kind:
                    ctrls.append(facts.add("control", DET, [_ev(sf, sf.line(d), sf.line(d))], control_kind=kind, name=dt.split("(")[0][:60], scope="route", file=sf.path))
            if route:
                # FastAPI Depends(...) parameters that look like auth
                params = fn.child_by_field_name("parameters")
                if params is not None:
                    for dep in re.findall(r"Depends\(([^)]*)\)", sf.node_text(params)):
                        kind = classify_control(dep)
                        if kind:
                            ctrls.append(facts.add("control", DET, [_ev(sf, sf.line(params), sf.line(params))], control_kind=kind, name=f"Depends({dep})"[:60], scope="route", file=sf.path))
                span = (fn.start_byte, fn.end_byte)
                fid = facts.add("entry_point", DET, [_ev(sf, sf.line(n), sf.line(fn))], protocol="http", method=route[1], path=route[0], file=sf.path, router=route[2], handler_span=span, route_controls=ctrls, handler_ref=None)
                routes.append((span, fid))
        # Django urls: path('x/', view)
        if n.type == "call_expression" or n.type == "call":
            fnode = n.child_by_field_name("function"); args = n.child_by_field_name("arguments")
            if fnode is None or args is None:
                continue
            ftxt = sf.node_text(fnode); nargs = args.named_children
            fparts = ftxt.split("(")[0].split(".")
            rootid = next((".".join(fparts[:k]) for k in (3, 2) if ".".join(fparts[:k]) in local_store or ".".join(fparts[:k]) in local_sdk), fparts[0])
            members = ftxt.split(".")[len(rootid.split(".")):]
            if ftxt in ("path", "re_path", "url") and nargs and nargs[0].type == "string" and "urls" in sf.path:
                facts.add("entry_point", DET, [_ev(sf, sf.line(n), sf.line(n))], protocol="http", method="ANY", path="/" + (_str(sf, nargs[0]) or ""), file=sf.path, router="django", handler_span=None, route_controls=[], handler_ref=sf.node_text(nargs[1])[:60] if len(nargs) > 1 else None)
            # secrets
            if ftxt in ("os.getenv", "os.environ.get", "environ.get", "getenv", "config", "env") and nargs and nargs[0].type == "string":
                name = _str(sf, nargs[0]) or ""
                if SECRET_ENV_RX.search(name) and not name.endswith(("_URL", "_URI")):
                    facts.add("config_value", DET, [_ev(sf, sf.line(n), sf.line(n))], name=name, data_class="secret", at_import=_enclosing_function(n) is None, file=sf.path)
            # grpc
            if ftxt in ("grpc.insecure_channel", "grpc.secure_channel", "grpc.aio.insecure_channel"):
                addr = _str(sf, nargs[0]) if nargs else None
                if addr is None and nargs and re.search(r"(environ|getenv)", sf.node_text(nargs[0])):
                    m = re.search(r"['\"]([A-Z0-9_]+)['\"]", sf.node_text(nargs[0])); addr = "env:" + m.group(1) if m else None
                if addr is None and nargs and nargs[0].type == "identifier" and sf.node_text(nargs[0]) in env_of_var:
                    addr = "env:" + env_of_var[sf.node_text(nargs[0])]
                if addr and addr.startswith("["):
                    host = addr[1:addr.index("]")] if "]" in addr else addr
                elif addr and not addr.startswith("env:"):
                    host = addr.split(":")[0]
                else:
                    host = addr
                if host in LOCAL_HOSTS:
                    continue  # loopback client (test or sidecar); not an outbound dependency
                facts.add("outbound_call", DET, [_ev(sf, sf.line(n), sf.line(n))], sdk_service=None, host=host, entity_kind="system", protocol="grpc", package="grpc", file=sf.path, operation="grpc_channel", handler=_handler_of(n, routes), insecure="insecure" in ftxt)
                if "insecure" in ftxt:
                    facts.add("weakness", DET, [_ev(sf, sf.line(n), sf.line(n))], weakness_kind="unencrypted_transport", name="grpc.insecure_channel", file=sf.path)
            if re.match(r"\w+\.add_\w+Servicer_to_server$", ftxt) or ftxt.endswith("add_to_server"):
                facts.add("entry_point", DET, [_ev(sf, sf.line(n), sf.line(n))], protocol="grpc", method="grpc", path=ftxt.split(".")[-1].replace("add_", "").replace("_to_server", ""), file=sf.path, router="grpc", handler_span=None, route_controls=[], handler_ref=None)
            if ftxt == "server.add_insecure_port" or ftxt.endswith(".add_insecure_port"):
                facts.add("listener", DET, [_ev(sf, sf.line(n), sf.line(n))], port=sf.node_text(nargs[0])[:40] if nargs else "?", tls=False, file=sf.path)
            # SQL literals with column lists -> table schema
            for a in nargs[:1]:
                if a.type == "string":
                    sql = sf.node_text(a)
                    m = re.search(r"INSERT\s+INTO\s+[`\"']?([A-Za-z_][\w.]*)[`\"']?\s*\(([^)]*)\)", sql, re.I) or re.search(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"']?([A-Za-z_][\w.]*)[`\"']?\s*\(([^;]*)\)", sql, re.I | re.S)
                    if m:
                        cols = [c.strip().strip('`"').split()[0] for c in m.group(2).split(",") if c.strip() and not c.strip().upper().startswith(("PRIMARY", "FOREIGN", "UNIQUE", "CONSTRAINT", "KEY", "INDEX"))]
                        if cols:
                            facts.add("schema", DET, [_ev(sf, sf.line(a), sf.end_line(a))], name=m.group(1), fields=[{"name": c, "type": "column"} for c in cols], file=sf.path, schema_kind="sql")
            # outbound http
            if rootid in local_http or ftxt.startswith(("requests.", "httpx.", "urllib.request.urlopen", "aiohttp.ClientSession")):
                url = _str(sf, nargs[0]) if nargs else None
                host = None; scheme = None
                m = re.match(r"^(https?)://([^/:\s{}]+)", url or "")
                if m: host, scheme = m.group(2).lower(), m.group(1)
                if url is None and nargs and nargs[0].type != "string":
                    txt = sf.node_text(nargs[0])
                    m2 = re.match(r"f?['\"](https?)://([^/:\s{}]+)", txt)
                    if m2: host, scheme = m2.group(2).lower(), m2.group(1)
                    else:
                        host = "variable:" + txt[:40]
                        for var in re.findall(r"\{\s*([A-Za-z_]\w*)", txt) + ([txt] if re.match(r"^[A-Za-z_]\w*$", txt) else []):
                            if var in env_of_var:
                                host = "env:" + env_of_var[var]; break
                if url and url.startswith("/"):
                    continue
                facts.add("outbound_call", DET, [_ev(sf, sf.line(n), sf.line(n))], sdk_service=None, host=host, entity_kind="system", protocol=scheme or "unknown", package=sf.bindings.get(rootid, rootid).split(":")[0], file=sf.path, operation=members[-1] if members else "request", handler=_handler_of(n, routes), url=url[:120] if url else None)
                if scheme == "http" and host and not host.startswith(LOCAL_HOSTS):
                    facts.add("weakness", DET, [_ev(sf, sf.line(n), sf.line(n))], weakness_kind="unencrypted_transport", name=f"plain http:// to {host}", file=sf.path)
            if "verify=False" in sf.node_text(args):
                facts.add("weakness", DET, [_ev(sf, sf.line(n), sf.line(n))], weakness_kind="tls_verification_disabled", name="verify=False", file=sf.path)
            # sdk usage
            if rootid in local_sdk and members:
                name, host, kind = SDK_PKGS[local_sdk[rootid]]
                if local_sdk[rootid] == "boto3" and members[0] in ("client", "resource") and nargs and nargs[0].type == "string":
                    svc = _str(sf, nargs[0])
                    if svc in ("s3", "dynamodb", "sqs"):
                        facts.add("store_access", DET, [_ev(sf, sf.line(n), sf.line(n))], technology=svc, operation="client_init", package="boto3", file=sf.path, logical_name=None, method=members[0], handler=_handler_of(n, routes), local=rootid)
                        continue
                    name = f"AWS {svc.upper()}"
                facts.add("outbound_call", DET, [_ev(sf, sf.line(n), sf.line(n))], sdk_service=name, host=host, entity_kind=kind, protocol="https" if "SMTP" not in name else "smtp", package=local_sdk[rootid], file=sf.path, operation=".".join(members)[:60], handler=_handler_of(n, routes))
            # store usage
            if (rootid in local_store or rootid in ("db", "session", "cursor", "cur", "c", "conn", "connection", "redis_client", "r", "rdb", "cache", "client", "collection", "mongo", "pool", "engine", "table", "bucket", "vector_store", "vectorstore", "store", "retriever")) and members and (store_specs or local_store):
                op = members[-1]
                if WRITE_RX.match(op) or READ_RX.match(op):
                    operation = "write" if WRITE_RX.match(op) else "read"
                    if op in ("execute", "fetch"):
                        sqltxt = sf.node_text(nargs[0]) if nargs else ""
                        operation = "write" if re.search(r"\b(INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\b", sqltxt, re.I) else ("read" if re.search(r"\bSELECT\b", sqltxt, re.I) else "unknown")
                    tech = local_store.get(rootid) or (sorted(set(store_specs.values()))[0] if store_specs else "unknown")
                    logical = None
                    if op in ("execute", "fetch") and nargs:
                        m = SQL_TABLE_RX.search(sf.node_text(nargs[0])); logical = m.group(1) if m else None
                    elif tech == "redis" and nargs and nargs[0].type == "string":
                        key = _str(sf, nargs[0]) or ""; logical = (re.split(r"[:{]", key)[0] + ":*") if key else None
                    elif tech == "mongodb" and len(members) >= 2:
                        logical = members[-2]
                    facts.add("store_access", DET, [_ev(sf, sf.line(n), sf.line(n))], technology=tech, operation=operation, logical_name=logical, method=op, file=sf.path, handler=_handler_of(n, routes), local=rootid)
            # app-level flask/fastapi middleware
            if ftxt.endswith(".add_middleware") and nargs:
                mw = sf.node_text(nargs[0]); kind = classify_control(mw.split("(")[0]) or ("cors" if "CORS" in mw else None)
                if kind:
                    facts.add("control", DET, [_ev(sf, sf.line(n), sf.line(n))], control_kind=kind, name=mw[:60], scope="app", path_prefix=None, file=sf.path, order=len(app_controls) + 1)
                if "CORS" in mw and re.search(r"allow_origins\s*=\s*\[\s*['\"]\*['\"]", sf.node_text(args)):
                    facts.add("weakness", DET, [_ev(sf, sf.line(n), sf.line(n))], weakness_kind="permissive_cors", name="CORSMiddleware allow_origins=['*']", file=sf.path)
            if ftxt in ("CORS", "cors") and nargs:
                facts.add("control", DET, [_ev(sf, sf.line(n), sf.line(n))], control_kind="cors", name="flask_cors.CORS", scope="app", path_prefix=None, file=sf.path, order=1)
                if len(nargs) == 1:
                    facts.add("weakness", DET, [_ev(sf, sf.line(n), sf.line(n))], weakness_kind="permissive_cors", name="CORS(app) with default (all origins)", file=sf.path)
            if ftxt in ("Limiter", "RateLimiter", "limiter.limit"):
                facts.add("control", DET, [_ev(sf, sf.line(n), sf.line(n))], control_kind="rate_limit", name=ftxt, scope="app", path_prefix=None, file=sf.path, order=2)
            if ftxt.endswith(".run") and rootid == "app" and is_web:
                facts.add("listener", DET, [_ev(sf, sf.line(n), sf.line(n))], port=sf.node_text(args)[:40], tls="ssl_context" in sf.node_text(args), file=sf.path)
                facts.add("app_entry", DET, [_ev(sf, 1, 1)], file=sf.path, middleware=[])
        if n.type == "assignment":
            left = n.child_by_field_name("left"); right = n.child_by_field_name("right")
            if left is not None and right is not None:
                lt = sf.node_text(left); rt = sf.node_text(right)
                if re.search(r"(SECRET|PASSWORD|API_KEY|TOKEN|PRIVATE_KEY)", lt, re.I) and right.type == "string" and len(rt) > 8 and not re.search(r"(example|changeme|your|xxx|\{\{)", rt, re.I):
                    facts.add("weakness", DET, [_ev(sf, sf.line(n), sf.line(n))], weakness_kind="plaintext_credentials", name=f"hard-coded {lt[:30]}", file=sf.path)
                if re.match(r"\w+\s*=\s*(Flask|FastAPI|Starlette|Sanic)\(", sf.node_text(n)):
                    facts.add("app_entry", DET, [_ev(sf, sf.line(n), sf.line(n))], file=sf.path, middleware=[])
        # pydantic / dataclass / django / sqlalchemy models -> schemas
        if n.type == "class_definition":
            sup = n.child_by_field_name("superclasses")
            st = sf.node_text(sup) if sup is not None else ""
            if re.search(r"(BaseModel|SQLModel|db\.Model|models\.Model|Base\b|Document|Schema|DeclarativeBase|BaseSchema)", st):
                body = n.child_by_field_name("body"); fields = []
                for c in body.named_children if body is not None else []:
                    if c.type == "expression_statement" and c.named_children and c.named_children[0].type in ("assignment",):
                        a = c.named_children[0]; l = a.child_by_field_name("left"); ty = a.child_by_field_name("type"); r = a.child_by_field_name("right")
                        if l is not None and l.type == "identifier":
                            fields.append({"name": sf.node_text(l), "type": (sf.node_text(ty) if ty is not None else (sf.node_text(r).split("(")[0] if r is not None else "unknown"))[:30]})
                if fields:
                    facts.add("schema", DET, [_ev(sf, sf.line(n), sf.end_line(n))], name=sf.node_text(n.child_by_field_name("name")), fields=fields, file=sf.path, schema_kind="model")
                    if re.search(r"(db\.Model|models\.Model|\bBase\b|Document|DeclarativeBase|SQLModel)", st) and "table=True" in st or re.search(r"(db\.Model|models\.Model|DeclarativeBase|Document)", st):
                        facts.add("store_access", DET, [_ev(sf, sf.line(n), sf.line(n))], technology=("mongodb" if "Document" in st else sorted(set(store_specs.values()))[0] if store_specs else "unknown"), operation="model_definition", logical_name=sf.node_text(n.child_by_field_name("name")), method="model", file=sf.path, handler=None, local=None)


def _handler_of(node, routes):
    for span, fid in routes:
        if span and span[0] <= node.start_byte and node.end_byte <= span[1]:
            return fid
    return None
