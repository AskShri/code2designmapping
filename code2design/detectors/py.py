"""Python detector: Flask (apps, blueprints, url_prefix), FastAPI (apps, APIRouter prefixes,
include_router, Depends-based controls and dependency call edges), Django (urlpatterns, include,
view decorators), route decorators as controls, SQLAlchemy / SQLModel / Flask-SQLAlchemy / Django
ORM / mongoengine table resolution, raw SQL drivers, Redis, MongoDB, outbound HTTP and SDK clients,
gRPC, pydantic and ORM schemas, secrets and weaknesses.
Coverage statement: literal route paths and prefixes (one level of constant resolution); a session
write whose object cannot be traced to a model class is reported with an unresolved table.
"""
import os, re
from ..model import classify_control, is_secret_name, evidence
from ..index import walk
from .common import manifest_engine, sql_operation, sql_table, sql_schema, is_local, looks_like_secret_literal, grpc_service_name

DET = "py@0.5"
STORE_PKGS = {"psycopg2": "postgres", "psycopg": "postgres", "asyncpg": "postgres", "aiopg": "postgres", "pymysql": "mysql", "mysql.connector": "mysql", "mysql": "mysql", "MySQLdb": "mysql", "aiomysql": "mysql", "sqlite3": "sqlite", "aiosqlite": "sqlite", "pyodbc": "mssql", "pymongo": "mongodb", "motor": "mongodb", "mongoengine": "mongodb", "flask_pymongo": "mongodb", "flask_mongoengine": "mongodb", "redis": "redis", "aioredis": "redis", "flask_caching": "unknown", "pymemcache": "memcached", "elasticsearch": "elasticsearch", "kafka": "kafka", "confluent_kafka": "kafka", "aiokafka": "kafka", "pika": "rabbitmq", "aio_pika": "rabbitmq", "kombu": "rabbitmq", "celery": "unknown", "sqlalchemy": "unknown", "flask_sqlalchemy": "unknown", "sqlmodel": "unknown", "peewee": "unknown", "tortoise": "unknown", "django.db": "unknown", "databases": "unknown", "langchain_google_alloydb_pg": "postgres", "langchain_postgres": "postgres", "pgvector": "postgres", "chromadb": "unknown", "pinecone": "unknown", "qdrant_client": "unknown", "weaviate": "unknown"}
SDK_PKGS = {"stripe": ("Stripe API", "api.stripe.com", "system"), "twilio": ("Twilio API", "api.twilio.com", "system"), "sendgrid": ("SendGrid API", "api.sendgrid.com", "system"), "openai": ("OpenAI API", "api.openai.com", "llm_api"), "anthropic": ("Anthropic API", "api.anthropic.com", "llm_api"), "google.generativeai": ("Google Gemini API", "generativelanguage.googleapis.com", "llm_api"), "cohere": ("Cohere API", "api.cohere.ai", "llm_api"), "langchain_openai": ("OpenAI API", "api.openai.com", "llm_api"), "langchain_anthropic": ("Anthropic API", "api.anthropic.com", "llm_api"), "langchain_google_genai": ("Google Gemini API", "generativelanguage.googleapis.com", "llm_api"), "langchain_google_vertexai": ("Google Vertex AI", None, "llm_api"), "vertexai": ("Google Vertex AI", None, "llm_api"), "google.genai": ("Google Gemini API", "generativelanguage.googleapis.com", "llm_api"), "groq": ("Groq API", "api.groq.com", "llm_api"), "mistralai": ("Mistral API", "api.mistral.ai", "llm_api"), "huggingface_hub": ("Hugging Face API", "huggingface.co", "llm_api"), "boto3": ("AWS SDK", None, "system"), "botocore": ("AWS SDK", None, "system"), "google.cloud": ("Google Cloud APIs", None, "system"), "slack_sdk": ("Slack API", "slack.com", "system"), "github": ("GitHub API", "api.github.com", "system"), "sentry_sdk": ("Sentry", None, "system"), "smtplib": ("SMTP mail relay", None, "system"), "flask_mail": ("SMTP mail relay", None, "system"), "opentelemetry.exporter": ("OTLP collector", None, "system")}
HTTP_CLIENT_PKGS = {"requests", "httpx", "aiohttp", "urllib3", "urllib.request", "urllib"}

WRITE_RX = re.compile(r"^(add_texts|add_documents|from_documents|add|add_all|commit|insert|insert_one|insert_many|update|update_one|update_many|replace_one|delete|delete_one|delete_many|save|create|bulk_create|set|hset|setex|lpush|rpush|sadd|incr|delete|execute|put_object|upload_file|put_item|send_message|publish|produce|basic_publish|index|remove|merge|flush)$")
READ_RX = re.compile(r"^(similarity_search|similarity_search_with_score|max_marginal_relevance_search|as_retriever|from_instance|get|query|filter|all|first|one|find|find_one|find_many|aggregate|count|count_documents|fetchone|fetchall|fetch|select|hget|hgetall|mget|lrange|smembers|get_object|get_item|scan|search|exists|keys)$")
for _k in ("sqlalchemy", "flask_sqlalchemy", "sqlmodel", "peewee", "tortoise", "django.db", "databases"):
    STORE_PKGS[_k] = "sql"
STORE_PKGS.pop("celery", None); STORE_PKGS.pop("flask_caching", None)
STORE_PKGS.update({"rq": "redis", "flask_redis": "redis", "opensearchpy": "elasticsearch", "google.cloud.storage": "gcs", "google.cloud.firestore": "unknown", "cassandra": "unknown"})
HTTP_VERBS = ("get", "post", "put", "patch", "delete", "head", "options")
MODEL_BASES = re.compile(r"\b(db\.Model|models\.Model|Model|Base|DeclarativeBase|SQLModel|Document|DynamicDocument|EmbeddedDocument)\b")
SCHEMA_BASES = re.compile(r"\b(BaseModel|SQLModel|Schema|FlaskForm|Form|ModelForm|Serializer|ModelSerializer|BaseSettings|TypedDict)\b")
SESSION_RX = re.compile(r"(^|\.)(session|db_session|sess|async_session|db\.session|dbsession|_session)$", re.I)
SESSION_WRITE = {"add", "add_all", "delete", "merge", "bulk_save_objects", "bulk_insert_mappings", "bulk_update_mappings"}
SESSION_READ = {"get", "query", "scalar", "scalars", "first_or_404", "get_or_404", "one_or_404", "paginate", "get_one"}
SESSION_EXEC = {"execute", "exec"}
SEGMENT_TECH = {"elasticsearch": "elasticsearch", "es": "elasticsearch", "opensearch": "elasticsearch", "redis": "redis", "redis_client": "redis", "mongo": "mongodb", "memcache": "memcached", "s3": "s3"}
DB_URL_TECH = [("postgres", "postgres"), ("mysql", "mysql"), ("mariadb", "mysql"), ("sqlite", "sqlite"), ("mssql", "mssql"), ("oracle", "sql"), ("mongodb", "mongodb")]
STRING_RX = r"[rbfu]{0,2}(?:'''|\"\"\"|'|\")"


def _ev(sf, start, end=None, symbol=None):
    return evidence(sf, start, end, DET, symbol)


def _lit(text):
    """String literal value of an expression text, else None."""
    m = re.match(r"^\s*[rbfu]{0,2}(['\"])(.*?)\1\s*$", text or "", re.S)
    return m.group(2) if m else None


def _chain(text):
    """Dotted names of a call chain with arguments removed: db.users.find({"a.b": 1}).count -> [db, users, find, count]."""
    out, depth, cur = [], 0, ""
    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif depth == 0:
            if ch == ".":
                out.append(cur); cur = ""
            else:
                cur += ch
    out.append(cur)
    return [x for x in out if re.match(r"^\w+$", x)]


def _kwarg(argtext, name):
    m = re.search(r"\b" + name + r"\s*=\s*((?:[^,()\[\]]|\([^()]*\)|\[[^\[\]]*\])+)", argtext or "")
    return m.group(1).strip() if m else None


SQL_EXPR_HELPERS = {"func", "select", "col", "text", "and_", "or_", "not_", "insert", "update", "delete", "literal", "column", "table", "case", "cast", "desc", "asc", "exists", "Field", "Relationship"}


SQL_STATEMENT_BUILDERS = {"select", "func", "col", "text", "and_", "or_", "not_", "literal", "column", "case", "cast", "desc", "asc", "exists", "insert", "update", "delete", "join", "outerjoin", "union"}


def _balanced(text, start, limit=1200):
    """The expression starting at `start`: up to the end of line once brackets balance."""
    depth, i = 0, start
    while i < len(text) and i - start < limit:
        ch = text[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "\n" and depth <= 0:
            break
        i += 1
    return text[start:i]


class _Repo:
    """Repo-wide Python knowledge shared by every file: ORM models, schema classes, dependency
    aliases, string constants and the database engine."""

    def __init__(self, idx):
        self.idx = idx
        self.files = [sf for sf in idx.files.values() if sf.lang == "python" and not sf.is_test]
        self.models = {}       # class name -> (logical table name, file, line, end, kind)
        self.schemas = {}      # class name -> (file, line, end)
        self.dep_alias = {}    # alias name -> (dependency function name, annotated type, file)
        self.constants = {}    # NAME -> string value (only when unique in the repo)
        self.rq = any("rq" in {v.split(":")[0] for v in sf.bindings.values()} for sf in self.files)
        seen_const = {}
        for sf in self.files:
            for (f, cls), info in idx.classes.classes.items():
                pass
            for m in re.finditer(r"^(\w+)\s*=\s*Annotated\[\s*([\w.\[\], |]+?)\s*,\s*Depends\(\s*([\w.]*)\s*\)", sf.text, re.M):
                self.dep_alias[m.group(1)] = (m.group(3), m.group(2).split("[")[0].split(".")[-1], sf.path)
            for m in re.finditer(r"^\s*([A-Z][A-Z0-9_]{2,})\s*(?::\s*[\w.\[\] |]+)?\s*=\s*[rbfu]{0,2}(['\"])([^'\"\n]*)\2\s*$", sf.text, re.M):
                seen_const.setdefault(m.group(1), set()).add(m.group(3))
        self.constants = {k: sorted(v)[0] for k, v in seen_const.items() if len(v) == 1}
        for (f, cls), info in sorted(idx.classes.classes.items()):
            sf = idx.files.get(f)
            if sf is None or sf.lang != "python" or sf.is_test:
                continue
            header = info["header"]
            body = "\n".join(sf.lines[info["start"] - 1:info["end"]])
            base_names = [b for b, _ in info["bases"]]
            is_model = bool(MODEL_BASES.search(header)) and not re.search(r"\b(BaseModel|FlaskForm|Form|Schema)\b", header)
            if re.search(r"\btable\s*=\s*True\b", header):
                is_model = True     # SQLModel table class, whatever its (possibly not yet visited) base
            elif "SQLModel" in header or any(b in self.schemas and b not in self.models for b in base_names):
                is_model = False
            if any(b in self.models for b in base_names) and not re.search(r"\btable\s*=", header) and "SQLModel" not in header:
                is_model = True     # subclass of a model base declared in the repo
            if re.match(r"^(Base|Model|BaseModel|DeclarativeBase|Document|TimestampMixin|\w+Mixin)$", cls) and "__tablename__" not in body:
                is_model = False    # abstract bases are not tables
            if "abstract = True" in body or "__abstract__ = True" in body:
                is_model = False
            if is_model:
                t = re.search(r"__tablename__\s*=\s*['\"](\w+)['\"]", body) or re.search(r"db_table\s*=\s*['\"](\w+)['\"]", body) or re.search(r"['\"]collection['\"]\s*:\s*['\"](\w+)['\"]", body)
                kind = "mongodb" if re.search(r"Document\b", header) else "sql"
                default = cls.lower() if re.search(r"\btable\s*=\s*True\b", header) else cls    # SQLModel's default table name
                self.models[cls] = (t.group(1) if t else default, f, info["start"], info["end"], kind)
            if is_model or SCHEMA_BASES.search(header) or any(b in self.schemas for b in base_names):
                self.schemas[cls] = (f, info["start"], info["end"])
        self.tech = self._engine()

    def _engine(self):
        """SQL engine from connection-string literals in configuration code, else 'sql'."""
        hits = set()
        for sf in self.files:
            for m in re.finditer(r"['\"]((?:postgres(?:ql)?|mysql|mariadb|sqlite|mssql|oracle)(?:\+\w+)?)://", sf.text):
                hits |= {t for k, t in DB_URL_TECH if m.group(1).startswith(k)}
            for m in re.finditer(r"django\.db\.backends\.(\w+)", sf.text):
                hits |= {t for k, t in DB_URL_TECH if m.group(1).startswith(k)}
            if re.search(r"PostgresDsn|postgresql\+psycopg|asyncpg", sf.text):
                hits.add("postgres")
        hits.discard("sql")
        if len(hits) > 1 and "sqlite" in hits:
            hits.discard("sqlite")    # sqlite is the usual local fallback next to the production engine
        if len(hits) == 1:
            return sorted(hits)[0]
        return (manifest_engine(self.idx) or "sql") if not hits else "sql"

    def const(self, expr):
        """Resolve a prefix expression: literal, NAME, or obj.NAME (one level, unique constants only)."""
        v = _lit(expr)
        if v is not None:
            return v
        name = (expr or "").strip().split(".")[-1]
        return self.constants.get(name)


def run(idx, facts):
    repo = _Repo(idx)
    if not repo.files:
        return
    # ORM models and schema classes once, repo-wide
    for cls, (logical, f, start, end, kind) in sorted(repo.models.items()):
        sf = idx.files[f]
        facts.add("store_access", DET, _ev(sf, start), file=f, technology=repo.tech if kind == "sql" else "mongodb", operation="model_definition", logical_name=logical)
    for cls, (f, start, end) in sorted(repo.schemas.items()):
        sf = idx.files[f]
        fields = []
        for line in sf.lines[start:end]:
            m = re.match(r"^\s{2,8}(\w+)\s*(?::\s*([^=#]+?))?\s*(?:=\s*(.+))?$", line)
            if not m or m.group(1).startswith("_") or m.group(1) in ("class", "def", "return", "pass", "model_config", "objects", "query", "metadata") or (m.group(2) is None and m.group(3) is None):
                continue
            if m.group(2) is None and not re.search(r"(Column|Field|relationship|models\.\w+|sa\.\w+|so\.\w+|mapped_column)\(", m.group(3) or ""):
                continue
            if "relationship(" in (m.group(3) or "") or "Relationship(" in (m.group(3) or ""):
                continue
            fields.append({"name": m.group(1), "type": (m.group(2) or (m.group(3) or "").split("(")[0]).strip()[:30]})
        if fields:
            name = repo.models[cls][0] if cls in repo.models else cls
            facts.add("schema", DET, _ev(sf, start, end), file=f, name=name, fields=fields, schema_kind="model" if cls in repo.models else "validation", class_name=cls)
            if re.search(r"BaseSettings", idx.classes.classes[(f, cls)]["header"]):
                for fld in fields:
                    if is_secret_name(fld["name"]):
                        facts.add("config_value", DET, _ev(sf, start), file=f, name=fld["name"], data_class="secret")
    for sf in repo.files:
        _PyFile(idx, sf, facts, repo).run()


class _PyFile:
    def __init__(self, idx, sf, facts, repo):
        self.idx, self.sf, self.facts, self.repo = idx, sf, facts, repo
        self.specs = {v.split(":")[0] for v in sf.bindings.values()} | {s for s, _, _ in sf.imports}
        self.local_store = {}
        for nm, spec in sf.bindings.items():
            base = spec.split(":")[0]
            for s, t in STORE_PKGS.items():
                if base == s or base.startswith(s + "."):
                    self.local_store[nm] = t
        self.local_sdk = {nm: s for nm, spec in sf.bindings.items() for s in SDK_PKGS if spec.split(":")[0] == s or spec.split(":")[0].startswith(s + ".")}
        self.local_http = {nm for nm, spec in sf.bindings.items() if spec.split(":")[0] in HTTP_CLIENT_PKGS}
        self.routers = {}       # local -> True (declared in this file)
        self.env_of_var = {}
        self.func_cache = {}

    def ev(self, node, end=None):
        return _ev(self.sf, self.sf.line(node), end)

    def store_techs(self):
        return sorted({t for s, t in STORE_PKGS.items() if any(x == s or x.startswith(s + ".") for x in self.specs)})

    def router_key(self, local):
        """(router_file, router_local) for a name used as `@local.route(...)`."""
        if local in self.routers:
            return self.sf.path, local
        if local in self.sf.bindings:
            f, sym = self.idx.resolve_symbol(self.sf, self.sf.bindings[local])
            if f:
                return f, sym or local
        return self.sf.path, local

    # ------------------------------------------------------------------ driver
    def _before_request_guards(self):
        """@bp.before_request / @app.before_request functions that enforce authentication guard every
        route of that blueprint (before_app_request: of the whole app)."""
        sf = self.sf
        for m in re.finditer(r"^@(\w+)\.before_(app_)?request\s*\n((?:@[^\n]+\n)*)\s*(?:async\s+)?def\s+(\w+)\([^)]*\)[^:]*:\n((?:[ \t]+[^\n]*\n|\n)*)", sf.text, re.M):
            decos = [d.strip().lstrip("@").split("(")[0] for d in m.group(3).splitlines() if d.strip()]
            kind = next((k for k in (classify_control(d.split(".")[-1]) for d in decos) if k in ("authn", "authz")), None)
            if not kind and re.search(r"abort\(\s*40[13]\b|\b40[13]\b\s*$|Unauthorized|login_manager\.unauthorized|verify_jwt_in_request", m.group(5), re.M):
                kind = "authn"
            if kind:
                rf, rl = self.router_key(m.group(1))
                attrs = dict(file=sf.path, control_kind=kind, name=f"before_request:{m.group(4)}"[:60])
                if m.group(2):
                    self.facts.add("control", DET, _ev(sf, sf.line_of_offset(m.start())), scope="service", **attrs)
                else:
                    self.facts.add("control", DET, _ev(sf, sf.line_of_offset(m.start())), scope="router", router=rl, router_file=rf, ordered=False, **attrs)

    def run(self):
        sf, facts = self.sf, self.facts
        self._before_request_guards()
        for spec, line, names in sf.imports:
            base = spec.split(":")[0]
            hit = next(((s, t) for s, t in sorted(STORE_PKGS.items(), key=lambda kv: -len(kv[0])) if base == s or base.startswith(s + ".")), None)
            if hit and hit[1] != "sql":
                facts.add("store_access", DET, _ev(sf, line), file=sf.path, technology=hit[1], operation="client_init", package=hit[0])
            sdk = next((s for s in sorted(SDK_PKGS, key=len, reverse=True) if base == s or base.startswith(s + ".")), None)
            if sdk:
                name, host, kind = SDK_PKGS[sdk]
                facts.add("outbound_call", DET, _ev(sf, line), file=sf.path, protocol="smtp" if "SMTP" in name else "https", operation="sdk_import", sdk_service=name, host=host, entity_kind=kind, package=sdk)
        self._assignments()
        self._decorated()
        self._request_fields()
        self._django_urls()
        for n in walk(sf.tree.root_node):
            if n.type == "call":
                self._call(n)

    # ------------------------------------------------------------------ assignments: routers, aliases, env, secrets
    def _assignments(self):
        sf, facts, repo = self.sf, self.facts, self.repo
        nodes = [n for n in walk(sf.tree.root_node) if n.type == "assignment"]
        for _pass in (0, 1):
            for n in nodes:
                left = n.child_by_field_name("left"); right = n.child_by_field_name("right")
                if left is None or right is None or left.type not in ("identifier", "attribute"):
                    continue
                lt = sf.node_text(left); rt = sf.node_text(right)
                callee = rt.split("(")[0].strip()
                rparts = callee.split(".")
                root = next((".".join(rparts[:k]) for k in (3, 2, 1) if ".".join(rparts[:k]) in self.local_store or ".".join(rparts[:k]) in self.local_sdk or ".".join(rparts[:k]) in self.local_http), rparts[0])
                last = rparts[-1]
                # aliases come from constructors and factories, never from query or response results
                factory = right.type in ("attribute", "subscript") or last[:1].isupper() or last in ("connect", "cursor", "client", "resource", "from_url", "create_engine", "get_database", "get_collection", "get_default_database", "session", "Session", "sessionmaker", "pipeline", "pool", "create_pool", "AsyncClient")
                bm = re.match(r"^(?:boto3|session)\.(?:client|resource)\(\s*['\"](s3|dynamodb|sqs)['\"]", rt)
                if bm:
                    self.local_store[lt] = bm.group(1)
                elif root in self.local_store and lt not in self.local_store and factory:
                    self.local_store[lt] = self.local_store[root]
                elif root in self.local_sdk and lt not in self.local_sdk and factory:
                    self.local_sdk[lt] = self.local_sdk[root]
                elif root in self.local_http and factory and last in ("Session", "Client", "AsyncClient", "ClientSession"):
                    self.local_http.add(lt)
                if _pass:
                    continue
                if re.search(r"(environ|getenv)", rt):
                    m = re.search(r"['\"]([A-Z0-9_]+)['\"]", rt)
                    if m: self.env_of_var[lt] = m.group(1)
                args = rt[len(callee):]
                if left.type == "identifier" and right.type == "call":
                    cname = callee.split(".")[-1]
                    if cname in ("Flask", "FastAPI", "Starlette", "Sanic", "Quart", "Bottle") and "(" in rt:
                        self.routers[lt] = True
                        facts.add("router", DET, self.ev(n), file=sf.path, local=lt, own_prefix=repo.const(_kwarg(args, "root_path")) or "", root=True)
                        facts.add("app", DET, self.ev(n), file=sf.path, framework=cname.lower())
                        self._deps_controls(n, args, "router", lt)
                    elif cname in ("Blueprint", "APIRouter", "APIBlueprint"):
                        self.routers[lt] = True
                        prefix = repo.const(_kwarg(args, "url_prefix") or _kwarg(args, "prefix")) or ""
                        facts.add("router", DET, self.ev(n), file=sf.path, local=lt, own_prefix=prefix, root=False)
                        self._deps_controls(n, args, "router", lt)
                if re.search(r"(SECRET|PASSWORD|API_KEY|TOKEN|PRIVATE_KEY)", lt, re.I) and right.type == "string" and looks_like_secret_literal(_lit(rt) or ""):
                    facts.add("weakness", DET, self.ev(n), file=sf.path, weakness_kind="plaintext_credentials", name=f"hard-coded {lt.split('.')[-1][:40]}")

    def _deps_controls(self, node, argtext, scope, router=None, caller_line=None):
        """dependencies=[Depends(f), ...] on an app, router, include_router or route decorator."""
        out = []
        deps = _kwarg(argtext, "dependencies")
        for fn in re.findall(r"Depends\(\s*([\w.]+)", deps or ""):
            out += self._dep(node, fn, scope, router, caller_line=caller_line)
        return out

    def _dep(self, node, fn, scope, router=None, caller_line=None):
        """A dependency function: a control when its name says so, and a call edge to its body."""
        sf = self.sf
        out = []
        name = fn.split(".")[-1]
        kind = classify_control(name)
        if kind:
            attrs = dict(file=sf.path, control_kind=kind, name=f"Depends({name})", scope=scope)
            if scope == "router":
                rf, rl = self.router_key(router)
                attrs.update(router=rl, router_file=rf, ordered=False)
            out.append(self.facts.add("control", DET, self.ev(node), **attrs))
        tfile, sym = (None, None)
        if fn.split(".")[0] in sf.bindings:
            tfile, sym = self.idx.resolve_symbol(sf, sf.bindings[fn.split(".")[0]])
            sym = sym if "." not in fn else name
        elif re.match(r"^\w+$", fn):
            tfile, sym = sf.path, fn
        if tfile and caller_line:
            self.facts.add("call_edge", DET, _ev(sf, caller_line), file=sf.path, line=caller_line, target_file=tfile, target_symbol=sym or name)
        return out

    # ------------------------------------------------------------------ decorated functions: routes, tasks, view controls
    def _decorated(self):
        sf, facts, repo = self.sf, self.facts, self.repo
        for n in walk(sf.tree.root_node):
            if n.type == "function_definition":
                self._function_deps(n)
            if n.type != "decorated_definition":
                continue
            fn = n.child_by_field_name("definition")
            if fn is None or fn.type != "function_definition":
                continue
            fname = sf.node_text(fn.child_by_field_name("name"))
            fline = sf.line(fn)
            cls = self.idx.classes.class_at(sf.path, fline)
            symbol = f"{cls}.{fname}" if cls else fname
            routes, controls, other = [], [], []
            for d in (c for c in n.children if c.type == "decorator"):
                dt = sf.node_text(d)[1:].strip()
                m = re.match(r"^([\w.]+)\.(route|get|post|put|patch|delete|head|options|api_route|websocket)\s*\((.*)\)\s*$", dt, re.S)
                if m and "." not in m.group(1) or (m and m.group(1).split(".")[-1] in ("bp", "app", "router", "blueprint", "api")):
                    args = m.group(3)
                    first = re.match(r"\s*(" + STRING_RX + r")(.*?)\1", args, re.S)
                    path = first.group(2) if first else (repo.const(args.split(",")[0]) if args.strip() and "=" not in args.split(",")[0] else None)
                    if path is None and (m.group(2) in HTTP_VERBS) and not args.strip():
                        path = ""
                    if path is None:
                        continue
                    if m.group(2) in ("route", "api_route"):
                        mm = re.search(r"methods\s*=\s*[\[({]([^\])}]*)", args)
                        methods = [x.upper() for x in re.findall(r"['\"](\w+)['\"]", mm.group(1))] if mm else ["GET"]
                    elif m.group(2) == "websocket":
                        methods = ["WS"]
                    else:
                        methods = [m.group(2).upper()]
                    routes.append((m.group(1).split(".")[-1], path, methods, d, args))
                    continue
                if re.match(r"^(\w+\.)?(task|shared_task|periodic_task)\b", dt) and re.search(r"(celery|shared_task|\.task)", dt + sf.text[:2000]):
                    facts.add("entry_point", DET, _ev(sf, sf.line(d), fline), file=sf.path, protocol="amqp", method="TASK", path=fname, router="<tasks>", handler_file=sf.path, handler_symbol=symbol)
                    continue
                other.append((d, dt))
            for d, dt in other:
                name = dt.split("(")[0]
                args = dt[len(name):].strip("()")
                kind = classify_control(name, args)
                if name.endswith("permission_classes"):
                    kind = "authn" if re.search(r"IsAuthenticated|IsAdminUser|DjangoModelPermissions", args) else None
                if kind:
                    scope = "route" if routes else "handler"
                    attrs = dict(file=sf.path, control_kind=kind, name=name[:60], scope=scope)
                    if scope == "handler":
                        attrs.update(handler_file=sf.path, handler_symbol=symbol)
                    controls.append(facts.add("control", DET, _ev(sf, sf.line(d)), **attrs))
            if not routes:
                continue
            params = sf.node_text(fn.child_by_field_name("parameters")) if fn.child_by_field_name("parameters") is not None else ""
            payload_types = sorted({t for t in re.findall(r":\s*(?:Annotated\[\s*)?([A-Z]\w*)", params) if t in repo.schemas and t not in repo.dep_alias})
            body_text = sf.node_text(fn)
            payload_types += sorted({t for t in re.findall(r"\b([A-Z]\w*Form)\(", body_text) if t in repo.schemas})
            for local, path, methods, d, args in routes:
                rfile, rlocal = self.router_key(local)
                body = fn.child_by_field_name("body")
                rc = list(controls) + self._deps_controls(d, args, "route", caller_line=sf.line(body) if body is not None else fline)
                for meth in methods:
                    facts.add("entry_point", DET, _ev(sf, sf.line(d), fline), file=sf.path, protocol="http", method=meth, path=path, router=rlocal, router_file=rfile,
                              route_controls=rc, handler_file=sf.path, handler_symbol=symbol, payload_types=payload_types)

    def _function_deps(self, fn):
        """Parameters that carry FastAPI dependencies: `x = Depends(f)`, `x: Annotated[T, Depends(f)]`, `x: Alias`."""
        sf, repo = self.sf, self.repo
        pnode = fn.child_by_field_name("parameters")
        if pnode is None:
            return
        params = sf.node_text(pnode)
        if "Depends" not in params and not any(re.search(r":\s*" + re.escape(a) + r"\b", params) for a in repo.dep_alias):
            return
        fname = sf.node_text(fn.child_by_field_name("name"))
        cls = self.idx.classes.class_at(sf.path, sf.line(fn))
        symbol = f"{cls}.{fname}" if cls else fname
        body = fn.child_by_field_name("body")
        caller_line = sf.line(body) if body is not None else sf.line(fn)
        deps = set(re.findall(r"Depends\(\s*([\w.]+)", params))
        alias_deps = set()
        for a, (depfn, _typ, afile) in repo.dep_alias.items():
            if depfn and re.search(r":\s*" + re.escape(a) + r"\b", params):
                alias_deps.add((depfn, afile))
        for depfn in sorted(deps):
            for cid in self._dep(pnode, depfn, "handler", caller_line=caller_line):
                f = self.facts.get(cid); f["handler_file"] = sf.path; f["handler_symbol"] = symbol
        for depfn, afile in sorted(alias_deps):
            name = depfn.split(".")[-1]
            kind = classify_control(name)
            if kind:
                self.facts.add("control", DET, self.ev(pnode), file=sf.path, control_kind=kind, name=f"Depends({name})", scope="handler", handler_file=sf.path, handler_symbol=symbol)
            af = self.idx.files.get(afile)
            tfile, tsym = afile, name
            if af is not None and depfn.split(".")[0] in af.bindings:
                tfile, tsym = self.idx.resolve_symbol(af, af.bindings[depfn.split(".")[0]])
                tsym = tsym or name
            if tfile:
                self.facts.add("call_edge", DET, _ev(sf, caller_line), file=sf.path, line=caller_line, target_file=tfile, target_symbol=tsym)

    def _request_fields(self):
        sf = self.sf
        by_line = {}
        for m in re.finditer(r"request\.(?:json|form|args|values|data|get_json\(\))(?:\.get\(|\[)\s*['\"](\w+)['\"]", sf.text):
            by_line.setdefault(sf.line_of_offset(m.start()), set()).add(m.group(1))
        for line, fields in sorted(by_line.items()):
            self.facts.add("schema", DET, _ev(sf, line), file=sf.path, name="request fields", fields=[{"name": f, "type": "request"} for f in sorted(fields)], schema_kind="request")

    def _root_urlconf(self):
        for f in self.repo.files:
            m = re.search(r"^ROOT_URLCONF\s*=\s*['\"]([\w.]+)['\"]", f.text, re.M)
            if m:
                return self.idx._py_module(f, m.group(1))
        return None

    def _view_class(self, ref):
        """(file, class, info) for a view reference: a local class or an imported one."""
        sf, C = self.sf, self.idx.classes
        head, name = ref.split(".")[0], ref.split(".")[-1]
        cands = []
        if (sf.path, name) in C.classes:
            cands.append(sf.path)
        if head in sf.bindings:
            f, sym = self.idx.resolve_symbol(sf, sf.bindings[head])
            if f:
                cands.append(f)
        for f in cands:
            if (f, name) in C.classes:
                return f, name, C.classes[(f, name)]
        return None

    def _class_methods(self, f, cls, info):
        lines = self.idx.files[f].lines[info["start"] - 1:info["end"]]
        return {m.group(1): info["start"] + i for i, l in enumerate(lines) for m in [re.match(r"\s+(?:async\s+)?def\s+(\w+)\s*\(", l)] if m}

    def _bases_closure(self, f, cls, depth=0):
        """Base class names, following bases declared in the repository."""
        info = self.idx.classes.classes.get((f, cls))
        if not info or depth > 5:
            return []
        out = []
        for b, _g in info["bases"]:
            out.append(b.split(".")[-1])
            hit = next(((bf, bc) for (bf, bc) in self.idx.classes.classes if bc == b.split(".")[-1] and self.idx.files[bf].lang == "python"), None)
            if hit:
                out += self._bases_closure(hit[0], hit[1], depth + 1)
        return out

    def _view_controls(self, f, cls, info, node):
        """permission_classes / authentication_classes / decorators on a class-based view."""
        body = "\n".join(self.idx.files[f].lines[info["start"] - 1:info["end"]])
        ctl, anonymous = [], False
        m = re.search(r"^\s+permission_classes\s*=\s*[\[(]([^\])]*)[\])]", body, re.M)
        if m:
            names = [x.strip().split(".")[-1] for x in m.group(1).split(",") if x.strip()]
            if names and all(n == "AllowAny" for n in names):
                anonymous = True
            for n in names:
                kind = "authz" if re.search(r"Admin|Owner|Permission|Staff|Role|DjangoModel", n) else ("authn" if re.search(r"IsAuthenticated|Authenticated", n) else classify_control(n))
                if kind and n != "AllowAny":
                    ctl.append(self.facts.add("control", DET, self.ev(node), file=self.sf.path, control_kind=kind, name=n, scope="route"))
        if re.search(r"LoginRequiredMixin|PermissionRequiredMixin|UserPassesTestMixin", " ".join(b for b, _ in info["bases"])):
            ctl.append(self.facts.add("control", DET, self.ev(node), file=self.sf.path, control_kind="authn", name="LoginRequiredMixin", scope="route"))
        return ctl, anonymous

    GENERIC_METHODS = [("ListCreate", ("GET", "POST")), ("RetrieveUpdateDestroy", ("GET", "PUT", "PATCH", "DELETE")), ("RetrieveUpdate", ("GET", "PUT", "PATCH")),
                       ("RetrieveDestroy", ("GET", "DELETE")), ("List", ("GET",)), ("Create", ("POST",)), ("Retrieve", ("GET",)), ("Update", ("PUT", "PATCH")), ("Destroy", ("DELETE",)),
                       ("TemplateView", ("GET",)), ("ListView", ("GET",)), ("DetailView", ("GET",)), ("CreateView", ("GET", "POST")), ("UpdateView", ("GET", "POST")),
                       ("DeleteView", ("GET", "POST")), ("FormView", ("GET", "POST")), ("RedirectView", ("GET",))]
    VERB_METHODS = {"get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH", "delete": "DELETE", "head": "HEAD"}

    def _emit_view(self, node, route, ref, prefix_router="urlpatterns"):
        """One entry point per HTTP method a view handles; function views stay ANY."""
        hit = self._view_class(ref)
        if not hit:
            self.facts.add("entry_point", DET, self.ev(node), file=self.sf.path, protocol="http", method="ANY", path=route, router=prefix_router, route_controls=[], handler_ref=ref[:120])
            return
        f, cls, info = hit
        methods = self._class_methods(f, cls, info)
        bases = self._bases_closure(f, cls)
        ctl, anon = self._view_controls(f, cls, info, node)
        out = [(v, f"{cls}.{m}") for m, v in self.VERB_METHODS.items() if m in methods]
        if not out:
            for key, verbs in self.GENERIC_METHODS:
                if any(b.startswith(key) or b.endswith(key) for b in bases):
                    out = [(v, f"{cls}.dispatch") for v in verbs]
                    break
        for v, sym in out or [("ANY", f"{cls}.dispatch")]:
            attrs = dict(handler_file=f, handler_symbol=sym) if sym.split(".")[-1] in methods else dict(handler_scope="class", handler_file=f, handler_class=cls)
            self.facts.add("entry_point", DET, self.ev(node), file=self.sf.path, protocol="http", method=v, path=route, router=prefix_router, route_controls=ctl,
                           **attrs, **({"anonymous": True} if anon else {}))

    VIEWSET_ACTIONS = [("list", "GET", False), ("create", "POST", False), ("retrieve", "GET", True), ("update", "PUT", True), ("partial_update", "PATCH", True), ("destroy", "DELETE", True)]

    def _emit_viewset(self, node, prefix, ref):
        hit = self._view_class(ref)
        if not hit:
            return
        f, cls, info = hit
        methods = self._class_methods(f, cls, info)
        bases = " ".join(self._bases_closure(f, cls))
        ctl, anon = self._view_controls(f, cls, info, node)
        if "ModelViewSet" in bases and "ReadOnly" not in bases:
            acts = {a for a, _v, _d in self.VIEWSET_ACTIONS}
        elif "ReadOnlyModelViewSet" in bases:
            acts = {"list", "retrieve"}
        else:
            acts = {a for a, mix in (("list", "ListModelMixin"), ("create", "CreateModelMixin"), ("retrieve", "RetrieveModelMixin"), ("update", "UpdateModelMixin"),
                                     ("partial_update", "UpdateModelMixin"), ("destroy", "DestroyModelMixin")) if mix in bases}
        acts |= {a for a, _v, _d in self.VIEWSET_ACTIONS if a in methods}
        base = prefix.strip("/")
        for a, verb, detail in self.VIEWSET_ACTIONS:
            if a in acts:
                path = f"/{base}/{{pk}}" if detail else f"/{base}"
                h = dict(handler_file=f, handler_symbol=f"{cls}.{a}") if a in methods else dict(handler_scope="class", handler_file=f, handler_class=cls)
                self.facts.add("entry_point", DET, self.ev(node), file=self.sf.path, protocol="http", method=verb, path=path, router="urlpatterns",
                               route_controls=ctl, **h, **({"anonymous": True} if anon else {}))
        text = self.idx.files[f].lines
        for i in range(info["start"] - 1, info["end"]):
            m = re.match(r"\s*@action\((.*)\)\s*$", text[i])
            if not m:
                continue
            dm = re.search(r"\bdef\s+(\w+)", " ".join(text[i + 1:i + 4]))
            if not dm:
                continue
            detail = re.search(r"detail\s*=\s*True", m.group(1)) is not None
            verbs = re.findall(r"['\"](get|post|put|patch|delete)['\"]", m.group(1).lower()) or ["get"]
            up = re.search(r"url_path\s*=\s*['\"]([^'\"]+)['\"]", m.group(1))
            seg = up.group(1) if up else dm.group(1)
            path = f"/{base}/{{pk}}/{seg}" if detail else f"/{base}/{seg}"
            for v in verbs:
                self.facts.add("entry_point", DET, self.ev(node), file=self.sf.path, protocol="http", method=v.upper(), path=path, router="urlpatterns",
                               route_controls=ctl, handler_file=f, handler_symbol=f"{cls}.{dm.group(1)}", **({"anonymous": True} if anon else {}))

    def _drf_defaults(self):
        """REST_FRAMEWORK['DEFAULT_PERMISSION_CLASSES'] in settings: a service-wide control."""
        sf = self.sf
        if not sf.path.endswith("settings.py") and "/settings/" not in sf.path:
            return
        m = re.search(r"['\"]DEFAULT_PERMISSION_CLASSES['\"]\s*:\s*[\[(]([^\])]*)[\])]", sf.text)
        if not m:
            return
        names = [x.strip().strip("'\"").split(".")[-1] for x in m.group(1).split(",") if x.strip()]
        for n in names:
            if n == "AllowAny":
                continue
            kind = "authz" if re.search(r"Admin|Owner|Permission|Staff|Role|DjangoModel", n) and "Authenticated" not in n else "authn"
            self.facts.add("control", DET, _ev(sf, sf.line_of_offset(m.start())), file=sf.path, control_kind=kind, name=f"DEFAULT_PERMISSION_CLASSES:{n}", scope="service")

    def _django_urls(self):
        sf, facts = self.sf, self.facts
        self._drf_defaults()
        if not re.search(r"^urlpatterns\s*(\+)?=", sf.text, re.M):
            return
        root_conf = self._root_urlconf()
        is_root = sf.path == root_conf if root_conf else ("admin.site.urls" in sf.text or os.path.dirname(sf.path).count("/") == 0)
        facts.add("router", DET, _ev(sf, 1), file=sf.path, local="urlpatterns", own_prefix="", root=bool(is_root))
        registered = {}
        for m in re.finditer(r"^(\w+)\.register\(\s*r?['\"]([^'\"]*)['\"]\s*,\s*([\w.]+)", sf.text, re.M):
            registered.setdefault(m.group(1), []).append((m.group(2), m.group(3), sf.line_of_offset(m.start())))
        used_routers = set()
        for n in walk(sf.tree.root_node):
            if n.type != "call":
                continue
            fn = n.child_by_field_name("function"); args = n.child_by_field_name("arguments")
            if fn is None or args is None or sf.node_text(fn) not in ("path", "re_path", "url") or not args.named_child_count:
                continue
            route = _lit(sf.node_text(args.named_children[0]))
            if route is None or args.named_child_count < 2:
                continue
            route = re.sub(r"^\^|\$$", "", route)
            target = sf.node_text(args.named_children[1])
            rinc = re.match(r"include\(\s*(\w+)\.urls\s*\)", target)
            if rinc and rinc.group(1) in registered:
                used_routers.add(rinc.group(1))
                for prefix, ref, _line in registered[rinc.group(1)]:
                    self._emit_viewset(n, route.rstrip("/") + "/" + prefix if route else prefix, ref)
                continue
            inc = re.match(r"include\(\s*(?:\(\s*)?['\"]([\w.]+)['\"]", target)
            if inc:
                tfile = self.idx._py_module(sf, inc.group(1))
                if tfile:
                    facts.add("router_mount", DET, self.ev(n), file=sf.path, parent="urlpatterns", prefix=route, child_file=tfile, child_local="urlpatterns")
                continue
            if "include(" in target or "admin.site" in target:
                continue
            ref = re.sub(r"\.as_view\(.*$", "", target, flags=re.S)
            self._emit_view(n, route, ref)
        for rv, regs in sorted(registered.items()):        # urlpatterns += router.urls
            if rv not in used_routers and re.search(r"\b" + re.escape(rv) + r"\.urls\b", sf.text):
                for prefix, ref, line in regs:
                    self._emit_viewset(self._node_at_line(line), prefix, ref)

    def _node_at_line(self, line):
        for n in walk(self.sf.tree.root_node):
            if n.type == "call" and self.sf.line(n) == line:
                return n
        return self.sf.tree.root_node

    # ------------------------------------------------------------------ calls
    def _enclosing(self, node):
        p = node.parent
        while p is not None and p.type != "function_definition":
            p = p.parent
        return p

    def _fn_text(self, node):
        fn = self._enclosing(node)
        if fn is None:
            return "", ""
        key = fn.start_byte
        if key not in self.func_cache:
            pn = fn.child_by_field_name("parameters")
            self.func_cache[key] = (self.sf.node_text(fn), self.sf.node_text(pn) if pn is not None else "")
        return self.func_cache[key]

    def _models_in(self, text):
        return [m for m in dict.fromkeys(re.findall(r"\b([A-Z]\w*)\b", text or "")) if m in self.repo.models]

    def _models_for_args(self, node, argtext):
        """Model classes a session call touches: named in the arguments, or reachable through the
        arguments' variables (assignment in the same function, parameter annotation, dependency alias)."""
        hits = self._models_in(argtext)
        if hits:
            return hits
        body, params = self._fn_text(node)
        out = []
        for var in dict.fromkeys(re.findall(r"\b([a-z_]\w*)\b", argtext or "")):
            for m in re.finditer(r"^\s*" + re.escape(var) + r"\s*(?::\s*[\w.\[\] |]+)?=\s*", body, re.M):
                rhs = _balanced(body, m.end())
                found = self._models_in(rhs)
                call = re.match(r"\s*(?:await\s+)?([\w.]+)\(", rhs)
                if not found and call:
                    found = self._returned_models(call.group(1))
                out += found
            pm = re.search(r"\b" + re.escape(var) + r"\s*:\s*(?:Annotated\[\s*)?([\w.]+)", params)
            if pm:
                t = pm.group(1).split(".")[-1]
                if t in self.repo.models:
                    out.append(t)
                elif t in self.repo.dep_alias and self.repo.dep_alias[t][1] in self.repo.models:
                    out.append(self.repo.dep_alias[t][1])
        return list(dict.fromkeys(out))

    def _returned_models(self, fname):
        """Models named in the return annotation of a function defined here or imported: def f(...) -> User | None."""
        sf, idx = self.sf, self.idx
        head, name = fname.split(".")[0], fname.split(".")[-1]
        texts = [sf.text]
        if head in sf.bindings:
            tfile, _sym = idx.resolve_symbol(sf, sf.bindings[head])
            if tfile and tfile in idx.files:
                texts.append(idx.files[tfile].text)
        for t in texts:
            m = re.search(r"^\s*(?:async\s+)?def\s+" + re.escape(name) + r"\s*\((?:[^()]|\([^()]*\))*\)\s*->\s*([^:\n]+):", t, re.M)
            if m:
                return [x for x in re.findall(r"\b([A-Z]\w*)\b", m.group(1)) if x in self.repo.models]
        return []

    def _emit_store(self, node, tech, operation, logical, method):
        self.facts.add("store_access", DET, self.ev(node), file=self.sf.path, technology=tech, operation=operation, logical_name=logical, method=method)

    def _call(self, n):
        sf, facts, repo = self.sf, self.facts, self.repo
        fnode = n.child_by_field_name("function"); args = n.child_by_field_name("arguments")
        if fnode is None or args is None:
            return
        ftxt = re.sub(r"\s+", "", sf.node_text(fnode))
        argtext = sf.node_text(args)[1:-1]
        nargs = args.named_children
        parts = _chain(ftxt)
        if not parts:
            return
        root = next((".".join(parts[:k]) for k in (3, 2) if ".".join(parts[:k]) in self.local_store or ".".join(parts[:k]) in self.local_sdk), parts[0])
        members = parts[len(root.split(".")):]
        op = members[-1] if members else None
        recv = ".".join(parts[:-1])
        # ---- routing calls
        if op == "register_blueprint" and nargs:
            self._mount(n, recv.split(".")[-1], sf.node_text(nargs[0]), repo.const(_kwarg(argtext, "url_prefix")) or "")
            return
        if op == "include_router" and nargs:
            self._mount(n, recv.split(".")[-1], sf.node_text(nargs[0]), repo.const(_kwarg(argtext, "prefix")) or "")
            self._deps_controls(n, argtext, "router", sf.node_text(nargs[0]).split(".")[0] if sf.node_text(nargs[0]).split(".")[0] in sf.bindings else sf.node_text(nargs[0]).split(".")[-1])
            return
        if op == "add_middleware" and nargs:
            mw = sf.node_text(nargs[0])
            kind = classify_control(mw)
            if kind:
                facts.add("control", DET, self.ev(n), file=sf.path, control_kind=kind, name=mw[:60], scope="router", router=recv.split(".")[-1], ordered=False)
            if "CORS" in mw and re.search(r"allow_origins\s*=\s*\[\s*['\"]\*['\"]", argtext):
                facts.add("weakness", DET, self.ev(n), file=sf.path, weakness_kind="permissive_cors", name="CORSMiddleware allow_origins=['*']")
            return
        if ftxt in ("CORS", "cors.init_app") and nargs:
            if not re.search(r"\b(origins|resources)\s*=", argtext) or re.search(r"origins\s*=\s*['\"]\*['\"]", argtext):
                facts.add("weakness", DET, self.ev(n), file=sf.path, weakness_kind="permissive_cors", name="flask-cors with all origins")
            return
        if op in ("add_resource", "add_url_rule") and len(nargs) >= 2:
            a0, a1 = sf.node_text(nargs[0]), sf.node_text(nargs[1])
            path = _lit(a1) if op == "add_resource" else _lit(a0)
            view = a0 if op == "add_resource" else (_kwarg(argtext, "view_func") or (sf.node_text(nargs[2]) if len(nargs) > 2 else None))
            if path is not None and view:
                rfile, rlocal = self.router_key(recv.split(".")[-1])
                if op == "add_resource":
                    vfile = self.idx.resolve_symbol(sf, sf.bindings[view])[0] if view in sf.bindings else sf.path
                    for meth in HTTP_VERBS:
                        if vfile and (vfile, f"{view}.{meth}") in {(k[0], f"{k[1]}.{meth}") for k in self.idx.classes.classes if k[0] == vfile and k[1] == view} and re.search(r"def\s+" + meth + r"\s*\(", self.idx.files[vfile].text):
                            facts.add("entry_point", DET, self.ev(n), file=sf.path, protocol="http", method=meth.upper(), path=path, router=rlocal, router_file=rfile, route_controls=[], handler_file=vfile, handler_symbol=f"{view}.{meth}")
                else:
                    facts.add("entry_point", DET, self.ev(n), file=sf.path, protocol="http", method="ANY", path=path, router=rlocal, router_file=rfile, route_controls=[], handler_ref=re.sub(r"\.as_view\(.*$", "", view, flags=re.S)[:120])
            return
        if (op == "run" and recv.split(".")[-1] in self.routers) or ftxt == "uvicorn.run":
            facts.add("listener", DET, self.ev(n), file=sf.path, port=(_kwarg(argtext, "port") or "?")[:40], tls=bool(re.search(r"ssl_(context|keyfile|certfile)", argtext)))
            if re.search(r"\bdebug\s*=\s*True", argtext):
                facts.add("weakness", DET, self.ev(n), file=sf.path, weakness_kind="debug_mode_enabled", name="debug=True on the application server")
            return
        # ---- secrets
        if ftxt in ("os.getenv", "os.environ.get", "environ.get", "getenv", "config", "env", "env.str") and nargs and nargs[0].type == "string":
            name = _lit(sf.node_text(nargs[0])) or ""
            if is_secret_name(name):
                facts.add("config_value", DET, self.ev(n), file=sf.path, name=name, data_class="secret")
            return
        # ---- gRPC
        if ftxt in ("grpc.insecure_channel", "grpc.secure_channel", "grpc.aio.insecure_channel", "grpc.aio.secure_channel"):
            a0 = sf.node_text(nargs[0]) if nargs else ""
            addr = _lit(a0)
            if addr is None:
                m = re.search(r"['\"]([A-Z0-9_]+)['\"]", a0) if re.search(r"(environ|getenv)", a0) else None
                addr = ("env:" + m.group(1)) if m else ("env:" + self.env_of_var[a0] if a0 in self.env_of_var else None)
            if addr is None:
                addr = "variable:" + a0[:40]
            host = addr if addr.startswith(("env:", "variable:")) else (addr[1:addr.index("]")] if addr.startswith("[") and "]" in addr else addr.split(":")[0])
            if not is_local(host):
                facts.add("outbound_call", DET, self.ev(n), file=sf.path, protocol="grpc", operation="grpc channel", sdk_service=None, host=host, entity_kind="system", package="grpc", insecure="insecure" in ftxt)
                if "insecure" in ftxt:
                    facts.add("weakness", DET, self.ev(n), file=sf.path, weakness_kind="unencrypted_transport", name="grpc.insecure_channel")
            return
        m = re.match(r"^(?:\w+\.)*add_(\w+)Servicer_to_server$", ftxt)
        if m:
            facts.add("entry_point", DET, self.ev(n), file=sf.path, protocol="grpc", method="grpc", path=grpc_service_name(m.group(1)), router="<grpc>", handler_scope="file")
            return
        if op == "add_insecure_port" or op == "add_secure_port":
            facts.add("listener", DET, self.ev(n), file=sf.path, port=sf.node_text(nargs[0])[:40] if nargs else "?", tls=op == "add_secure_port")
            return
        if "verify=False" in argtext.replace(" ", ""):
            facts.add("weakness", DET, self.ev(n), file=sf.path, weakness_kind="tls_verification_disabled", name="verify=False")
        # ---- outbound HTTP
        if (root in self.local_http or ftxt.startswith(("requests.", "httpx.", "urllib.request.urlopen"))) and (op in HTTP_VERBS + ("request", "urlopen", "stream", "send") or root == ftxt):
            a0 = nargs[1] if op == "request" and len(nargs) > 1 else (nargs[0] if nargs else None)
            raw = sf.node_text(a0) if a0 is not None else ""
            m = re.search(r"['\"](https?)://([A-Za-z0-9.-]+)", raw)
            host, scheme = (m.group(2).lower(), m.group(1)) if m else (None, None)
            if host is None:
                lit = _lit(raw)
                if lit is not None and lit.startswith("/"):
                    return
                var = next((v for v in re.findall(r"\b([A-Za-z_]\w*)\b", raw) if v in self.env_of_var), None)
                host = ("env:" + self.env_of_var[var]) if var else "variable:" + raw[:40]
            resolved = not host.startswith(("env:", "variable:"))
            facts.add("outbound_call", DET, self.ev(n), file=sf.path, protocol=scheme if resolved else "unknown", operation=op or "request", sdk_service=None, host=host, entity_kind="system", package=sf.bindings.get(root, root).split(":")[0])
            if scheme == "http" and resolved and not is_local(host):
                facts.add("weakness", DET, self.ev(n), file=sf.path, weakness_kind="unencrypted_transport", name=f"plain http:// to {host}")
            return
        # ---- SDK usage
        if root in self.local_sdk and members:
            sdk = self.local_sdk[root]
            name, host, kind = SDK_PKGS[sdk]
            if sdk in ("boto3", "botocore") and members[0] in ("client", "resource") and nargs and nargs[0].type == "string":
                svc = _lit(sf.node_text(nargs[0]))
                if svc in ("s3", "dynamodb", "sqs"):
                    facts.add("store_access", DET, self.ev(n), file=sf.path, technology=svc, operation="client_init", package="boto3")
                    return
                name = f"AWS {svc.upper()}"
            facts.add("outbound_call", DET, self.ev(n), file=sf.path, protocol="smtp" if "SMTP" in name else "https", operation=".".join(members)[:60], sdk_service=name, host=host, entity_kind=kind, package=sdk)
            return
        if op == "send" and re.search(r"(^|\.)mail$", recv) and any(s.startswith("flask_mail") for s in self.specs | {sp for f in repo.files for sp in [v.split(":")[0] for v in f.bindings.values()]}):
            facts.add("outbound_call", DET, self.ev(n), file=sf.path, protocol="smtp", operation="send", sdk_service="SMTP mail relay", host=None, entity_kind="system", package="flask_mail")
            return
        # ---- data stores
        self._store_call(n, ftxt, parts, root, members, op, recv, argtext, nargs)

    def _mount(self, node, parent, child_expr, prefix):
        sf = self.sf
        child_expr = child_expr.strip()
        head = child_expr.split(".")[0]
        if child_expr in self.routers:
            cfile, clocal = sf.path, child_expr
        elif head in sf.bindings:
            cfile, sym = self.idx.resolve_symbol(sf, sf.bindings[head])
            clocal = child_expr.split(".")[-1] if "." in child_expr else (sym or child_expr)
        else:
            cfile, clocal = sf.path, child_expr.split(".")[-1]
        if cfile:
            pfile, plocal = self.router_key(parent)
            self.facts.add("router_mount", DET, self.ev(node), file=pfile if pfile != sf.path else sf.path, parent=plocal, prefix=prefix, child_file=cfile, child_local=clocal)

    def _store_call(self, n, ftxt, parts, root, members, op, recv, argtext, nargs):
        sf, repo = self.sf, self.repo
        if op is None:
            return
        # (a) SQLAlchemy-style sessions
        if SESSION_RX.search(recv) and (op in SESSION_WRITE or op in SESSION_READ or op in SESSION_EXEC):
            models = self._models_for_args(n, argtext)
            if op in SESSION_EXEC:
                raw = argtext
                if not self._models_in(argtext):
                    body, _ = self._fn_text(n)
                    for var in re.findall(r"\b([a-z_]\w*)\b", argtext):
                        for mm in re.finditer(r"^\s*" + re.escape(var) + r"\s*=\s*", body, re.M):
                            raw += " " + _balanced(body, mm.end())
                sqlm = re.search(r"text\(\s*['\"](.+?)['\"]", raw, re.S) or re.search(r"^\s*[rf]?['\"]{1,3}(.+?)['\"]", raw, re.S)
                if sqlm and re.search(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", sqlm.group(1), re.I):
                    self._emit_store(n, repo.tech, sql_operation(sqlm.group(1)), sql_table(sqlm.group(1)), op); return
                operation = "write" if re.search(r"\b(insert|update|delete)\(", raw) else "read"
                models = models or self._models_in(raw)
            else:
                operation = "write" if op in SESSION_WRITE else "read"
            for mdl in models or [None]:
                self._emit_store(n, repo.models[mdl][4] == "mongodb" and "mongodb" or repo.tech if mdl else repo.tech, operation, repo.models[mdl][0] if mdl else None, op)
            return
        # (b) Model.query / Model.objects / Model.select() chains and db.first_or_404(select(Model))
        if parts[0] in repo.models and len(parts) >= 2:
            logical, _f, _s, _e, kind = repo.models[parts[0]]
            chain = parts[1:]
            if chain[0] in ("query", "objects", "select", "find", "find_one", "get", "get_or_none", "filter", "create", "insert", "insert_many", "update", "delete", "get_or_create", "bulk_create", "all", "count", "search", "reindex", "aggregate") or op in ("search",):
                write = any(c in ("create", "insert", "insert_many", "update", "delete", "get_or_create", "bulk_create", "update_or_create", "bulk_update", "save", "remove") for c in chain)
                self._emit_store(n, repo.tech if kind == "sql" else "mongodb", "write" if write else "read", logical, ".".join(chain)[:40])
                return
        if op in ("first_or_404", "get_or_404", "one_or_404", "paginate") and self._models_in(argtext):
            for mdl in self._models_in(argtext):
                self._emit_store(n, repo.tech, "read", repo.models[mdl][0], op)
            return
        # (c) instance save()/delete() on a model object (Django, mongoengine)
        if op in ("save", "delete") and len(parts) == 2 and not nargs and any(s.startswith(("django", "mongoengine", "flask_mongoengine", "peewee")) for s in self.specs):
            for mdl in self._models_for_args(n, parts[0]):
                self._emit_store(n, repo.tech if repo.models[mdl][4] == "sql" else "mongodb", "write", repo.models[mdl][0], op)
            return
        # (d) raw drivers and typed clients
        generic = parts[0] in ("db", "cursor", "cur", "conn", "connection", "redis_client", "r", "rdb", "cache", "client", "collection", "mongo", "pool", "engine", "table", "bucket", "vector_store", "vectorstore", "store", "retriever")
        if root in SQL_EXPR_HELPERS or (op in SQL_STATEMENT_BUILDERS and (sf.bindings.get(root, "").split(":")[0].startswith(("sqlalchemy", "sqlmodel")) or root in ("db", "sa", "sqlalchemy"))):
            return                  # statement construction, not an access: the session call that runs it is
        if (root in self.local_store or (generic and (self.store_techs() or self.local_store))) and members and not SESSION_RX.search(recv):
            if op in ("fetchone", "fetchall", "fetchmany", "commit", "rollback", "close", "cursor", "connect", "ping", "pipeline"):
                return
            if not (WRITE_RX.match(op) or READ_RX.match(op) or op in ("execute", "executemany", "fetch", "fetchrow", "fetchval")):
                return
            techs = [t for t in self.store_techs() if t != "sql"]
            tech = self.local_store.get(root) or (techs[0] if len(techs) == 1 else ("sql" if "sql" in self.store_techs() else "unknown"))
            operation = "write" if WRITE_RX.match(op) else "read"
            logical = None
            if op in ("execute", "executemany", "fetch", "fetchrow", "fetchval") and nargs:
                sql = sf.node_text(nargs[0])
                if not re.search(r"\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP)\b", sql, re.I):
                    return
                operation = sql_operation(sql); logical = sql_table(sql)
                hit = sql_schema(sql)
                if hit:
                    self.facts.add("schema", DET, self.ev(nargs[0]), file=sf.path, name=hit[0], fields=[{"name": c, "type": "column"} for c in hit[1]], schema_kind="sql")
            elif tech == "redis":
                key = _lit(sf.node_text(nargs[0])) if nargs else None
                logical = (re.split(r"[:{]", key)[0] + ":*") if key and re.search(r"[:{]", key) and re.split(r"[:{]", key)[0] else None
            elif tech == "mongodb" and len(members) >= 2 and members[-2] not in ("db", "client"):
                logical = members[-2]
            if tech == "sql":
                tech = repo.tech
            self._emit_store(n, tech, operation, logical, op)
            return
        # (e) clients held on an application object: current_app.elasticsearch.search(...), app.redis.get(...)
        for seg in parts[1:-1]:
            tech = SEGMENT_TECH.get(seg.lower())
            if tech and (WRITE_RX.match(op) or READ_RX.match(op) or op in ("index", "search", "delete")):
                self._emit_store(n, tech, "write" if (WRITE_RX.match(op) or op in ("index", "delete")) and op != "search" else "read", None, op)
                return
        if op in ("enqueue", "enqueue_call", "enqueue_in", "enqueue_at") and repo.rq:
            self._emit_store(n, "redis", "write", "rq:*", op)
