"""Go detector: net/http, gorilla/mux, gin, echo, chi, fiber routing with route groups (including
groups passed to register functions in other packages), middleware as ordered controls, gRPC
servers and clients with env-mapped addresses, database/sql, GORM models and table resolution,
go-redis, MongoDB, outbound HTTP, secrets and weaknesses. Line-oriented with function scopes.
Coverage statement: literal paths; a GORM call whose model type cannot be traced reports an unresolved table."""
import os, re
from ..model import classify_control, is_secret_name, evidence
from .common import sql_operation, sql_table, host_of_url, is_local, grpc_service_name

DET = "go@0.5"
STORE_IMPORTS = [("github.com/go-redis/redis", "redis"), ("github.com/redis/go-redis", "redis"), ("github.com/gomodule/redigo", "redis"), ("go.mongodb.org/mongo-driver", "mongodb"), ("github.com/jackc/pgx", "postgres"),
                 ("github.com/lib/pq", "postgres"), ("gorm.io/driver/postgres", "postgres"), ("gorm.io/driver/mysql", "mysql"), ("github.com/go-sql-driver/mysql", "mysql"), ("gorm.io/driver/sqlite", "sqlite"),
                 ("github.com/mattn/go-sqlite3", "sqlite"), ("github.com/glebarez/sqlite", "sqlite"), ("gorm.io/driver/sqlserver", "mssql"), ("cloud.google.com/go/storage", "gcs"), ("github.com/aws/aws-sdk-go-v2/service/s3", "s3"),
                 ("github.com/aws/aws-sdk-go/service/s3", "s3"), ("github.com/aws/aws-sdk-go-v2/service/dynamodb", "dynamodb"), ("github.com/segmentio/kafka-go", "kafka"), ("github.com/IBM/sarama", "kafka"),
                 ("github.com/Shopify/sarama", "kafka"), ("github.com/streadway/amqp", "rabbitmq"), ("github.com/rabbitmq/amqp091-go", "rabbitmq"), ("github.com/elastic/go-elasticsearch", "elasticsearch"),
                 ("cloud.google.com/go/alloydbconn", "postgres"), ("gorm.io/gorm", "sql"), ("github.com/jinzhu/gorm", "sql"), ("github.com/jmoiron/sqlx", "sql"), ("database/sql", "sql")]
SDK_IMPORTS = [("github.com/stripe/stripe-go", ("Stripe API", "api.stripe.com", "system")), ("cloud.google.com/go/profiler", ("Google Cloud Profiler", None, "system")), ("go.opentelemetry.io/otel/exporters/otlp", ("OTLP collector", None, "system")),
               ("github.com/sendgrid/sendgrid-go", ("SendGrid API", "api.sendgrid.com", "system")), ("github.com/sashabaranov/go-openai", ("OpenAI API", "api.openai.com", "llm_api")),
               ("github.com/anthropics/anthropic-sdk-go", ("Anthropic API", "api.anthropic.com", "llm_api")), ("cloud.google.com/go/vertexai", ("Google Vertex AI", None, "llm_api")),
               ("github.com/google/generative-ai-go", ("Google Gemini API", "generativelanguage.googleapis.com", "llm_api")), ("github.com/twilio/twilio-go", ("Twilio API", "api.twilio.com", "system"))]
ROUTER_TYPES = re.compile(r"\*?(gin\.RouterGroup|gin\.Engine|gin\.IRouter|gin\.IRoutes|mux\.Router|chi\.Router|chi\.Mux|echo\.Group|echo\.Echo|fiber\.Router|fiber\.App|http\.ServeMux)")
APP_CTOR = re.compile(r"\b(\w+)\s*:?=\s*(gin\.Default|gin\.New|mux\.NewRouter|chi\.NewRouter|chi\.NewMux|echo\.New|fiber\.New|http\.NewServeMux)\(")
GROUP_RX = re.compile(r"\b(\w+)\s*:?=\s*(\w+)\.(?:Group\(\s*\"([^\"]*)\"|PathPrefix\(\s*\"([^\"]*)\"\s*\)\.Subrouter\(|Route\(\s*\"([^\"]*)\")")
ROUTE_RX = re.compile(r"\b(\w+)\.(HandleFunc|Handle|GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|Any|Get|Post|Put|Patch|Delete|Head|Options|All|Add)\(\s*(?:\w+\s*\+\s*)?\"([^\"]*)\"\s*,\s*(.+)$")
GORM_OPS = {"First": "read", "Find": "read", "Take": "read", "Last": "read", "Count": "read", "Pluck": "read", "Scan": "read", "Preload": "read", "Association": "read", "Row": "read", "Rows": "read",
            "Save": "write", "Create": "write", "Delete": "write", "Update": "write", "Updates": "write", "FirstOrCreate": "write", "UpdateColumn": "write", "CreateInBatches": "write", "AutoMigrate": None}
VERBS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


def _ev(sf, s, e=None):
    return evidence(sf, s, e, DET)


def _env_for(text, var, depth=0):
    """mustMapEnv(&svc.cartSvcAddr, "CART_SERVICE_ADDR") or x := os.Getenv("X") -> env var name for a variable."""
    if not var or depth > 4:
        return None
    base = var.split(".")[-1]
    m = re.search(r"mustMapEnv\(&[\w.]*\b" + re.escape(base) + r"\s*,\s*\"([A-Z0-9_]+)\"", text) or re.search(r"\b" + re.escape(base) + r"\s*:?=\s*os\.Getenv\(\s*\"([A-Z0-9_]+)\"", text)
    if m:
        return m.group(1)
    m = re.search(r"&[\w.]*\b" + re.escape(base) + r"\s*,\s*([\w.]+Addr)\b", text)   # conn created from an address variable
    return _env_for(text, m.group(1), depth + 1) if m and m.group(1).split(".")[-1] != base else None


class _Repo:
    def __init__(self, idx):
        self.files = [sf for sf in idx.files.values() if sf.lang == "go" and not sf.is_test]
        self.pkg_text = {}
        for sf in self.files:
            self.pkg_text.setdefault(os.path.dirname(sf.path), []).append(sf.text)
        self.pkg_text = {d: "\n".join(t) for d, t in self.pkg_text.items()}
        all_text = "\n".join(self.pkg_text.values())
        techs = sorted({t for imp, t in STORE_IMPORTS if ('"' + imp) in all_text and t in ("postgres", "mysql", "sqlite", "mssql")})
        self.sql_tech = techs[0] if len(techs) == 1 else "sql"
        # functions that take a router: (dir, func) -> (file, param)
        self.router_funcs = {}
        self.models = {}     # struct name -> (file, line)
        for sf in self.files:
            for m in re.finditer(r"^func\s+(?:\([^)]*\)\s*)?(\w+)\(([^)]*)\)", sf.text, re.M):
                for pm in re.finditer(r"(\w+)\s+(\*?[\w.]+)", m.group(2)):
                    if ROUTER_TYPES.fullmatch(pm.group(2)):
                        self.router_funcs[(os.path.dirname(sf.path), m.group(1))] = (sf.path, pm.group(1))
            for m in re.finditer(r"^type\s+(\w+)\s+struct\s*\{([^}]*)\}", sf.text, re.M | re.S):
                if "gorm.Model" in m.group(2) or 'gorm:"' in m.group(2) or 'bson:"' in m.group(2):
                    self.models[m.group(1)] = (sf.path, sf.line_of_offset(m.start()), m.group(2), 'bson:"' in m.group(2) and 'gorm:"' not in m.group(2))


def run(idx, facts):
    repo = _Repo(idx)
    for name, (f, line, body, mongo) in sorted(repo.models.items()):
        sf = idx.files[f]
        facts.add("store_access", DET, _ev(sf, line), file=f, technology="mongodb" if mongo else repo.sql_tech, operation="model_definition", logical_name=name)
        fields = [{"name": m.group(1), "type": m.group(2)[:30]} for m in re.finditer(r"^\s*(\w+)\s+([\w.*\[\]]+)", body, re.M) if m.group(1) not in ("gorm",)]
        if fields:
            facts.add("schema", DET, _ev(sf, line, line + body.count("\n") + 1), file=f, name=name, fields=fields, schema_kind="model")
    for sf in repo.files:
        _file(idx, sf, facts, repo)


def _func_scopes(sf):
    """[(start_line, end_line, func name, {router param names})] from brace matching on top-level funcs."""
    out = []
    for m in re.finditer(r"^func\s+(?:\(([^)]*)\)\s*)?(\w+)\(([^)]*)\)[^{]*\{", sf.text, re.M):
        start = sf.line_of_offset(m.start())
        depth = 0; i = m.end() - 1
        while i < len(sf.text):
            c = sf.text[i]
            depth += c == "{"; depth -= c == "}"
            if depth == 0:
                break
            i += 1
        params = {pm.group(1) for pm in re.finditer(r"(\w+)\s+(\*?[\w.]+)", m.group(3)) if ROUTER_TYPES.fullmatch(pm.group(2))}
        out.append((start, sf.line_of_offset(i), m.group(2), params, m.group(3)))
    return out


def _file(idx, sf, facts, repo):
    text, lines = sf.text, sf.lines
    d = os.path.dirname(sf.path)
    pkg_text = repo.pkg_text.get(d, text)
    scopes = _func_scopes(sf)
    is_web = bool(re.search(r"\"(net/http|github.com/gorilla/mux|github.com/gin-gonic/gin|github.com/labstack/echo[\w/]*|github.com/go-chi/chi[\w/]*|github.com/gofiber/fiber[\w/]*)\"", text))
    uses_gorm = "gorm" in pkg_text
    routers = set()

    def scope_of(line):
        return next((s for s in scopes if s[0] <= line <= s[1]), None)

    def local(name, line):
        s = scope_of(line)
        return f"{s[2]}:{name}" if s and name in s[3] else name

    for s in scopes:
        for p in sorted(s[3]):
            facts.add("router", DET, _ev(sf, s[0]), file=sf.path, local=f"{s[2]}:{p}", own_prefix="", root=False)
            routers.add(f"{s[2]}:{p}")
    # join method-chain continuation lines into statements: (first line, text)
    stmts = []
    i = 0
    while i < len(lines):
        t = lines[i]; start = i + 1
        while i + 1 < len(lines) and (lines[i + 1].lstrip().startswith(".") or t.rstrip().endswith((".", ",", "("))) and len(t) < 2000:
            i += 1; t += " " + lines[i].strip()
        stmts.append((start, t)); i += 1

    for i, l in enumerate(lines, 1):
        s = l.strip()
        if s.startswith("//"):
            continue
        for imp, tech in STORE_IMPORTS:
            if s.endswith('"' + imp + '"') or ('"' + imp + "/") in s or s.endswith('"' + imp + '"'):
                if tech != "sql":
                    facts.add("store_access", DET, _ev(sf, i), file=sf.path, technology=tech, operation="client_init", package=imp)
        for imp, (name, host, kind) in SDK_IMPORTS:
            if ('"' + imp) in s:
                facts.add("outbound_call", DET, _ev(sf, i), file=sf.path, protocol="https", operation="sdk_import", sdk_service=name, host=host, entity_kind=kind, package=imp)
        for m in re.finditer(r"os\.Getenv\(\s*\"([A-Z0-9_]+)\"", l):
            if is_secret_name(m.group(1)):
                facts.add("config_value", DET, _ev(sf, i), file=sf.path, name=m.group(1), data_class="secret")
        if re.search(r"InsecureSkipVerify:\s*true", l):
            facts.add("weakness", DET, _ev(sf, i), file=sf.path, weakness_kind="tls_verification_disabled", name="InsecureSkipVerify: true")
        m = re.search(r"\b(?:http\.ListenAndServe(TLS)?|\w+\.Run(TLS)?|\w+\.Start(TLS)?|\w+\.Listen)\(\s*([^,)]*)", l)
        if m and is_web and re.search(r"(ListenAndServe|\.Run(TLS)?\(|\.Start|\.Listen\()", l) and not re.search(r"\b(cmd|exec|wg|t|group)\.", l):
            facts.add("listener", DET, _ev(sf, i), file=sf.path, port=m.group(4).strip()[:40] or "?", tls=bool(m.group(1) or m.group(2) or m.group(3)))
        m = re.search(r"net\.Listen\(\"tcp\",\s*([^)]+)\)", l)
        if m:
            facts.add("listener", DET, _ev(sf, i), file=sf.path, port=m.group(1).strip()[:40], tls=False)
        # ---- gRPC
        m = re.search(r"\b\w+\.Register(\w+)Server\(", l)
        if m:
            facts.add("entry_point", DET, _ev(sf, i), file=sf.path, protocol="grpc", method="grpc", path=grpc_service_name(m.group(1)), router="<grpc>", handler_scope="package")
        m = re.search(r"\b\w+\.New(\w+)Client\(\s*([\w.]+)", l)
        if m and ("grpc" in pkg_text) and m.group(1) not in ("HTTP", "Redis", "Mongo"):
            env = _env_for(pkg_text, m.group(2))
            facts.add("outbound_call", DET, _ev(sf, i), file=sf.path, protocol="grpc", operation=f"grpc {m.group(1)}", sdk_service=None, host=("env:" + env) if env else f"svc:{m.group(1)}", entity_kind="system", package="grpc",
                      insecure="insecure.NewCredentials" in pkg_text or "WithInsecure" in pkg_text, service_hint=m.group(1))
        m = re.search(r"\bgrpc\.(?:Dial|DialContext|NewClient)\(\s*(?:ctx,\s*)?([^,)]+)", l)
        if m and not re.search(r"\bpb\.New\w+Client\(", pkg_text):
            arg = m.group(1).strip()
            host = arg.strip('"').split(":")[0] if arg.startswith('"') else None
            if host is None:
                env = _env_for(pkg_text, arg)
                host = ("env:" + env) if env else "variable:" + arg[:30]
            if not is_local(host):
                facts.add("outbound_call", DET, _ev(sf, i), file=sf.path, protocol="grpc", operation="grpc dial", sdk_service=None, host=host, entity_kind="system", package="grpc", insecure="insecure" in pkg_text)
        if "insecure.NewCredentials()" in l or "grpc.WithInsecure()" in l:
            facts.add("weakness", DET, _ev(sf, i), file=sf.path, weakness_kind="unencrypted_transport", name="gRPC client with insecure credentials")
        # ---- outbound HTTP
        m = re.search(r"\"(https?)://%s[^\"]*\"\s*,\s*([\w.]+)\b", l) or re.search(r"\"(https?)://\"\s*\+\s*([\w.]+)\b", l)
        if m:
            env = _env_for(pkg_text, m.group(2))
            facts.add("outbound_call", DET, _ev(sf, i), file=sf.path, protocol=m.group(1), operation="http", sdk_service=None, host=("env:" + env) if env else "variable:" + m.group(2)[:30], entity_kind="system", package="net/http")
        m = re.search(r"\bhttp\.(?:Get|Post|Head|PostForm)\(\s*\"(https?://[^\"]+)", l) or re.search(r"http\.NewRequest(?:WithContext)?\([^\"]*\"(?:GET|POST|PUT|DELETE|PATCH)\",\s*\"(https?://[^\"]+)", l)
        if m:
            host, scheme = host_of_url(m.group(1))
            if host and not is_local(host):
                facts.add("outbound_call", DET, _ev(sf, i), file=sf.path, protocol=scheme, operation="http", sdk_service=None, host=host, entity_kind="system", package="net/http")
                if scheme == "http":
                    facts.add("weakness", DET, _ev(sf, i), file=sf.path, weakness_kind="unencrypted_transport", name=f"plain http:// to {host}")
        # ---- routers, groups, mounts
        m = APP_CTOR.search(l)
        if m:
            routers.add(m.group(1))
            facts.add("router", DET, _ev(sf, i), file=sf.path, local=m.group(1), own_prefix="", root=True)
            facts.add("app", DET, _ev(sf, i), file=sf.path, framework=m.group(2).split(".")[0])
        m = GROUP_RX.search(l)
        if m and (local(m.group(2), i) in routers or m.group(2) in routers) and is_web:
            child = m.group(1); parent = local(m.group(2), i)
            routers.add(child)
            facts.add("router", DET, _ev(sf, i), file=sf.path, local=child, own_prefix="", root=False)
            facts.add("router_mount", DET, _ev(sf, i), file=sf.path, parent=parent, prefix=m.group(3) or m.group(4) or m.group(5) or "", child_file=sf.path, child_local=child)
        for m in re.finditer(r"(?:\b(\w+)\.)?\b(\w+)\(\s*(\w+)(?:\.Group\(\s*\"([^\"]*)\"\s*\))?\s*[,)]", l):
            pkg, fn, arg, grp = m.groups()
            argl = local(arg, i)
            if argl not in routers:
                continue
            target_dir = sf.go_imports.get(pkg) if pkg else d
            hit = repo.router_funcs.get((target_dir, fn)) if target_dir is not None else None
            if hit:
                facts.add("router_mount", DET, _ev(sf, i), file=sf.path, parent=argl, prefix=grp or "", child_file=hit[0], child_local=f"{fn}:{hit[1]}")
        m = re.search(r"\b(\w+)\.Use\(\s*(.+)\)\s*$", s)
        if m and local(m.group(1), i) in routers:
            for mw in re.findall(r"([\w.]+)(\([^()]*\))?", m.group(2)):
                name = mw[0].split(".")[-1]
                kind = classify_control(name, mw[1].strip("()"))
                if kind:
                    facts.add("control", DET, _ev(sf, i), file=sf.path, control_kind=kind, name=mw[0][:60], scope="router", router=local(m.group(1), i), ordered=True)
        # ---- routes
        m = ROUTE_RX.search(l)
        if m and is_web and (local(m.group(1), i) in routers or m.group(1) in ("http", "r", "router", "mux", "e", "app", "g")):
            recv, verb, path, rest = m.groups()
            if recv == "http" and verb not in ("HandleFunc", "Handle"):
                continue
            rl = local(recv, i)
            if rl not in routers:
                routers.add(rl)
                facts.add("router", DET, _ev(sf, i), file=sf.path, local=rl, own_prefix="", root=recv == "http")
            mm = re.search(r"\.Methods\(([^)]*)\)", rest)
            methods = [x.upper() for x in re.findall(r"(?:http\.Method|\")(\w+)", mm.group(1))] if mm else ([verb.upper()] if verb.upper() in VERBS else ["ANY"])
            g122 = re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE)\s+(\S*)$", path)
            if g122 and verb in ("HandleFunc", "Handle"):     # Go 1.22 ServeMux: "GET /items/{id}" and "POST example.com/x"
                methods, path = [g122.group(1)], g122.group(2)
                path = path[path.index("/"):] if "/" in path and not path.startswith("/") else path
            path = re.sub(r"\{(\w+)\.\.\.\}", r"{\1}", path).replace("{$}", "") if verb in ("HandleFunc", "Handle") else path
            if "GET" in methods and "HEAD" in methods:
                methods.remove("HEAD")
            hpart = re.sub(r"\)\s*\.Methods\(.*$", "", rest).rstrip(") ")
            args = [a.strip() for a in re.split(r",\s*(?![^()]*\))", hpart) if a.strip()]
            handler = args[-1] if args else ""
            controls = []
            for a in args[:-1]:
                nm = a.split("(")[0]
                kind = classify_control(nm.split(".")[-1], a[len(nm):].strip("()"))
                if kind:
                    controls.append(facts.add("control", DET, _ev(sf, i), file=sf.path, control_kind=kind, name=nm[:60], scope="route"))
            attrs = dict(handler_span=(i, i)) if handler.startswith("func") else dict(handler_ref=handler.split("(")[0][:120])
            if handler.startswith("func"):
                # inline handler: its span runs to the matching closing brace
                depth = 0; j = i
                for j in range(i, min(i + 400, len(lines)) + 1):
                    depth += lines[j - 1].count("{") - lines[j - 1].count("}")
                    if depth <= 0 and j > i or (depth <= 0 and "{" in lines[j - 1]):
                        break
                attrs = dict(handler_span=(i, j))
            for meth in methods:
                facts.add("entry_point", DET, _ev(sf, i), file=sf.path, protocol="http", method=meth, path=path, router=rl, route_controls=controls, **attrs)
        # ---- database/sql and other clients
        m = re.search(r"\bsql\.Open\(\s*\"(\w+)\"", l)
        if m:
            tech = {"postgres": "postgres", "pgx": "postgres", "mysql": "mysql", "sqlite3": "sqlite", "sqlite": "sqlite", "sqlserver": "mssql", "mssql": "mssql"}.get(m.group(1), "sql")
            facts.add("store_access", DET, _ev(sf, i), file=sf.path, technology=tech, operation="client_init", package="database/sql")
    # ---- statements: GORM chains, raw SQL, redis/mongo calls
    for start, t in stmts:
        if t.strip().startswith("//"):
            continue
        m = re.search(r"\b\w+\.(?:Query|QueryRow|QueryContext|QueryRowContext|Exec|ExecContext|Get|Select|NamedExec|Raw)\(\s*(?:ctx,\s*|context\.\w+\(\),\s*)?(?:&\w+,\s*)?[\"`]([^\"`]*)", t)
        if not m:   # the statement held in a variable: query := "SELECT ... FROM " + table
            mv = re.search(r"\b\w+\.(?:Query|QueryRow|QueryContext|QueryRowContext|Exec|ExecContext)\(\s*(?:ctx,\s*|context\.\w+\(\),\s*)?(\w+)\s*[,)]", t)
            if mv:
                ma = None
                for ma in re.finditer(r"\b" + re.escape(mv.group(1)) + r"\s*:?=\s*[\"`]([^\"`]*)", sf.text[:sum(len(x) + 1 for x in sf.lines[:start])]):
                    pass
                m = ma
        if m and re.search(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", m.group(1), re.I):
            facts.add("store_access", DET, _ev(sf, start), file=sf.path, technology=repo.sql_tech, operation=sql_operation(m.group(1)), logical_name=sql_table(m.group(1)), method="sql")
            continue
        if uses_gorm and re.search(r"\b(db|tx|DB|database|conn|query)\w*\b[^;]*\.(" + "|".join(GORM_OPS) + r")\(", t):
            ops = [o for o in re.findall(r"\.(\w+)\(", t) if o in GORM_OPS]
            kinds = [GORM_OPS[o] for o in ops if GORM_OPS[o]]
            if not kinds:
                continue
            operation = "write" if "write" in kinds else "read"
            sc = scope_of(start)
            body = "\n".join(lines[sc[0] - 1:sc[1]]) if sc else t
            models = [x for x in re.findall(r"&?\b([A-Z]\w*)\{", t) if x in repo.models] + [x for x in re.findall(r"\bModel\(\s*&?(\w+)\b", t) if x in repo.models]
            if not models:
                for var in re.findall(r"&(\w+)\b", t) + re.findall(r"\((\w+)\)", t):
                    vm = re.search(r"\bvar\s+" + re.escape(var) + r"\s+\[?\]?\*?(?:\w+\.)?(\w+)", body) or re.search(r"\b" + re.escape(var) + r"\s*:=\s*&?\[?\]?(?:\w+\.)?(\w+)\{", body) or \
                         (re.search(r"\b" + re.escape(var) + r"\s+\[?\]?\*?(?:\w+\.)?(\w+)", sc[4]) if sc else None)
                    if vm and vm.group(1) in repo.models:
                        models.append(vm.group(1))
            if not models and sc:   # method on a model receiver: func (u UserModel) following(...)
                rm = re.search(r"^func\s+\(\s*\w+\s+\*?(\w+)\s*\)\s*" + re.escape(sc[2]) + r"\(", sf.text, re.M)
                if rm and rm.group(1) in repo.models and re.search(r"\(\s*&?" + r"(?:self|\w)\w*\s*\)", t):
                    models.append(rm.group(1))
            for mdl in list(dict.fromkeys(models)) or [None]:
                facts.add("store_access", DET, _ev(sf, start), file=sf.path, technology=repo.sql_tech, operation=operation, logical_name=mdl, method=ops[-1])
            continue
        m = re.search(r"\b(\w+)\.(HGet|HSet|HGetAll|Get|Set|SetNX|Incr|Decr|Del|Expire|LPush|RPush|LRange|SAdd|SMembers|Publish|Subscribe)\(", t)
        if m and re.search(r"\b(redis|rdb|cache)\w*", m.group(1), re.I) and "redis" in pkg_text:
            facts.add("store_access", DET, _ev(sf, start), file=sf.path, technology="redis", operation="read" if m.group(2) in ("HGet", "HGetAll", "Get", "LRange", "SMembers", "Subscribe") else "write", logical_name=None, method=m.group(2))
            continue
        m = re.search(r"\.Collection\(\s*\"(\w+)\"\s*\)[^;]*\.(InsertOne|InsertMany|FindOne|Find|UpdateOne|UpdateMany|DeleteOne|DeleteMany|Aggregate|CountDocuments|ReplaceOne)\(", t)
        if m:
            facts.add("store_access", DET, _ev(sf, start), file=sf.path, technology="mongodb", operation="read" if m.group(2) in ("FindOne", "Find", "Aggregate", "CountDocuments") else "write", logical_name=m.group(1), method=m.group(2))
