"""Go, Java (Spring, gRPC) and C# (ASP.NET, gRPC) detectors. Regex over lines with tree-sitter
only for function spans (used by the call graph). Coverage: literal route paths, gRPC service
registration, well-known client packages, env-read secrets, a few weaknesses."""
import re
from ..model import classify_control, SECRET_ENV_RX, LOCAL_HOSTS, evidence

DET = {"go": "go@0.1", "java": "java@0.1", "c_sharp": "csharp@0.1"}


def _ev(sf, s, e=None):
    return evidence(sf, s, e or s, DET[sf.lang])


def _grpc_service_name(raw):
    raw = raw.split(".")[-1]
    for suf in ("Server", "Servicer", "Impl", "Service"):
        if raw.endswith(suf) and len(raw) > len(suf):
            raw = raw[: -len(suf)]
    return raw


def run(idx, facts):
    for sf in idx.files.values():
        if sf.is_test:
            continue
        if sf.lang == "go":
            _go(idx, sf, facts)
        elif sf.lang == "java":
            _java(idx, sf, facts)
        elif sf.lang == "c_sharp":
            _csharp(idx, sf, facts)


# ---------------------------------------------------------------- Go
GO_STORE_IMPORTS = [("github.com/go-redis/redis", "redis"), ("github.com/redis/go-redis", "redis"), ("github.com/gomodule/redigo", "redis"), ("go.mongodb.org/mongo-driver", "mongodb"), ("github.com/jackc/pgx", "postgres"), ("github.com/lib/pq", "postgres"), ("gorm.io/driver/postgres", "postgres"), ("gorm.io/driver/mysql", "mysql"), ("github.com/go-sql-driver/mysql", "mysql"), ("gorm.io/driver/sqlite", "sqlite"), ("github.com/mattn/go-sqlite3", "sqlite"), ("cloud.google.com/go/storage", "gcs"), ("github.com/aws/aws-sdk-go-v2/service/s3", "s3"), ("github.com/aws/aws-sdk-go/service/s3", "s3"), ("github.com/aws/aws-sdk-go-v2/service/dynamodb", "dynamodb"), ("github.com/segmentio/kafka-go", "kafka"), ("github.com/IBM/sarama", "kafka"), ("github.com/Shopify/sarama", "kafka"), ("github.com/streadway/amqp", "rabbitmq"), ("github.com/rabbitmq/amqp091-go", "rabbitmq"), ("cloud.google.com/go/pubsub", "unknown"), ("github.com/elastic/go-elasticsearch", "elasticsearch"), ("cloud.google.com/go/alloydbconn", "postgres"), ("cloud.google.com/go/spanner", "unknown"), ("cloud.google.com/go/firestore", "unknown")]
GO_SDK_IMPORTS = [("github.com/stripe/stripe-go", ("Stripe API", "api.stripe.com", "system")), ("cloud.google.com/go/profiler", ("Google Cloud Profiler", None, "system")), ("go.opentelemetry.io/otel/exporters/otlp", ("OTLP collector", None, "system")), ("github.com/sendgrid/sendgrid-go", ("SendGrid API", "api.sendgrid.com", "system")), ("github.com/sashabaranov/go-openai", ("OpenAI API", "api.openai.com", "llm_api")), ("github.com/anthropics/anthropic-sdk-go", ("Anthropic API", "api.anthropic.com", "llm_api")), ("cloud.google.com/go/vertexai", ("Google Vertex AI", None, "llm_api")), ("github.com/google/generative-ai-go", ("Google Gemini API", "generativelanguage.googleapis.com", "llm_api"))]
GO_ROUTE_RX = re.compile(r"\b(\w+)\.(HandleFunc|Handle|GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Patch|Delete|Any)\(\s*(?:\w+\s*\+\s*)?\"([^\"]+)\"\s*,\s*([\w.]+)")
GO_ROUTE_RX2 = re.compile(r"\bhttp\.(HandleFunc|Handle)\(\s*(?:\w+\s*\+\s*)?\"([^\"]+)\"\s*,\s*([\w.]+)")


def _go(idx, sf, facts):
    text = sf.text; lines = sf.lines
    import os as _os
    pkg_text = "\n".join(f.text for f in idx.files.values() if f.lang == "go" and _os.path.dirname(f.path) == _os.path.dirname(sf.path))
    is_web = any(k in text for k in ("net/http", "github.com/gorilla/mux", "github.com/gin-gonic/gin", "github.com/labstack/echo", "github.com/go-chi/chi"))
    for i, l in enumerate(lines, 1):
        s = l.strip()
        for imp, tech in GO_STORE_IMPORTS:
            if s.startswith('"' + imp) or (" " + '"' + imp) in s:
                facts.add("store_access", DET["go"], [_ev(sf, i)], technology=tech, operation="client_init", package=imp, file=sf.path)
        for imp, (name, host, kind) in GO_SDK_IMPORTS:
            if ('"' + imp) in s:
                facts.add("outbound_call", DET["go"], [_ev(sf, i)], sdk_service=name, host=host, entity_kind=kind, protocol="https", package=imp, file=sf.path, operation="sdk_import", handler=None)
        m = GO_ROUTE_RX.search(l) or None
        if m and (is_web or m.group(2) in ("HandleFunc", "Handle")) and m.group(3).startswith("/"):
            verb = m.group(2).upper() if m.group(2).lower() in ("get", "post", "put", "patch", "delete") else ("ANY" if m.group(2) in ("Any", "HandleFunc", "Handle") else m.group(2))
            mm = re.search(r"\.Methods\(\s*(?:http\.Method)?\"?(\w+)", l)
            if mm: verb = mm.group(1).upper()
            href = m.group(4)
            inline = re.search(r"\bfunc\s*\(", l) is not None and href == "func"
            facts.add("entry_point", DET["go"], [_ev(sf, i)], protocol="http", method=verb, path=m.group(3), file=sf.path, router=m.group(1), handler_span=None, route_controls=[], handler_ref=None if inline else href, handler_module=sf.path, handler_symbol=(f"<anon:{i}>" if inline else href.split(".")[-1]))
        m = GO_ROUTE_RX2.search(l)
        if m and not GO_ROUTE_RX.search(l):
            facts.add("entry_point", DET["go"], [_ev(sf, i)], protocol="http", method="ANY", path=m.group(2), file=sf.path, router="http", handler_span=None, route_controls=[], handler_ref=m.group(3), handler_module=sf.path, handler_symbol=m.group(3).split(".")[-1])
        m = re.search(r"\b\w+\.Register(\w+)Server\(", l)
        if m:
            facts.add("entry_point", DET["go"], [_ev(sf, i)], protocol="grpc", method="grpc", path=m.group(1), file=sf.path, router="grpc", handler_span=None, route_controls=[], handler_ref=None)
        m = re.search(r"\b\w+\.New(\w+)Client\(\s*([\w.]+)", l)
        if m and ("grpc" in pkg_text or "pb." in l):
            svc = m.group(1); connvar = m.group(2)
            env = _go_env_for(pkg_text, connvar)
            facts.add("outbound_call", DET["go"], [_ev(sf, i)], sdk_service=None, host=("env:" + env) if env else f"svc:{svc}", entity_kind="system", protocol="grpc", package="grpc", file=sf.path, operation=f"grpc {svc}", handler=None, insecure="insecure.NewCredentials" in text or "WithInsecure" in text, service_hint=svc)
        m = re.search(r"\bgrpc\.(Dial|DialContext|NewClient)\(\s*(?:ctx,\s*)?([^,)]+)", l)
        if m and "New" not in l.split("grpc.")[0]:
            arg = m.group(2).strip()
            host = None
            if arg.startswith('"'):
                host = arg.strip('"').split(":")[0]
            else:
                env = _go_env_for(pkg_text, arg.split(".")[-1]) or _go_env_for(pkg_text, arg)
                host = "env:" + env if env else "variable:" + arg[:30]
            if host and host not in LOCAL_HOSTS and not (host.startswith("variable:") and re.search(r"\b\w+\.New\w+Client\(", pkg_text)):
                facts.add("outbound_call", DET["go"], [_ev(sf, i)], sdk_service=None, host=host, entity_kind="system", protocol="grpc", package="grpc", file=sf.path, operation="grpc dial", handler=None, insecure="insecure.NewCredentials" in text or "WithInsecure" in text)
        mf = re.search(r"\"(https?)://%s[^\"]*\"\s*,\s*([\w.]+Addr)\b", l) or re.search(r"\"(https?)://\"\s*\+\s*([\w.]+Addr)\b", l)
        if mf:
            env = _go_env_for(pkg_text, mf.group(2))
            facts.add("outbound_call", DET["go"], [_ev(sf, i)], sdk_service=None, host=("env:" + env) if env else "variable:" + mf.group(2)[:30], entity_kind="system", protocol=mf.group(1), package="net/http", file=sf.path, operation="http", handler=None)
        m = re.search(r"\bhttp\.(Get|Post|Head)\(\s*\"(https?://[^\"/]+)", l) or re.search(r"http\.NewRequest(?:WithContext)?\([^,]+,\s*\"(?:GET|POST|PUT|DELETE)\",\s*\"(https?://[^\"/]+)", l)
        if m:
            url = m.group(m.lastindex); host = url.split("://")[1]; scheme = url.split("://")[0]
            facts.add("outbound_call", DET["go"], [_ev(sf, i)], sdk_service=None, host=host, entity_kind="system", protocol=scheme, package="net/http", file=sf.path, operation="http", handler=None, url=url)
            if scheme == "http" and not host.startswith(LOCAL_HOSTS):
                facts.add("weakness", DET["go"], [_ev(sf, i)], weakness_kind="unencrypted_transport", name=f"plain http:// to {host}", file=sf.path)
        m = re.search(r"\bsql\.Open\(\s*\"(\w+)\"", l)
        if m:
            tech = {"postgres": "postgres", "pgx": "postgres", "mysql": "mysql", "sqlite3": "sqlite", "sqlite": "sqlite", "sqlserver": "mssql", "mssql": "mssql"}.get(m.group(1), "unknown")
            facts.add("store_access", DET["go"], [_ev(sf, i)], technology=tech, operation="client_init", package="database/sql", file=sf.path)
        m = re.search(r"\b(\w+)\.(Query|QueryRow|QueryContext|Exec|ExecContext|Get|Select|First|Find|Create|Save|Updates?|Delete|HGet|HSet|Set|Incr|Del|Publish|WriteMessages|ReadMessage|InsertOne|FindOne|UpdateOne|DeleteOne)\(", l)
        if m and any(k in text for k in ("database/sql", "gorm", "redis", "mongo", "kafka", "amqp", "pgx")):
            op = m.group(2)
            operation = "write" if op in ("Exec", "ExecContext", "Create", "Save", "Update", "Updates", "Delete", "HSet", "Set", "Incr", "Del", "Publish", "WriteMessages", "InsertOne", "UpdateOne", "DeleteOne") else "read"
            if op in ("Exec", "ExecContext", "Query", "QueryRow", "QueryContext"):
                operation = "write" if re.search(r"\b(INSERT|UPDATE|DELETE|CREATE)\b", l, re.I) else ("read" if "SELECT" in l.upper() else operation)
            tech = next((t for imp, t in GO_STORE_IMPORTS if imp in text), "unknown")
            mt = re.search(r"\b(?:FROM|INTO|UPDATE)\s+[`\"']?(\w+)", l, re.I)
            facts.add("store_access", DET["go"], [_ev(sf, i)], technology=tech, operation=operation, logical_name=mt.group(1) if mt else None, method=op, file=sf.path, handler=None, local=m.group(1))
        for m in re.finditer(r"os\.Getenv\(\s*\"([A-Z0-9_]+)\"", l):
            if SECRET_ENV_RX.search(m.group(1)) and not m.group(1).endswith(("_URL", "_URI", "_ADDR")):
                facts.add("config_value", DET["go"], [_ev(sf, i)], name=m.group(1), data_class="secret", at_import=False, file=sf.path)
        if "InsecureSkipVerify: true" in l.replace(" ", "") or "InsecureSkipVerify:true" in l.replace(" ", ""):
            facts.add("weakness", DET["go"], [_ev(sf, i)], weakness_kind="tls_verification_disabled", name="InsecureSkipVerify: true", file=sf.path)
        m = re.search(r"\bhttp\.ListenAndServe(TLS)?\(\s*([^,]+)", l) or re.search(r"net\.Listen\(\"tcp\",\s*([^)]+)\)", l)
        if m:
            facts.add("listener", DET["go"], [_ev(sf, i)], port=m.group(m.lastindex).strip()[:40], tls=bool(m.lastindex == 2 and m.group(1)), file=sf.path)
            facts.add("app_entry", DET["go"], [_ev(sf, i)], file=sf.path, middleware=[])
        m = re.search(r"\b(\w+)\.Use\(\s*([\w.]+)", l)
        if m and is_web:
            kind = classify_control(m.group(2).split(".")[-1])
            if kind:
                facts.add("control", DET["go"], [_ev(sf, i)], control_kind=kind, name=m.group(2)[:60], scope="app", path_prefix=None, file=sf.path, order=i)
    if ("insecure.NewCredentials()" in text or "grpc.WithInsecure()" in text):
        ln = next((i for i, l in enumerate(lines, 1) if "insecure.NewCredentials" in l or "WithInsecure" in l), 1)
        facts.add("weakness", DET["go"], [_ev(sf, ln)], weakness_kind="unencrypted_transport", name="gRPC client with insecure credentials", file=sf.path)


def _go_env_for(text, var):
    """mustMapEnv(&svc.cartSvcAddr, "CART_SERVICE_ADDR") or x := os.Getenv("X") -> env var name for a variable."""
    if not var:
        return None
    base = var.split(".")[-1]
    m = re.search(r"mustMapEnv\(&[\w.]*" + re.escape(base) + r"\s*,\s*\"([A-Z0-9_]+)\"", text) or re.search(re.escape(base) + r"\s*:?=\s*os\.Getenv\(\s*\"([A-Z0-9_]+)\"", text)
    if m:
        return m.group(1)
    # connection variable created from an address variable: cartSvcConn <- mustConnGRPC(ctx, &svc.cartSvcConn, svc.cartSvcAddr)
    m = re.search(r"&[\w.]*" + re.escape(base) + r"\s*,\s*([\w.]+Addr)\b", text)
    if m:
        return _go_env_for(text, m.group(1))
    return None


# ---------------------------------------------------------------- Java
JAVA_STORE = [("javax.persistence", "unknown"), ("jakarta.persistence", "unknown"), ("org.springframework.data.jpa", "unknown"), ("org.springframework.jdbc", "unknown"), ("org.springframework.data.redis", "redis"), ("redis.clients.jedis", "redis"), ("io.lettuce", "redis"), ("org.springframework.data.mongodb", "mongodb"), ("com.mongodb", "mongodb"), ("org.springframework.kafka", "kafka"), ("org.apache.kafka", "kafka"), ("org.springframework.amqp", "rabbitmq"), ("com.rabbitmq", "rabbitmq"), ("com.amazonaws.services.s3", "s3"), ("software.amazon.awssdk.services.s3", "s3"), ("software.amazon.awssdk.services.dynamodb", "dynamodb"), ("org.postgresql", "postgres"), ("com.mysql", "mysql"), ("org.elasticsearch", "elasticsearch")]
JAVA_SDK = [("com.stripe", ("Stripe API", "api.stripe.com", "system")), ("com.twilio", ("Twilio API", "api.twilio.com", "system")), ("com.sendgrid", ("SendGrid API", "api.sendgrid.com", "system")), ("io.opentelemetry.exporter", ("OTLP collector", None, "system")), ("com.google.cloud.vertexai", ("Google Vertex AI", None, "llm_api")), ("com.theokanning.openai", ("OpenAI API", "api.openai.com", "llm_api")), ("dev.langchain4j", ("LLM API via langchain4j", None, "llm_api")), ("com.google.cloud.storage", ("Google Cloud Storage", None, "system")), ("com.google.cloud", ("Google Cloud APIs", None, "system"))]


def _java(idx, sf, facts):
    text = sf.text; lines = sf.lines
    class_prefix = ""
    m = re.search(r"@RequestMapping\(\s*(?:value\s*=\s*)?\"([^\"]*)\"[^)]*\)\s*(?:public\s+)?(?:class|@)", text)
    if m: class_prefix = m.group(1)
    has_security = "org.springframework.security" in text
    for i, l in enumerate(lines, 1):
        s = l.strip()
        if s.startswith("import "):
            for imp, tech in JAVA_STORE:
                if imp in s:
                    facts.add("store_access", DET["java"], [_ev(sf, i)], technology=tech, operation="client_init", package=imp, file=sf.path); break
            for imp, (name, host, kind) in JAVA_SDK:
                if imp in s:
                    facts.add("outbound_call", DET["java"], [_ev(sf, i)], sdk_service=name, host=host, entity_kind=kind, protocol="https", package=imp, file=sf.path, operation="sdk_import", handler=None); break
        m = re.search(r"@(Get|Post|Put|Patch|Delete|Request)Mapping\(\s*(?:value\s*=\s*|path\s*=\s*)?\"([^\"]*)\"", l)
        if m:
            verb = m.group(1).upper() if m.group(1) != "Request" else (re.search(r"RequestMethod\.(\w+)", l).group(1) if re.search(r"RequestMethod\.(\w+)", l) else "ANY")
            path = (class_prefix.rstrip("/") + "/" + m.group(2).lstrip("/")).replace("//", "/") if class_prefix else m.group(2)
            # the handler method is the next method declaration
            sym = None
            for j in range(i, min(i + 6, len(lines))):
                mm = re.search(r"\b(\w+)\s*\(", lines[j])
                if mm and not lines[j].strip().startswith("@"):
                    sym = mm.group(1); break
            ctrls = []
            for j in range(max(0, i - 4), i):
                mm = re.search(r"@(PreAuthorize|Secured|RolesAllowed|PermitAll|Authenticated)", lines[j])
                if mm:
                    ctrls.append(facts.add("control", DET["java"], [_ev(sf, j + 1)], control_kind="authz" if mm.group(1) != "Authenticated" else "authn", name="@" + mm.group(1), scope="route", file=sf.path))
            facts.add("entry_point", DET["java"], [_ev(sf, i)], protocol="http", method=verb, path=path or "/", file=sf.path, router="spring", handler_span=None, route_controls=ctrls, handler_ref=sym, handler_module=sf.path, handler_symbol=sym)
        m = re.search(r"\.addService\(\s*new\s+(\w+)\(", l) or re.search(r"\.addService\(\s*(\w+)\s*[),]", l)
        if m:
            facts.add("entry_point", DET["java"], [_ev(sf, i)], protocol="grpc", method="grpc", path=_grpc_service_name(m.group(1)), file=sf.path, router="grpc", handler_span=None, route_controls=[], handler_ref=None)
        m = re.search(r"ManagedChannelBuilder\.forAddress\(\s*([^,]+),\s*([^)]+)\)|ManagedChannelBuilder\.forTarget\(\s*([^)]+)\)", l)
        if m:
            arg = (m.group(1) or m.group(3) or "").strip()
            host = arg.strip('"').split(":")[0] if arg.startswith('"') else None
            if not host:
                env = re.search(r"System\.getenv\(\s*\"([A-Z0-9_]+(?:_ADDR|_HOST|_URL|_ENDPOINT))\"", text)
                host = ("env:" + env.group(1)) if env else "variable:" + arg[:30]
            facts.add("outbound_call", DET["java"], [_ev(sf, i)], sdk_service=None, host=host, entity_kind="system", protocol="grpc", package="grpc", file=sf.path, operation="grpc channel", handler=None, insecure=".usePlaintext()" in text)
        if ".usePlaintext()" in l:
            facts.add("weakness", DET["java"], [_ev(sf, i)], weakness_kind="unencrypted_transport", name="gRPC channel usePlaintext()", file=sf.path)
        if re.search(r"\b(RestTemplate|WebClient|HttpClient)\b", l) and re.search(r"\"https?://[^\"/]+", l):
            url = re.search(r"\"(https?)://([^\"/]+)", l)
            facts.add("outbound_call", DET["java"], [_ev(sf, i)], sdk_service=None, host=url.group(2), entity_kind="system", protocol=url.group(1), package="http", file=sf.path, operation="http", handler=None)
        for m in re.finditer(r"System\.getenv\(\s*\"([A-Z0-9_]+)\"", l):
            if SECRET_ENV_RX.search(m.group(1)) and not m.group(1).endswith(("_URL", "_URI", "_ADDR")):
                facts.add("config_value", DET["java"], [_ev(sf, i)], name=m.group(1), data_class="secret", at_import=False, file=sf.path)
        if re.search(r"csrf\(\)\s*\.disable\(\)|\.csrf\(\s*\w+\s*->\s*\w+\.disable\(\)\)", l):
            facts.add("weakness", DET["java"], [_ev(sf, i)], weakness_kind="csrf_disabled", name="Spring Security csrf().disable()", file=sf.path)
        if "@Entity" in s or "@Document" in s:
            # fields of the following class
            fields = []
            for j in range(i, min(i + 80, len(lines))):
                mm = re.match(r"\s*(?:private|protected|public)\s+([\w<>\[\], ]+)\s+(\w+)\s*(=|;)", lines[j])
                if mm: fields.append({"name": mm.group(2), "type": mm.group(1).strip()[:30]})
                if lines[j].strip().startswith("}") and j > i + 2 and lines[j].startswith("}"):
                    break
            cm = re.search(r"class\s+(\w+)", "\n".join(lines[i:i + 6]))
            if fields and cm:
                facts.add("schema", DET["java"], [_ev(sf, i, min(i + 80, len(lines)))], name=cm.group(1), fields=fields, file=sf.path, schema_kind="model")
                facts.add("store_access", DET["java"], [_ev(sf, i)], technology="mongodb" if "@Document" in s else "unknown", operation="model_definition", logical_name=cm.group(1), method="entity", file=sf.path, handler=None, local=None)
        m = re.search(r"\b(\w+)\.(save|saveAll|findById|findAll|findBy\w+|delete\w*|query|queryForObject|queryForList|update|execute|batchUpdate|opsForValue|opsForHash|send|convertAndSend|insert|aggregate)\(", l)
        if m and any(imp in text for imp, _ in JAVA_STORE):
            op = m.group(2)
            operation = "read" if op.startswith(("find", "query", "opsFor")) else "write"
            tech = next((t for imp, t in JAVA_STORE if imp in text and t != "unknown"), next((t for imp, t in JAVA_STORE if imp in text), "unknown"))
            facts.add("store_access", DET["java"], [_ev(sf, i)], technology=tech, operation=operation, logical_name=None, method=op, file=sf.path, handler=None, local=m.group(1))
        m = re.search(r"\.forPort\(\s*(\w+)\s*\)|ServerBuilder\.forPort\(\s*(\w+)", l)
        if m:
            facts.add("listener", DET["java"], [_ev(sf, i)], port=(m.group(1) or m.group(2))[:40], tls="useTransportSecurity" in text, file=sf.path)
            facts.add("app_entry", DET["java"], [_ev(sf, i)], file=sf.path, middleware=[])
    if has_security and re.search(r"(authorizeHttpRequests|authorizeRequests|authenticated\(\)|oauth2ResourceServer|httpBasic|formLogin)", text):
        ln = next((i for i, l in enumerate(lines, 1) if re.search(r"(authorizeHttpRequests|authorizeRequests)", l)), 1)
        facts.add("control", DET["java"], [_ev(sf, ln)], control_kind="authn", name="Spring Security filter chain", scope="file", path_prefix=None, file=sf.path, order=1)
    if "@SpringBootApplication" in text:
        facts.add("app_entry", DET["java"], [_ev(sf, 1)], file=sf.path, middleware=[])


# ---------------------------------------------------------------- C#
CS_STORE = [("StackExchange.Redis", "redis"), ("Microsoft.Extensions.Caching.Distributed", "unknown"), ("Microsoft.Extensions.Caching.Memory", "memcached"), ("AddStackExchangeRedisCache", "redis"), ("UseNpgsql", "postgres"), ("Npgsql", "postgres"), ("UseSqlServer", "mssql"), ("UseMySql", "mysql"), ("UseSqlite", "sqlite"), ("MongoDB.Driver", "mongodb"), ("Confluent.Kafka", "kafka"), ("RabbitMQ.Client", "rabbitmq"), ("Amazon.S3", "s3"), ("Amazon.DynamoDBv2", "dynamodb"), ("Azure.Storage.Blobs", "unknown"), ("Microsoft.EntityFrameworkCore", "unknown"), ("Dapper", "unknown"), ("Google.Cloud.AlloyDb", "postgres"), ("Google.Cloud.Spanner", "unknown")]
CS_SDK = [("Stripe", ("Stripe API", "api.stripe.com", "system")), ("Twilio", ("Twilio API", "api.twilio.com", "system")), ("SendGrid", ("SendGrid API", "api.sendgrid.com", "system")), ("OpenTelemetry.Exporter", ("OTLP collector", None, "system")), ("Azure.AI.OpenAI", ("Azure OpenAI", None, "llm_api")), ("OpenAI", ("OpenAI API", "api.openai.com", "llm_api")), ("Anthropic", ("Anthropic API", "api.anthropic.com", "llm_api")), ("Google.Cloud.AIPlatform", ("Google Vertex AI", None, "llm_api"))]


def _csharp(idx, sf, facts):
    text = sf.text; lines = sf.lines
    route_prefix = ""
    m = re.search(r"\[Route\(\s*\"([^\"]*)\"\s*\)\]", text)
    if m: route_prefix = "/" + m.group(1).replace("[controller]", (re.search(r"class\s+(\w+)Controller", text).group(1).lower() if re.search(r"class\s+(\w+)Controller", text) else "controller")).lstrip("/")
    for i, l in enumerate(lines, 1):
        s = l.strip()
        if s.startswith("using "):
            for imp, tech in CS_STORE:
                if imp in s:
                    facts.add("store_access", DET["c_sharp"], [_ev(sf, i)], technology=tech, operation="client_init", package=imp, file=sf.path); break
            for imp, (name, host, kind) in CS_SDK:
                if re.search(r"\busing\s+" + re.escape(imp) + r"[.;]", s):
                    facts.add("outbound_call", DET["c_sharp"], [_ev(sf, i)], sdk_service=name, host=host, entity_kind=kind, protocol="https", package=imp, file=sf.path, operation="sdk_import", handler=None); break
        for imp, tech in CS_STORE:
            if imp in l and not s.startswith("using ") and imp in ("AddStackExchangeRedisCache", "UseNpgsql", "UseSqlServer", "UseMySql", "UseSqlite"):
                facts.add("store_access", DET["c_sharp"], [_ev(sf, i)], technology=tech, operation="client_init", package=imp, file=sf.path)
        m = re.search(r"\.Map(Get|Post|Put|Patch|Delete)\(\s*\"([^\"]+)\"", l)
        if m:
            facts.add("entry_point", DET["c_sharp"], [_ev(sf, i)], protocol="http", method=m.group(1).upper(), path=m.group(2), file=sf.path, router="minimal-api", handler_span=None, route_controls=[], handler_ref=None)
        m = re.search(r"\[Http(Get|Post|Put|Patch|Delete)(?:\(\s*\"([^\"]*)\"\s*\))?\]", l)
        if m:
            path = (route_prefix.rstrip("/") + "/" + (m.group(2) or "").lstrip("/")).rstrip("/") or "/"
            ctrls = []
            for j in range(max(0, i - 4), i):
                if "[Authorize" in lines[j]:
                    ctrls.append(facts.add("control", DET["c_sharp"], [_ev(sf, j + 1)], control_kind="authn", name="[Authorize]", scope="route", file=sf.path))
            sym = None
            for j in range(i, min(i + 5, len(lines))):
                mm = re.search(r"\b(\w+)\s*\(", lines[j])
                if mm and not lines[j].strip().startswith("["):
                    sym = mm.group(1); break
            facts.add("entry_point", DET["c_sharp"], [_ev(sf, i)], protocol="http", method=m.group(1).upper(), path=path, file=sf.path, router="mvc", handler_span=None, route_controls=ctrls, handler_ref=sym, handler_module=sf.path, handler_symbol=sym)
        m = re.search(r"\.MapGrpcService<(\w+)>", l)
        if m:
            facts.add("entry_point", DET["c_sharp"], [_ev(sf, i)], protocol="grpc", method="grpc", path=_grpc_service_name(m.group(1)), file=sf.path, router="grpc", handler_span=None, route_controls=[], handler_ref=None)
        m = re.search(r"GrpcChannel\.ForAddress\(\s*([^)]+)\)", l)
        if m:
            arg = m.group(1).strip()
            host = arg.strip('"').split("://")[-1].split(":")[0] if arg.startswith('"') else None
            if not host:
                env = re.search(r"GetEnvironmentVariable\(\s*\"([A-Z0-9_]+)\"", text) or re.search(r"GetValue<string>\(\s*\"([A-Z0-9_]+)\"", text)
                host = ("env:" + env.group(1)) if env else "variable:" + arg[:30]
            facts.add("outbound_call", DET["c_sharp"], [_ev(sf, i)], sdk_service=None, host=host, entity_kind="system", protocol="grpc", package="grpc", file=sf.path, operation="grpc channel", handler=None)
        m = re.search(r"\b(ConnectionMultiplexer\.Connect|\w+\.StringGetAsync|\w+\.StringSetAsync|\w+\.HashGetAsync|\w+\.HashSetAsync|\w+\.KeyDeleteAsync|\w+\.GetAsync|\w+\.SetAsync|\w+\.RemoveAsync|\w+\.GetStringAsync|\w+\.SetStringAsync|\w+\.SaveChangesAsync|\w+\.ToListAsync|\w+\.FirstOrDefaultAsync|\w+\.AddAsync|\w+\.ExecuteAsync|\w+\.QueryAsync)\(", l)
        if m and any(imp in text for imp, _ in CS_STORE):
            op = m.group(1).split(".")[-1]
            operation = "write" if op in ("StringSetAsync", "HashSetAsync", "KeyDeleteAsync", "SetAsync", "SetStringAsync", "RemoveAsync", "SaveChangesAsync", "AddAsync", "ExecuteAsync") else ("read" if op != "Connect" else "client_init")
            tech = next((t for imp, t in CS_STORE if imp in text and t != "unknown"), next((t for imp, t in CS_STORE if imp in text), "unknown"))
            if operation == "client_init":
                facts.add("store_access", DET["c_sharp"], [_ev(sf, i)], technology=tech, operation="client_init", package="StackExchange.Redis", file=sf.path)
            else:
                facts.add("store_access", DET["c_sharp"], [_ev(sf, i)], technology=tech, operation=operation, logical_name=None, method=op, file=sf.path, handler=None, local=m.group(1).split(".")[0])
        if re.search(r"\b(HttpClient|GetAsync|PostAsync|GetStringAsync)\b", l) and re.search(r"\"https?://[^\"/]+", l):
            url = re.search(r"\"(https?)://([^\"/]+)", l)
            facts.add("outbound_call", DET["c_sharp"], [_ev(sf, i)], sdk_service=None, host=url.group(2), entity_kind="system", protocol=url.group(1), package="HttpClient", file=sf.path, operation="http", handler=None)
        for m in re.finditer(r"(?:GetEnvironmentVariable|GetValue<string>)\(\s*\"([A-Z0-9_]+)\"", l):
            if SECRET_ENV_RX.search(m.group(1)) and not m.group(1).endswith(("_URL", "_URI", "_ADDR")):
                facts.add("config_value", DET["c_sharp"], [_ev(sf, i)], name=m.group(1), data_class="secret", at_import=False, file=sf.path)
        if "ServerCertificateCustomValidationCallback" in l and "true" in l:
            facts.add("weakness", DET["c_sharp"], [_ev(sf, i)], weakness_kind="tls_verification_disabled", name="ServerCertificateCustomValidationCallback returns true", file=sf.path)
        if re.search(r"\.UseAuthentication\(\)|AddAuthentication\(|AddJwtBearer\(", l):
            facts.add("control", DET["c_sharp"], [_ev(sf, i)], control_kind="authn", name=re.search(r"(UseAuthentication|AddAuthentication|AddJwtBearer)", l).group(1), scope="app", path_prefix=None, file=sf.path, order=i)
        if re.search(r"\.UseCors\(|AddCors\(", l):
            facts.add("control", DET["c_sharp"], [_ev(sf, i)], control_kind="cors", name="UseCors", scope="app", path_prefix=None, file=sf.path, order=i)
            if "AllowAnyOrigin" in text:
                facts.add("weakness", DET["c_sharp"], [_ev(sf, i)], weakness_kind="permissive_cors", name="CORS AllowAnyOrigin", file=sf.path)
        if re.search(r"\.Run\(\)|\.Run\(\s*\"|UseUrls\(|UseKestrel", l) and ("WebApplication" in text or "IHost" in text or "Host.CreateDefaultBuilder" in text):
            facts.add("listener", DET["c_sharp"], [_ev(sf, i)], port=(re.search(r"\"https?://[^\"]+\"", l).group(0) if re.search(r"\"https?://[^\"]+\"", l) else "?")[:40], tls="https://" in l or "UseHttpsRedirection" in text, file=sf.path)
            facts.add("app_entry", DET["c_sharp"], [_ev(sf, i)], file=sf.path, middleware=[])
