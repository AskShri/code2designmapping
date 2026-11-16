"""C# detector: ASP.NET Core controllers ([Route] tokens, [HttpX], class and method [Authorize],
[AllowAnonymous]), minimal APIs and route groups, Razor Pages, gRPC services, repository and
DbSet access resolved to entity tables, StackExchange.Redis and IDistributedCache, gRPC channels,
HttpClient, configuration secrets and weaknesses.
Coverage statement: attribute and string literals only; conventional (table-based) MVC routes are
not expanded."""
import re
from ..model import is_secret_name, evidence
from .common import manifest_engine, host_of_url, is_local, grpc_service_name, looks_like_secret_literal

DET = "csharp@0.5"
REPO_TYPES = ("IRepository", "IReadRepository", "IAsyncRepository", "IGenericRepository", "Repository", "EfRepository", "DbSet", "IMongoCollection", "IQueryable")
EF_TECH = [("UseSqlServer", "mssql"), ("UseNpgsql", "postgres"), ("UseMySql", "mysql"), ("UseSqlite", "sqlite"), ("UseCosmos", "unknown"), ("UseOracle", "sql")]
SDK_USINGS = [("Stripe", ("Stripe API", "api.stripe.com", "system")), ("Twilio", ("Twilio API", "api.twilio.com", "system")), ("SendGrid", ("SendGrid API", "api.sendgrid.com", "system")),
              ("OpenTelemetry.Exporter", ("OTLP collector", None, "system")), ("Azure.AI.OpenAI", ("Azure OpenAI", None, "llm_api")), ("OpenAI", ("OpenAI API", "api.openai.com", "llm_api")),
              ("Anthropic", ("Anthropic API", "api.anthropic.com", "llm_api")), ("Google.Cloud.AIPlatform", ("Google Vertex AI", None, "llm_api")), ("System.Net.Mail", ("SMTP mail relay", None, "system")), ("MailKit", ("SMTP mail relay", None, "system"))]
STORE_USINGS = [("StackExchange.Redis", "redis"), ("Microsoft.Extensions.Caching.StackExchangeRedis", "redis"), ("MongoDB.Driver", "mongodb"), ("Confluent.Kafka", "kafka"), ("RabbitMQ.Client", "rabbitmq"),
                ("Amazon.S3", "s3"), ("Amazon.DynamoDBv2", "dynamodb"), ("Azure.Storage.Blobs", "unknown"), ("Google.Cloud.Spanner", "unknown")]
WRITE_METHODS = re.compile(r"^(Add|AddRange|Update|UpdateRange|Delete|DeleteRange|Remove|RemoveRange|Save|SaveChanges|Insert|Upsert|Replace|Attach|Execute)", re.I)
HTTP_ATTR_RX = re.compile(r"\[Http(Get|Post|Put|Patch|Delete|Head|Options)(?:\(\s*(?:\"([^\"]*)\")?[^)]*\))?\]")
MAP_RX = re.compile(r"\b(\w+)\s*\.\s*Map(Get|Post|Put|Patch|Delete)\(\s*\"([^\"]*)\"")


def _ev(sf, s, e=None, symbol=None):
    return evidence(sf, s, e, DET, symbol)


class _Repo:
    def __init__(self, idx):
        self.idx = idx
        self.files = [sf for sf in idx.files.values() if sf.lang == "c_sharp" and not sf.is_test]
        text = "\n".join(sf.text for sf in self.files)
        techs = sorted({t for k, t in EF_TECH if re.search(r"\b" + k + r"\(", text)} - {"unknown", "sql"})
        self.tech = techs[0] if len(techs) == 1 else ("sql" if techs else (manifest_engine(idx) or "sql"))
        self.entities = {}   # entity type -> (file, line) from DbSet<T> declarations
        for sf in self.files:
            for m in re.finditer(r"\bDbSet<\s*(\w+)\s*>\s+(\w+)", sf.text):
                self.entities.setdefault(m.group(1), (sf.path, sf.line_of_offset(m.start()), m.group(2)))
        self.razor = "MapRazorPages" in text


def run(idx, facts):
    repo = _Repo(idx)
    if not repo.files:
        return
    for ent, (f, line, setname) in sorted(repo.entities.items()):
        facts.add("store_access", DET, _ev(idx.files[f], line), file=f, technology=repo.tech, operation="model_definition", logical_name=ent)
        ef = idx.type_file(idx.files[f], ent)
        info = idx.classes.classes.get((ef, ent)) if ef else None
        if info:
            esf = idx.files[ef]
            fields = [{"name": m.group(2), "type": m.group(1)[:30]} for m in re.finditer(r"^\s*public\s+(?:virtual\s+|required\s+)?([\w<>\[\]?., ]+?)\s+(\w+)\s*\{\s*get", "\n".join(esf.lines[info["start"] - 1:info["end"]]), re.M)]
            if fields:
                facts.add("schema", DET, _ev(esf, info["start"], info["end"]), file=ef, name=ent, fields=fields, schema_kind="model", class_name=ent)
    for sf in repo.files:
        _file(idx, sf, facts, repo)


def _file(idx, sf, facts, repo):
    text, lines = sf.text, sf.lines
    C = idx.classes
    for spec, line, _n in sf.imports:
        hit = next((t for u, t in STORE_USINGS if spec == u or spec.startswith(u + ".")), None)
        if hit:
            facts.add("store_access", DET, _ev(sf, line), file=sf.path, technology=hit, operation="client_init", package=spec)
        sdk = next((v for u, v in SDK_USINGS if spec == u or spec.startswith(u + ".")), None)
        if sdk:
            facts.add("outbound_call", DET, _ev(sf, line), file=sf.path, protocol="smtp" if "SMTP" in sdk[0] else "https", operation="sdk_import", sdk_service=sdk[0], host=sdk[1], entity_kind=sdk[2], package=spec)
    is_program = bool(re.search(r"WebApplication\.Create(Builder)?\(|Host\.CreateDefaultBuilder\(|\.UseStartup<|IApplicationBuilder\s+\w+", text))
    if is_program:
        ln = sf.line_of_offset(re.search(r"WebApplication\.Create(Builder)?\(|Host\.CreateDefaultBuilder\(|\.UseStartup<|IApplicationBuilder\s+\w+", text).start())
        facts.add("app", DET, _ev(sf, ln), file=sf.path, framework="aspnetcore")
        facts.add("listener", DET, _ev(sf, ln), file=sf.path, port="?", tls="UseHttpsRedirection" in text or "UseHsts" in text)
        if re.search(r"FallbackPolicy\s*=|RequireAuthenticatedUser\(\)", text):
            m = re.search(r"FallbackPolicy\s*=|RequireAuthenticatedUser\(\)", text)
            facts.add("control", DET, _ev(sf, sf.line_of_offset(m.start())), file=sf.path, control_kind="authn", name="authorization fallback policy", scope="service")
        if "AllowAnyOrigin" in text:
            facts.add("weakness", DET, _ev(sf, sf.line_of_offset(text.index("AllowAnyOrigin"))), file=sf.path, weakness_kind="permissive_cors", name="CORS AllowAnyOrigin")
    if re.search(r"ServerCertificateCustomValidationCallback\s*=\s*(\([^)]*\)\s*=>\s*true|HttpClientHandler\.DangerousAcceptAnyServerCertificateValidator)", text):
        m = re.search(r"ServerCertificateCustomValidationCallback", text)
        facts.add("weakness", DET, _ev(sf, sf.line_of_offset(m.start())), file=sf.path, weakness_kind="tls_verification_disabled", name="server certificate validation callback accepts any certificate")
    # ---- MVC / API controllers
    classes = sorted(((info["start"], info["end"], cls, info) for (f, cls), info in C.classes.items() if f == sf.path), key=lambda x: x[0])
    for start, end, cls, info in classes:
        decl = next((j for j in range(start, min(end, start + 40) + 1) if re.search(r"\bclass\s+" + re.escape(cls) + r"\b", lines[j - 1])), start)
        pre = "\n".join(lines[max(0, start - 8):decl])     # attributes are part of the class node in the C# grammar
        is_controller = cls.endswith("Controller") or "[ApiController]" in pre or any(b in ("Controller", "ControllerBase") for b, _ in info["bases"])
        is_page = repo.razor and any(b == "PageModel" for b, _ in info["bases"])
        is_grpc = any(re.search(r"\.\w+Base$|Base$", b) for b, _ in info["bases"]) and "Grpc" in text and not is_controller
        if is_controller:
            token = re.sub(r"Controller$", "", cls)
            rm = re.findall(r"\[Route\(\s*\"([^\"]*)\"", pre)
            own = rm[-1].replace("[controller]", token) if rm else ""
            facts.add("router", DET, _ev(sf, start), file=sf.path, local=cls, own_prefix=own.replace("/[action]", "").replace("[action]", ""), root=True)
            action_in_prefix = "[action]" in own
            if re.search(r"\[Authorize\b", pre):
                facts.add("control", DET, _ev(sf, start), file=sf.path, control_kind="authn", name="[Authorize]", scope="router", router=cls, ordered=False)
            i = start
            while i <= end:
                l = lines[i - 1]
                if not HTTP_ATTR_RX.search(l):
                    i += 1; continue
                top = i
                while top - 1 > start and lines[top - 2].strip().startswith("["):
                    top -= 1
                j = i
                while j <= end and lines[j - 1].strip().startswith("["):
                    j += 1
                block = "\n".join(lines[top - 1:j - 1])
                sig = re.search(r"\b(\w+)\s*\(", lines[j - 1]) if j <= end else None
                method_name = sig.group(1) if sig else "?"
                mroute = re.search(r"\[Route\(\s*\"([^\"]*)\"", block)
                ctl = []
                if re.search(r"\[Authorize\b", block):
                    ctl.append(facts.add("control", DET, _ev(sf, i), file=sf.path, control_kind="authn", name="[Authorize]", scope="route"))
                if re.search(r"\[ValidateAntiForgeryToken\]", block):
                    ctl.append(facts.add("control", DET, _ev(sf, i), file=sf.path, control_kind="csrf", name="[ValidateAntiForgeryToken]", scope="route"))
                for hm in HTTP_ATTR_RX.finditer(block):
                    sub = hm.group(2) if hm.group(2) is not None else (mroute.group(1) if mroute else "")
                    if sub.startswith("/") or sub.startswith("~/"):
                        path = sub.lstrip("~"); absolute = True
                    else:
                        path = (method_name + ("/" + sub if sub else "")) if action_in_prefix else sub
                        absolute = False
                    path = path.replace("[action]", method_name).replace("[controller]", token)
                    facts.add("entry_point", DET, _ev(sf, top, j), file=sf.path, protocol="http", method=hm.group(1).upper(), path=path, router=cls if not absolute else f"{cls}:abs", route_controls=ctl,
                              handler_file=sf.path, handler_symbol=f"{cls}.{method_name}", anonymous="[AllowAnonymous]" in block)
                    if absolute:
                        facts.add("router", DET, _ev(sf, top), file=sf.path, local=f"{cls}:abs", own_prefix="", root=True)
                i = j + 1
        elif is_page:
            m = re.search(r"(?:^|/)Pages/(.+)\.cshtml\.cs$", sf.path)
            if m:
                route = "/" + re.sub(r"(^|/)Index$", "", m.group(1))
                facts.add("router", DET, _ev(sf, start), file=sf.path, local=cls, own_prefix="", root=True)
                if re.search(r"\[Authorize\b", pre):
                    facts.add("control", DET, _ev(sf, start), file=sf.path, control_kind="authn", name="[Authorize]", scope="router", router=cls, ordered=False)
                for hm in re.finditer(r"\bpublic\s+(?:async\s+)?[\w<>\[\]?.]+\s+On(Get|Post|Put|Delete)(\w*?)(?:Async)?\s*\(", "\n".join(lines[start - 1:end])):
                    ln = start + "\n".join(lines[start - 1:end])[:hm.start()].count("\n")
                    name = "On" + hm.group(1) + hm.group(2)
                    key = next((k[1] for k in sorted(idx_functions(idx, sf.path)) if k[1].split("#")[0] in (f"{cls}.{name}", f"{cls}.{name}Async")), f"{cls}.{name}")
                    facts.add("entry_point", DET, _ev(sf, ln), file=sf.path, protocol="http", method=hm.group(1).upper(), path=route or "/", router=cls, route_controls=[], handler_file=sf.path, handler_symbol=key)
        elif is_grpc and re.search(r"MapGrpcService<\s*" + re.escape(cls) + r"\s*>", "\n".join(f.text for f in repo.files)):
            pass
    # ---- minimal APIs, route groups, gRPC service registration
    groups = set()
    for i, l in enumerate(lines, 1):
        s = l.strip()
        if s.startswith("//"):
            continue
        m = re.search(r"\b(?:var\s+)?(\w+)\s*=\s*(\w+)\.MapGroup\(\s*\"([^\"]*)\"\s*\)", l)
        if m:
            groups.add(m.group(1))
            facts.add("router", DET, _ev(sf, i), file=sf.path, local=m.group(1), own_prefix="", root=False)
            facts.add("router_mount", DET, _ev(sf, i), file=sf.path, parent=m.group(2), prefix=m.group(3), child_file=sf.path, child_local=m.group(1))
            if ".RequireAuthorization(" in l:
                facts.add("control", DET, _ev(sf, i), file=sf.path, control_kind="authn", name="RequireAuthorization", scope="router", router=m.group(1), ordered=False)
        m = MAP_RX.search(l)
        if m:
            recv = m.group(1)
            if recv not in groups:
                key = f"minimal:{recv}"
                if key not in groups:
                    groups.add(key)
                    facts.add("router", DET, _ev(sf, i), file=sf.path, local=recv, own_prefix="", root=True)
            # the statement runs to the terminating semicolon at depth 0
            stmt = l; j = i; depth = l.count("(") - l.count(")")
            while (depth > 0 or not stmt.rstrip().endswith(";")) and j < len(lines) and j - i < 80:
                j += 1; stmt += "\n" + lines[j - 1]; depth += lines[j - 1].count("(") - lines[j - 1].count(")")
            ctl = []
            if re.search(r"\[Authorize\b|\.RequireAuthorization\(", stmt):
                ctl.append(facts.add("control", DET, _ev(sf, i), file=sf.path, control_kind="authn", name="[Authorize]" if "[Authorize" in stmt else "RequireAuthorization", scope="route"))
            facts.add("entry_point", DET, _ev(sf, i, j), file=sf.path, protocol="http", method=m.group(2).upper(), path=m.group(3), router=recv, route_controls=ctl, handler_span=(i, j), anonymous=".AllowAnonymous(" in stmt)
        m = re.search(r"\.MapGrpcService<\s*([\w.]+)\s*>", l)
        if m:
            svc = m.group(1).split(".")[-1]
            tf = idx.type_file(sf, svc)
            facts.add("entry_point", DET, _ev(sf, i), file=sf.path, protocol="grpc", method="grpc", path="Health" if "ealth" in svc else grpc_service_name(svc), router="<grpc>", handler_scope="class" if tf else "package", handler_file=tf, handler_class=svc)
        # ---- data access through typed fields
        cls = C.class_at(sf.path, i)
        for cm in re.finditer(r"(?<![\w.])(_?\w+)\s*\.\s*(\w+)\s*(?:<[^>]*>)?\s*\(", l):
            recv, meth = cm.group(1), cm.group(2)
            ft = C.field_type(sf.path, cls, recv) if cls else None
            if not ft:
                continue
            ftype, generic = ft
            if ftype in REPO_TYPES and generic:
                facts.add("store_access", DET, _ev(sf, i), file=sf.path, technology="mongodb" if ftype == "IMongoCollection" else repo.tech, operation="write" if WRITE_METHODS.match(meth) else "read", logical_name=generic, method=meth)
            elif ftype in ("IDistributedCache", "IDatabase", "IConnectionMultiplexer", "IMemoryCache") and re.match(r"(Get|Set|Remove|String|Hash|Key|List|Refresh)", meth):
                facts.add("store_access", DET, _ev(sf, i), file=sf.path, technology="redis" if ftype != "IMemoryCache" else "memcached", operation="write" if re.match(r"(Set|Remove|StringSet|HashSet|KeyDelete|ListPush)", meth) else "read", logical_name=None, method=meth) if ftype != "IMemoryCache" else None
            elif ftype in ("HttpClient", "IHttpClientFactory") and re.match(r"(Get|Post|Put|Delete|Send|Patch)", meth):
                um = re.search(r"\"(https?://[^\"]+)\"", l)
                host, scheme = host_of_url(um.group(1)) if um else (None, None)
                facts.add("outbound_call", DET, _ev(sf, i), file=sf.path, protocol=scheme or "unknown", operation=meth, sdk_service=None, host=host or "variable:HttpClient", entity_kind="system", package="HttpClient")
                if scheme == "http" and host and not is_local(host):
                    facts.add("weakness", DET, _ev(sf, i), file=sf.path, weakness_kind="unencrypted_transport", name=f"plain http:// to {host}")
        # DbContext sets: _context.Orders.Add(...), db.Set<Order>()
        for cm in re.finditer(r"(?<![\w.])(_?\w+)\s*\.\s*(\w+)\s*\.\s*(\w+)\s*\(", l):
            ft = C.field_type(sf.path, cls, cm.group(1)) if cls else None
            ent = next((e for e, (_f, _l, setname) in repo.entities.items() if setname == cm.group(2)), None)
            if ft and ent and (ft[0].endswith("Context") or ft[0] == "DbContext"):
                facts.add("store_access", DET, _ev(sf, i), file=sf.path, technology=repo.tech, operation="write" if WRITE_METHODS.match(cm.group(3)) else "read", logical_name=ent, method=cm.group(3))
        m = re.search(r"GrpcChannel\.ForAddress\(\s*([^)]+)\)", l)
        if m:
            arg = m.group(1).strip()
            host = arg.strip('"').split("://")[-1].split(":")[0] if arg.startswith('"') else None
            if host is None:
                env = re.search(r"(?:GetEnvironmentVariable|GetValue<string>)\(\s*\"([A-Z0-9_]+(?:_ADDR|_HOST|_URL|_ENDPOINT))\"", text)
                host = ("env:" + env.group(1)) if env else "variable:" + arg[:30]
            if not is_local(host):
                facts.add("outbound_call", DET, _ev(sf, i), file=sf.path, protocol="grpc", operation="grpc channel", sdk_service=None, host=host, entity_kind="system", package="grpc")
        for cm in re.finditer(r"(?:GetEnvironmentVariable|GetValue<string>|GetConnectionString)\(\s*\"([\w:]+)\"|\bConfiguration\[\s*\"([\w:]+)\"\s*\]", l):
            name = cm.group(1) or cm.group(2)
            if is_secret_name(name.replace(":", "_")) or "GetConnectionString" in cm.group(0):
                facts.add("config_value", DET, _ev(sf, i), file=sf.path, name=name, data_class="secret")
        m = re.search(r"\b(?:const|static\s+readonly)\s+string\s+(\w*(?:PASSWORD|SECRET|API_?KEY|TOKEN|PRIVATE_?KEY)\w*)\s*=\s*\"([^\"]+)\"", l, re.I)
        if m and looks_like_secret_literal(m.group(2)):
            facts.add("weakness", DET, _ev(sf, i), file=sf.path, weakness_kind="plaintext_credentials", name=f"hard-coded {m.group(1)}")
        m = re.search(r"(ConnectionMultiplexer\.Connect|AddStackExchangeRedisCache)\(", l)
        if m:
            facts.add("store_access", DET, _ev(sf, i), file=sf.path, technology="redis", operation="client_init", package="StackExchange.Redis")


def idx_functions(idx, file):
    """Function keys of a file once the call graph exists; before that, an empty list (names fall back to the literal)."""
    cg = getattr(idx, "callgraph", None)
    return [k for k in cg.functions if k[0] == file] if cg else []
