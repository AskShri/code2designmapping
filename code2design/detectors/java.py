"""Java detector: Spring MVC/WebFlux controllers (class-level and method mappings, multi-path and
bare mappings), @ModelAttribute pre-handlers as call edges, method security annotations and the
Spring Security filter chain as controls, Spring Data repositories resolved to entity tables,
JdbcTemplate and EntityManager access, JPA entities as schemas, grpc-java, message listeners,
outbound HTTP, secrets and weaknesses, and datasource engines from application properties.
Coverage statement: annotation literals only; security path matchers are not evaluated (the filter
chain is reported as a conditional control)."""
import os, re
from ..model import classify_control, is_secret_name, evidence, text_evidence
from .common import sql_operation, sql_table, host_of_url, is_local, grpc_service_name, looks_like_secret_literal

DET = "java@0.5"
REPO_BASES = ("JpaRepository", "CrudRepository", "PagingAndSortingRepository", "Repository", "MongoRepository", "ReactiveCrudRepository", "ReactiveMongoRepository", "ListCrudRepository",
              "R2dbcRepository", "ElasticsearchRepository", "CassandraRepository", "JpaSpecificationExecutor", "KeyValueRepository")
MAPPING_RX = re.compile(r"@(Get|Post|Put|Patch|Delete|Request)Mapping\b(\s*\((?:[^()]|\([^()]*\))*\))?")
STORE_IMPORTS = [("org.springframework.data.redis", "redis"), ("redis.clients.jedis", "redis"), ("io.lettuce", "redis"), ("org.springframework.data.mongodb", "mongodb"), ("com.mongodb", "mongodb"),
                 ("org.springframework.kafka", "kafka"), ("org.apache.kafka", "kafka"), ("org.springframework.amqp", "rabbitmq"), ("com.rabbitmq", "rabbitmq"), ("com.amazonaws.services.s3", "s3"),
                 ("software.amazon.awssdk.services.s3", "s3"), ("software.amazon.awssdk.services.dynamodb", "dynamodb"), ("org.elasticsearch", "elasticsearch")]
SDK_IMPORTS = [("com.stripe", ("Stripe API", "api.stripe.com", "system")), ("com.twilio", ("Twilio API", "api.twilio.com", "system")), ("com.sendgrid", ("SendGrid API", "api.sendgrid.com", "system")),
               ("io.opentelemetry.exporter", ("OTLP collector", None, "system")), ("com.google.cloud.vertexai", ("Google Vertex AI", None, "llm_api")), ("com.theokanning.openai", ("OpenAI API", "api.openai.com", "llm_api")),
               ("dev.langchain4j", ("LLM API via langchain4j", None, "llm_api")), ("org.springframework.mail", ("SMTP mail relay", None, "system")), ("jakarta.mail", ("SMTP mail relay", None, "system"))]
JDBC_TECH = [("postgresql", "postgres"), ("mysql", "mysql"), ("mariadb", "mysql"), ("sqlserver", "mssql"), ("sqlite", "sqlite"), ("oracle", "sql"), ("h2", "sql"), ("hsqldb", "sql"), ("mongodb", "mongodb")]


def _ev(sf, s, e=None, symbol=None):
    return evidence(sf, s, e, DET, symbol)


def _paths(args):
    """Path literals of a mapping annotation's arguments: "/a", {"/a", "/b"}, value = "/a", path = {...}."""
    if not args:
        return [""]
    a = args.strip()[1:-1]
    m = re.search(r"(?:^|,)\s*(?:value|path)\s*=\s*(\{[^}]*\}|\"[^\"]*\")", a) or re.match(r"\s*(\{[^}]*\}|\"[^\"]*\")", a)
    if not m:
        return [""]
    return re.findall(r"\"([^\"]*)\"", m.group(1)) or [""]


class _Repo:
    def __init__(self, idx):
        self.idx = idx
        self.files = [sf for sf in idx.files.values() if sf.lang == "java" and not sf.is_test]
        C = idx.classes
        self.entities = {}     # entity class -> (table, file, line, end, tech kind)
        self.repos = {}        # repository type -> entity class
        for (f, cls), info in sorted(C.classes.items()):
            sf = idx.files.get(f)
            if sf is None or sf.lang != "java" or sf.is_test:
                continue
            pre = "\n".join(sf.lines[max(0, info["start"] - 8):info["start"] + 1])
            body_head = "\n".join(sf.lines[info["start"] - 1:info["start"] + 3])
            ann = pre + body_head
            if re.search(r"@(Entity|Document|Table|MappedSuperclass)\b", ann) and not re.search(r"@MappedSuperclass", ann):
                t = re.search(r"@Table\(\s*(?:name\s*=\s*)?\"(\w+)\"", ann) or re.search(r"@Document\(\s*(?:collection\s*=\s*)?\"(\w+)\"", ann) or re.search(r"@Entity\(\s*name\s*=\s*\"(\w+)\"", ann)
                self.entities[cls] = (t.group(1) if t else cls, f, info["start"], info["end"], "mongodb" if "@Document" in ann else "sql")
            g = C.base_generic(f, cls, REPO_BASES)
            if g:
                self.repos[cls] = g
        self.tech = self._engine()

    def _engine(self):
        """Engine from the default application properties, else any single profile, else 'sql'."""
        default, others = set(), set()
        for rel in self.idx.config_files:
            fn = os.path.basename(rel)
            if not fn.startswith("application"):
                continue
            try:
                text = open(os.path.join(self.idx.root, rel), encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            hits = {t for m in re.finditer(r"jdbc:(\w+):", text) for k, t in JDBC_TECH if m.group(1).startswith(k)} | ({"mongodb"} if "mongodb://" in text else set())
            (default if re.match(r"application\.(properties|ya?ml)$", fn) else others).update(hits)
        for pool in (default - {"sql"}, others - {"sql"}):
            if len(pool) == 1:
                return sorted(pool)[0]
        return "sql"

    def table(self, entity):
        return self.entities[entity][0] if entity in self.entities else entity


def run(idx, facts):
    repo = _Repo(idx)
    if not repo.files:
        return
    for cls, (table, f, start, end, kind) in sorted(repo.entities.items()):
        sf = idx.files[f]
        facts.add("store_access", DET, _ev(sf, start), file=f, technology="mongodb" if kind == "mongodb" else repo.tech, operation="model_definition", logical_name=table)
        fields = [{"name": m.group(2), "type": m.group(1)[:30]} for m in re.finditer(r"^\s*(?:private|protected|public)\s+(?:final\s+)?([\w<>\[\], ?.]+?)\s+(\w+)\s*(?:=[^;]*)?;", "\n".join(sf.lines[start - 1:end]), re.M)]
        if fields:
            facts.add("schema", DET, _ev(sf, start, end), file=f, name=table, fields=fields, schema_kind="model", class_name=cls)
    for rel in idx.config_files:   # plaintext datasource passwords
        fn = os.path.basename(rel)
        if fn.startswith("application") and fn.endswith(".properties"):
            try:
                lines = open(os.path.join(idx.root, rel), encoding="utf-8", errors="replace").read().splitlines()
            except OSError:
                continue
            for i, l in enumerate(lines, 1):
                m = re.match(r"\s*([\w.-]*(?:password|secret|api-key|apikey|token)[\w.-]*)\s*[=:]\s*(.+)$", l, re.I)
                if m:
                    val = m.group(2).strip()
                    dm = re.match(r"^\$\{[^:}]+:(.+)\}$", val)
                    lit = dm.group(1) if dm else (None if val.startswith("${") else val)
                    if lit and len(lit) >= 3 and not re.search(r"(changeme|example|your)", lit, re.I):
                        facts.add("weakness", DET, text_evidence(rel, lines, i, detector=DET), file=rel, weakness_kind="plaintext_credentials", name=f"{m.group(1)} has a literal {'default ' if dm else ''}value in {fn}")
    for sf in repo.files:
        _file(idx, sf, facts, repo)


def _file(idx, sf, facts, repo):
    text, lines = sf.text, sf.lines
    C = idx.classes
    for spec, line, _names in sf.imports:
        hit = next((t for imp, t in STORE_IMPORTS if spec.startswith(imp)), None)
        if hit:
            facts.add("store_access", DET, _ev(sf, line), file=sf.path, technology=hit, operation="client_init", package=spec)
        sdk = next((v for imp, v in SDK_IMPORTS if spec.startswith(imp)), None)
        if sdk:
            facts.add("outbound_call", DET, _ev(sf, line), file=sf.path, protocol="smtp" if "SMTP" in sdk[0] else "https", operation="sdk_import", sdk_service=sdk[0], host=sdk[1], entity_kind=sdk[2], package=spec)
    if "@SpringBootApplication" in text:
        facts.add("app", DET, _ev(sf, sf.line_of_offset(text.index("@SpringBootApplication"))), file=sf.path, framework="spring-boot")
    # ---- Spring Security filter chain: a service-wide, path-conditional control
    if "org.springframework.security" in text and re.search(r"(authorizeHttpRequests|authorizeRequests|authorizeExchange)", text):
        ln = sf.line_of_offset(re.search(r"(authorizeHttpRequests|authorizeRequests|authorizeExchange)", text).start())
        if re.search(r"\.authenticated\(\)|hasRole|hasAuthority|hasAnyRole", text):
            facts.add("control", DET, _ev(sf, ln), file=sf.path, control_kind="authn", name="Spring Security filter chain", scope="service", conditional=bool(re.search(r"permitAll\(\)", text)))
    for m in re.finditer(r"csrf\(\)\s*\.disable\(\)|\.csrf\(\s*\w+\s*->\s*\w+\.disable\(\)\s*\)|csrf\(AbstractHttpConfigurer::disable\)", text):
        facts.add("weakness", DET, _ev(sf, sf.line_of_offset(m.start())), file=sf.path, weakness_kind="csrf_disabled", name="Spring Security CSRF protection disabled")
    # ---- controllers: annotation blocks before a class or a method
    classes = sorted((info["start"], info["end"], cls) for (f, cls), info in C.classes.items() if f == sf.path)
    class_prefix, class_controls, model_attrs, handlers = {}, {}, {}, []
    i = 0
    while i < len(lines):
        if not lines[i].lstrip().startswith("@"):
            i += 1; continue
        top = i
        block = []
        depth = 0
        while i < len(lines) and (lines[i].lstrip().startswith("@") or depth > 0 or not lines[i].strip()):
            block.append(lines[i]); depth += lines[i].count("(") - lines[i].count(")"); i += 1
        if i >= len(lines):
            break
        btxt = "\n".join(block)
        decl = lines[i]
        j = i
        while j + 1 < len(lines) and "{" not in decl and ";" not in decl and j - i < 6:
            j += 1; decl += " " + lines[j].strip()
        line_no = top + 1
        cm = re.search(r"\b(?:class|interface|record)\s+(\w+)", decl)
        if cm and not re.search(r"\w+\s*\(", decl.split(cm.group(0))[0]):
            cls = cm.group(1)
            mm = MAPPING_RX.search(btxt)
            if mm and mm.group(1) == "Request":
                class_prefix[cls] = _paths(mm.group(2))[0]
            if "@FeignClient" in btxt:
                class_prefix.pop(cls, None)
            elif re.search(r"@(Rest)?Controller\b", btxt) or mm:
                class_prefix.setdefault(cls, "")
            for am in re.finditer(r"@(PreAuthorize|Secured|RolesAllowed|CrossOrigin)\b", btxt):
                kind = classify_control(am.group(1))
                if kind:
                    class_controls.setdefault(cls, []).append((kind, "@" + am.group(1), line_no))
            i += 1
            continue
        sm = re.search(r"\b(\w+)\s*\(", re.sub(r"@\w+(\([^()]*\))?", "", decl))
        cls = next((c for s, e, c in sorted(classes, key=lambda x: x[1] - x[0]) if s <= i + 1 <= e), None)
        if sm and cls:
            method = sm.group(1)
            params = decl[decl.index("("):] if "(" in decl else ""
            pvars = re.findall(r"@PathVariable\(\s*(?:name\s*=\s*|value\s*=\s*)?\"(\w+)\"", params) + re.findall(r"@PathVariable\s+(?:final\s+)?[\w<>.]+\s+(\w+)", params)
            if "@ModelAttribute" in btxt:
                required = [v for v in pvars if not re.search(r"@PathVariable\([^)]*\"" + v + r"\"[^)]*required\s*=\s*false", params)]
                model_attrs.setdefault(cls, []).append((method, pvars, required, i + 1))
            for mm in MAPPING_RX.finditer(btxt):
                verb = mm.group(1).upper()
                if verb == "REQUEST":
                    rm = re.findall(r"RequestMethod\.(\w+)", mm.group(2) or "")
                    verbs = rm or ["ANY"]
                else:
                    verbs = [verb]
                ctl = [(classify_control(a.group(1)), "@" + a.group(1)) for a in re.finditer(r"@(PreAuthorize|Secured|RolesAllowed|CrossOrigin|RateLimiter)\b", btxt)]
                if "@Valid" in params or "@Validated" in params:
                    ctl.append(("input_validation", "@Valid"))
                payload = re.findall(r"@(?:RequestBody|Valid|ModelAttribute)\s+(?:final\s+)?([A-Z]\w*)", params)
                handlers.append((cls, method, verbs, _paths(mm.group(2)), [c for c in ctl if c[0]], line_no, i + 1, payload))
            lm = re.search(r"@(KafkaListener|RabbitListener|JmsListener|SqsListener)\(([^)]*)\)", btxt)
            if lm:
                topic = re.search(r"\"([^\"]+)\"", lm.group(2))
                facts.add("entry_point", DET, _ev(sf, line_no, i + 1), file=sf.path, protocol={"Kafka": "kafka", "Rabbit": "amqp", "Jms": "amqp", "Sqs": "sqs"}[lm.group(1).replace("Listener", "")], method="CONSUME",
                          path=topic.group(1) if topic else method, router="<listeners>", handler_file=sf.path, handler_symbol=f"{cls}.{method}")
        i += 1
    for cls in sorted(class_prefix):
        info = C.classes.get((sf.path, cls))
        facts.add("router", DET, _ev(sf, info["start"] if info else 1), file=sf.path, local=cls, own_prefix=class_prefix[cls], root=True)
        for kind, name, ln in class_controls.get(cls, []):
            facts.add("control", DET, _ev(sf, ln), file=sf.path, control_kind=kind, name=name, scope="router", router=cls, ordered=False)
    for cls, method, verbs, paths, ctl, line_no, sig_line, payload in handlers:
        if cls not in class_prefix:
            facts.add("router", DET, _ev(sf, line_no), file=sf.path, local=cls, own_prefix="", root=True); class_prefix[cls] = ""
        cids = [facts.add("control", DET, _ev(sf, line_no), file=sf.path, control_kind=k, name=nm, scope="route") for k, nm in ctl]
        for path in paths:
            full = class_prefix[cls].rstrip("/") + "/" + path.lstrip("/")
            for verb in verbs:
                facts.add("entry_point", DET, _ev(sf, line_no, sig_line), file=sf.path, protocol="http", method=verb, path=path, router=cls, route_controls=cids,
                          handler_file=sf.path, handler_symbol=f"{cls}.{method}", payload_types=payload)
            # @ModelAttribute methods run before every handler of the controller whose path binds their variables
            for ma, pvars, required, ma_line in model_attrs.get(cls, []):
                if not pvars or all(("{" + v + "}") in full or re.search(r"\{" + v + r"[:}]", full) for v in required) and any(("{" + v) in full for v in pvars):
                    facts.add("call_edge", DET, _ev(sf, sig_line), file=sf.path, line=sig_line, target_file=sf.path, target_symbol=f"{cls}.{ma}")
    # ---- gRPC, listeners
    for m in re.finditer(r"\.addService\(\s*(?:new\s+)?(\w+)", text):
        impl = sorted((f, c) for (f, c) in getattr(idx, "classes", None).classes if c == m.group(1) and idx.files[f].lang == "java") if getattr(idx, "classes", None) else []
        scope = dict(handler_scope="class", handler_file=impl[0][0], handler_class=impl[0][1]) if impl else dict(handler_scope="package")
        facts.add("entry_point", DET, _ev(sf, sf.line_of_offset(m.start())), file=sf.path, protocol="grpc", method="grpc",
                  path=grpc_service_name(m.group(1)) if "ealth" not in m.group(1) else "Health", router="<grpc>", **scope)
    m = re.search(r"ServerBuilder\s*\.forPort\(\s*(\w+)", text.replace("\n", " "))
    if m:
        facts.add("listener", DET, _ev(sf, sf.line_of_offset(text.index("forPort"))), file=sf.path, port=m.group(1)[:40], tls="useTransportSecurity" in text)
        facts.add("app", DET, _ev(sf, sf.line_of_offset(text.index("forPort"))), file=sf.path, framework="grpc-java")
    # ---- line-level: data access through typed fields, outbound, secrets
    for i, l in enumerate(lines, 1):
        s = l.strip()
        if s.startswith(("//", "*", "import ", "@")):
            continue
        cls = C.class_at(sf.path, i)
        for m in re.finditer(r"(?:this\.)?\b(\w+)\s*\.\s*(\w+)\s*\(", l):
            recv, meth = m.group(1), m.group(2)
            ft = C.field_type(sf.path, cls, recv) if cls else None
            if not ft:
                continue
            ftype = ft[0]
            if ftype in repo.repos:
                ent = repo.repos[ftype]
                op = "read" if re.match(r"(find|get|read|query|count|exists|search|stream|load|fetch)", meth) else "write"
                tech = "mongodb" if repo.entities.get(ent, (0, 0, 0, 0, "sql"))[4] == "mongodb" else repo.tech
                facts.add("store_access", DET, _ev(sf, i), file=sf.path, technology=tech, operation=op, logical_name=repo.table(ent), method=meth)
            elif ftype in ("JdbcTemplate", "NamedParameterJdbcTemplate", "JdbcClient"):
                sm = re.search(r"\"([^\"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^\"]*)\"", l + " " + (lines[i] if i < len(lines) else ""), re.I)
                if sm:
                    facts.add("store_access", DET, _ev(sf, i), file=sf.path, technology=repo.tech, operation=sql_operation(sm.group(1)), logical_name=sql_table(sm.group(1)), method=meth)
            elif ftype in ("EntityManager", "Session") and meth in ("persist", "merge", "remove", "find", "createQuery", "createNativeQuery", "getReference", "save", "delete", "get"):
                em = re.search(r"\b([A-Z]\w*)\.class", l) or re.search(r"(?:FROM|from)\s+([A-Z]\w*)", l)
                facts.add("store_access", DET, _ev(sf, i), file=sf.path, technology=repo.tech, operation="write" if meth in ("persist", "merge", "remove", "save", "delete") else "read",
                          logical_name=repo.table(em.group(1)) if em else None, method=meth)
            elif ftype in ("RedisTemplate", "StringRedisTemplate", "Jedis", "ReactiveRedisTemplate"):
                facts.add("store_access", DET, _ev(sf, i), file=sf.path, technology="redis", operation="read" if re.match(r"(get|has|keys|range|members|opsFor)", meth) and "set" not in l.split(meth)[-1][:40] else "write", logical_name=None, method=meth)
            elif ftype in ("MongoTemplate", "ReactiveMongoTemplate"):
                em = re.search(r"\b([A-Z]\w*)\.class", l)
                facts.add("store_access", DET, _ev(sf, i), file=sf.path, technology="mongodb", operation="read" if re.match(r"(find|count|exists|aggregate|query)", meth) else "write", logical_name=repo.table(em.group(1)) if em else None, method=meth)
            elif ftype in ("KafkaTemplate", "RabbitTemplate", "AmqpTemplate") and re.match(r"(send|convertAndSend|publish)", meth):
                tm = re.search(r"\(\s*\"([^\"]+)\"", l[m.end() - 1:])
                facts.add("store_access", DET, _ev(sf, i), file=sf.path, technology="kafka" if ftype == "KafkaTemplate" else "rabbitmq", operation="write", logical_name=tm.group(1) if tm else None, method=meth)
            elif ftype in ("RestTemplate", "WebClient", "RestClient", "HttpClient") and re.match(r"(get|post|put|delete|exchange|patch|send|uri|retrieve)", meth, re.I):
                um = re.search(r"\"(https?://[^\"]+)\"", l)
                host, scheme = host_of_url(um.group(1)) if um else (None, None)
                facts.add("outbound_call", DET, _ev(sf, i), file=sf.path, protocol=scheme or "unknown", operation=meth, sdk_service=None, host=host or "variable:" + ftype, entity_kind="system", package=ftype)
                if scheme == "http" and host and not is_local(host):
                    facts.add("weakness", DET, _ev(sf, i), file=sf.path, weakness_kind="unencrypted_transport", name=f"plain http:// to {host}")
        m = re.search(r"ManagedChannelBuilder\.(?:forAddress\(\s*([^,]+),|forTarget\(\s*([^)]+)\))", l)
        if m:
            arg = (m.group(1) or m.group(2) or "").strip()
            host = arg.strip('"').split(":")[0] if arg.startswith('"') else None
            if host is None:
                env = re.search(r"System\.getenv\(\s*\"([A-Z0-9_]+(?:_ADDR|_HOST|_URL|_ENDPOINT|_TARGET))\"", text)
                host = ("env:" + env.group(1)) if env else "variable:" + arg[:30]
            if not is_local(host):
                facts.add("outbound_call", DET, _ev(sf, i), file=sf.path, protocol="grpc", operation="grpc channel", sdk_service=None, host=host, entity_kind="system", package="grpc", insecure=".usePlaintext()" in text)
        if ".usePlaintext()" in l:
            facts.add("weakness", DET, _ev(sf, i), file=sf.path, weakness_kind="unencrypted_transport", name="gRPC channel usePlaintext()")
        for m in re.finditer(r"System\.getenv\(\s*\"([A-Z0-9_]+)\"", l):
            if is_secret_name(m.group(1)):
                facts.add("config_value", DET, _ev(sf, i), file=sf.path, name=m.group(1), data_class="secret")
        for m in re.finditer(r"@Value\(\s*\"\$\{([\w.-]+)", l):
            if is_secret_name(m.group(1).replace(".", "_").replace("-", "_")):
                facts.add("config_value", DET, _ev(sf, i), file=sf.path, name=m.group(1), data_class="secret")
        m = re.search(r"\b(?:static\s+)?(?:final\s+)?String\s+(\w*(?:PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)\w*)\s*=\s*\"([^\"]+)\"", l, re.I)
        if m and looks_like_secret_literal(m.group(2)):
            facts.add("weakness", DET, _ev(sf, i), file=sf.path, weakness_kind="plaintext_credentials", name=f"hard-coded {m.group(1)}")
        m = re.search(r"@FeignClient\(([^)]*)\)", l)
        if m:
            um = re.search(r"url\s*=\s*\"(https?://[^\"]+)\"", m.group(1)); nm = re.search(r"(?:name|value)\s*=\s*\"([^\"]+)\"", m.group(1)) or re.search(r"^\s*\"([^\"]+)\"", m.group(1))
            host, scheme = host_of_url(um.group(1)) if um else (None, None)
            facts.add("outbound_call", DET, _ev(sf, i), file=sf.path, protocol=scheme or "http", operation="feign client", sdk_service=None if host else (f"{nm.group(1)} service" if nm else "Feign client"), host=host, entity_kind="system", package="feign")
