"""TypeScript class/decorator frameworks: NestJS controllers, guards, middleware consumers and
global prefix; TypeORM entities and repositories; @nestjs/mongoose models; Prisma services.
Coverage statement: decorators with literal paths; guards and middleware are classified by name."""
import re
from ..model import classify_control, evidence
from ..index import walk, JS_LANGS
from .common import host_of_url, is_local
from .js import READ_OPS, WRITE_OPS

DET = "nest@0.5"
ROUTE_DECO_RX = re.compile(r"@(Get|Post|Put|Patch|Delete|All|Head|Options)\(\s*(?:\[?\s*['\"`]([^'\"`]*)['\"`][^)]*)?\)")
METHOD_SIG_RX = re.compile(r"^\s*(?:public\s+|private\s+|protected\s+|static\s+|async\s+)*(\w+)\s*(?:<[^>]*>)?\s*\(")
ORM_READ = READ_OPS | {"findOneBy", "findBy", "findAndCount", "findOneOrFail", "createQueryBuilder", "exist", "existsBy", "countBy", "findByIds", "findOneById", "getMany", "getOne", "populate", "lean"}
ORM_WRITE = (WRITE_OPS | {"softDelete", "softRemove", "restore", "increment", "decrement", "clear", "persist", "persistAndFlush", "flush"}) - {"send", "publish", "run"}
SQL_TYPE_RX = re.compile(r"\btype\s*:\s*['\"](postgres|mysql|mariadb|sqlite|better-sqlite3|mssql|mongodb|cockroachdb)['\"]")
TYPE_TECH = {"postgres": "postgres", "cockroachdb": "postgres", "mysql": "mysql", "mariadb": "mysql", "sqlite": "sqlite", "better-sqlite3": "sqlite", "mssql": "mssql", "mongodb": "mongodb"}


GUARDS_RX = r"@UseGuards\(((?:[^()]|\((?:[^()]|\([^()]*\))*\))*)\)"


def _ev(sf, start, end=None, symbol=None):
    return evidence(sf, start, end, DET, symbol)


def _repo_tech(idx):
    """Engine named by a TypeORM configuration anywhere in the repo, else 'sql'."""
    hits = set()
    for sf in idx.files.values():
        if sf.lang in JS_LANGS and ("typeorm" in sf.text or "TypeOrm" in sf.text):
            hits |= {TYPE_TECH[m.group(1)] for m in SQL_TYPE_RX.finditer(sf.text)}
    import os
    for rel in idx.config_files:
        if os.path.basename(rel).startswith("ormconfig"):
            try:
                hits |= {TYPE_TECH[m.group(1)] for m in re.finditer(r"\"type\"\s*:\s*\"(\w[\w-]*)\"", open(os.path.join(idx.root, rel), encoding="utf-8", errors="replace").read()) if m.group(1) in TYPE_TECH}
            except OSError:
                pass
    return sorted(hits)[0] if len(hits) == 1 else "sql"


def run(idx, facts):
    files = [sf for sf in idx.files.values() if sf.lang in ("typescript", "tsx") and not sf.is_test]
    if not any("@nestjs/" in sf.text or "typeorm" in sf.text or "@Entity" in sf.text for sf in files):
        return
    tech = _repo_tech(idx)
    entities = {}   # entity class name -> logical table name
    for sf in files:
        for m in re.finditer(r"@Entity\(\s*(?:['\"`](\w+)['\"`]|\{[^}]*name\s*:\s*['\"`](\w+)['\"`][^}]*\})?[^)]*\)\s*(?:@\w+\([^)]*\)\s*)*(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+(\w+)", sf.text):
            cls = m.group(3)
            logical = m.group(1) or m.group(2) or re.sub(r"(Entity|Model)$", "", cls)
            entities[cls] = logical
            line = sf.line_of_offset(m.start())
            cinfo = idx.classes.classes.get((sf.path, cls))
            end = cinfo["end"] if cinfo else line
            body = "\n".join(sf.lines[line - 1:end])
            fields = [{"name": f.group(1), "type": f.group(2)[:30]} for f in re.finditer(r"@(?:Column|PrimaryGeneratedColumn|PrimaryColumn|CreateDateColumn|UpdateDateColumn)\([^)]*\)\s*(?:@\w+\([^)]*\)\s*)*(\w+)\s*[?!]?\s*:\s*([\w\[\]<>| ]+)", body)]
            facts.add("store_access", DET, _ev(sf, line), file=sf.path, technology=tech, operation="model_definition", logical_name=logical)
            if fields:
                facts.add("schema", DET, _ev(sf, line, end), file=sf.path, name=logical, fields=fields, schema_kind="model")
    for sf in files:
        _file(idx, sf, facts, tech, entities)


def _entity_logical(entities, type_name):
    if not type_name:
        return None
    return entities.get(type_name) or re.sub(r"(Entity|Model|Document)$", "", type_name)


def _file(idx, sf, facts, tech, entities):
    text, lines = sf.text, sf.lines
    # ---- application bootstrap
    if "NestFactory.create" in text:
        m = re.search(r"NestFactory\.create", text)
        facts.add("app", DET, _ev(sf, sf.line_of_offset(m.start())), file=sf.path, framework="nestjs")
        for m in re.finditer(r"\.setGlobalPrefix\(\s*['\"`]([^'\"`]*)['\"`]", text):
            facts.add("global_prefix", DET, _ev(sf, sf.line_of_offset(m.start())), file=sf.path, prefix=m.group(1))
        for m in re.finditer(r"\.listen\(\s*([^,)]+)", text):
            facts.add("listener", DET, _ev(sf, sf.line_of_offset(m.start())), file=sf.path, port=m.group(1).strip()[:40], tls="httpsOptions" in text)
        for m in re.finditer(r"\.useGlobal(Guards|Pipes|Interceptors)\(\s*new\s+(\w+)", text):
            kind = classify_control(m.group(2)) or ("input_validation" if m.group(1) == "Pipes" else None)
            if kind:
                facts.add("control", DET, _ev(sf, sf.line_of_offset(m.start())), file=sf.path, control_kind=kind, name=m.group(2), scope="service")
        if re.search(r"enableCors\(\s*\)|origin:\s*(true|['\"]\*['\"])", text):
            m = re.search(r"enableCors\(", text)
            if m:
                facts.add("weakness", DET, _ev(sf, sf.line_of_offset(m.start())), file=sf.path, weakness_kind="permissive_cors", name="enableCors() with default or wildcard origin")
    for m in re.finditer(r"provide\s*:\s*APP_GUARD\s*,\s*useClass\s*:\s*(\w+)", text):
        kind = classify_control(m.group(1))
        if kind:
            facts.add("control", DET, _ev(sf, sf.line_of_offset(m.start())), file=sf.path, control_kind=kind, name=m.group(1), scope="service")
    # ---- middleware consumers: consumer.apply(A, B).forRoutes(...)
    for m in re.finditer(r"\.apply\(([^)]*)\)\s*(?:\.exclude\(([^;]*?)\)\s*)?\.forRoutes\(", text):
        start = m.end(); depth = 1; i = start
        while i < len(text) and depth:
            depth += text[i] == "("; depth -= text[i] == ")"; i += 1
        body = text[start:i - 1]
        routes = [(r.group(2) or "ANY", r.group(1)) for r in re.finditer(r"\{\s*path\s*:\s*['\"`]([^'\"`]*)['\"`]\s*,\s*method\s*:\s*RequestMethod\.(\w+)", body)]
        routes += [("ANY", r.group(1)) for r in re.finditer(r"(?<![:\w])['\"`]([^'\"`]*)['\"`](?!\s*,\s*method)", re.sub(r"\{[^}]*\}", "", body))]
        ctrls = [c for c in re.findall(r"\b([A-Z]\w*Controller)\b", body)]
        for mw in [x.strip() for x in m.group(1).split(",") if x.strip()]:
            kind = classify_control(mw)
            if kind:
                facts.add("control", DET, _ev(sf, sf.line_of_offset(m.start())), file=sf.path, control_kind=kind, name=mw, scope="service",
                          routes=[(meth.upper().replace("ALL", "ANY"), path) for meth, path in routes], router_names=ctrls)
    # ---- controllers
    for m in re.finditer(r"@Controller\(\s*(?:['\"`]([^'\"`]*)['\"`]|\{[^}]*path\s*:\s*['\"`]([^'\"`]*)['\"`][^}]*\})?\s*\)\s*((?:@\w+\([^)]*(?:\([^)]*\)[^)]*)*\)\s*)*)(?:export\s+)?(?:default\s+)?class\s+(\w+)", text):
        cls = m.group(4); prefix = m.group(1) or m.group(2) or ""
        cline = sf.line_of_offset(m.start())
        facts.add("router", DET, _ev(sf, cline), file=sf.path, local=cls, own_prefix=prefix, root=True)
        pre = text[max(0, m.start() - 300):m.start()]
        class_decos = m.group(3) + " ".join([x.group(0) for x in re.finditer(GUARDS_RX, pre.split("}")[-1])])
        for g in re.finditer(GUARDS_RX, class_decos):
            for guard in re.findall(r"\b([A-Z]\w*)\b", g.group(1)):
                kind = classify_control(guard)
                if kind:
                    facts.add("control", DET, _ev(sf, cline), file=sf.path, control_kind=kind, name=guard, scope="router", router=cls, ordered=False)
        cinfo = idx.classes.classes.get((sf.path, cls))
        cend = cinfo["end"] if cinfo else len(lines)
        i = cline
        while i <= cend:
            line = lines[i - 1]
            rm = ROUTE_DECO_RX.search(line)
            if not rm:
                i += 1; continue
            # decorator block: contiguous decorator lines above and below the route decorator
            top = i
            while top - 1 >= cline and lines[top - 2].strip().startswith("@"):
                top -= 1
            j = i + 1
            while j <= cend and (lines[j - 1].strip().startswith("@") or not lines[j - 1].strip()):
                j += 1
            sig = METHOD_SIG_RX.match(lines[j - 1]) if j <= cend else None
            block = "\n".join(lines[top - 1:j - 1])
            controls = []
            for g in re.finditer(GUARDS_RX + r"|@(Roles|Auth|Throttle|UsePipes)\(", block):
                names = re.findall(r"\b([A-Z]\w*)\b", g.group(1)) if g.group(1) else [g.group(2)]
                for guard in names:
                    kind = classify_control(guard) or ("authz" if guard == "Roles" else None)
                    if kind:
                        controls.append(facts.add("control", DET, _ev(sf, i), file=sf.path, control_kind=kind, name=guard, scope="route"))
            if sig:
                facts.add("entry_point", DET, _ev(sf, i, j), file=sf.path, protocol="http", method=rm.group(1).upper().replace("ALL", "ANY"), path=rm.group(2) or "", router=cls,
                          route_controls=controls, handler_file=sf.path, handler_symbol=f"{cls}.{sig.group(1)}",
                          **({"anonymous": True} if re.search(r"@(Public|SkipAuth|AllowAnonymous|IsPublic|NoAuth)\(", block) else {}))
            i = j + 1
    # ---- gRPC / message handlers in Nest microservices
    for m in re.finditer(r"@GrpcMethod\(\s*['\"`](\w+)['\"`]", text):
        facts.add("entry_point", DET, _ev(sf, sf.line_of_offset(m.start())), file=sf.path, protocol="grpc", method="grpc", path=m.group(1), router="<grpc>", handler_scope="file")
    # ---- data access through typed fields
    if not re.search(r"(Repository|EntityManager|DataSource|InjectModel|Prisma|HttpService|getRepository)", text):
        return
    for n in walk(sf.tree.root_node):
        if n.type != "call_expression":
            continue
        fn = n.child_by_field_name("function")
        if fn is None:
            continue
        ftxt = re.sub(r"\s+", "", sf.node_text(fn))
        line = sf.line(n)
        m = re.match(r"^(?:await)?(?:this\.)?(?:\w+\.)?getRepository$", ftxt)
        if m:
            args = n.child_by_field_name("arguments")
            ent = sf.node_text(args.named_children[0]) if args is not None and args.named_child_count else None
            if ent and re.match(r"^[A-Z]\w*$", ent):
                # the operation is the method chained on the repository, when present
                parent = n.parent
                op = sf.node_text(parent.child_by_field_name("property")) if parent is not None and parent.type == "member_expression" and parent.child_by_field_name("property") is not None else "createQueryBuilder"
                facts.add("store_access", DET, _ev(sf, line), file=sf.path, technology=tech, operation="write" if op in ORM_WRITE and op not in ORM_READ else "read", logical_name=_entity_logical(entities, ent), method=op)
            continue
        m = re.match(r"^this\.(\w+)\.(\w+)(?:\.(\w+))?$", ftxt)
        if not m:
            continue
        cls = idx.classes.class_at(sf.path, line)
        ft = idx.classes.field_type(sf.path, cls, m.group(1)) if cls else None
        if not ft:
            continue
        ftype, generic = ft
        op = m.group(3) or m.group(2)
        if ftype in ("Repository", "TreeRepository", "MongoRepository", "EntityRepository") or (generic is None and idx.classes.base_generic(idx.type_file(sf, ftype) or "", ftype, ("Repository", "TreeRepository", "MongoRepository", "EntityRepository"))):
            ent = generic or idx.classes.base_generic(idx.type_file(sf, ftype) or "", ftype, ("Repository", "TreeRepository", "MongoRepository", "EntityRepository"))
            if m.group(3) is None and (op in ORM_READ or op in ORM_WRITE):
                facts.add("store_access", DET, _ev(sf, line), file=sf.path, technology=tech, operation="write" if op in ORM_WRITE and op not in ORM_READ else "read", logical_name=_entity_logical(entities, ent), method=op)
        elif ftype in ("EntityManager", "DataSource", "Connection") and (m.group(2) in ORM_READ or m.group(2) in ORM_WRITE):
            args = n.child_by_field_name("arguments")
            ent = sf.node_text(args.named_children[0]) if args is not None and args.named_child_count and args.named_children[0].type == "identifier" else None
            facts.add("store_access", DET, _ev(sf, line), file=sf.path, technology=tech, operation="write" if m.group(2) in ORM_WRITE and m.group(2) not in ORM_READ else "read", logical_name=_entity_logical(entities, ent) if ent and ent[:1].isupper() else None, method=m.group(2))
        elif ftype == "Model" and (op in ORM_READ or op in ORM_WRITE):
            facts.add("store_access", DET, _ev(sf, line), file=sf.path, technology="mongodb", operation="write" if op in ORM_WRITE and op not in ORM_READ else "read", logical_name=_entity_logical(entities, generic), method=op)
        elif re.search(r"Prisma(Service|Client)$", ftype) and m.group(3) and (m.group(3) in ORM_READ or m.group(3) in ORM_WRITE):
            facts.add("store_access", DET, _ev(sf, line), file=sf.path, technology="sql", operation="write" if m.group(3) in ORM_WRITE and m.group(3) not in ORM_READ else "read", logical_name=m.group(2), method=m.group(3))
        elif ftype == "HttpService" and m.group(2) in ("get", "post", "put", "patch", "delete", "request"):
            args = n.child_by_field_name("arguments")
            url = sf.node_text(args.named_children[0]).strip("'\"`") if args is not None and args.named_child_count else ""
            host, scheme = host_of_url(url)
            facts.add("outbound_call", DET, _ev(sf, line), file=sf.path, protocol=scheme or "unknown", operation=m.group(2), sdk_service=None, host=host or "variable:" + url[:40], entity_kind="system", package="@nestjs/axios")
            if scheme == "http" and host and not is_local(host):
                facts.add("weakness", DET, _ev(sf, line), file=sf.path, weakness_kind="unencrypted_transport", name=f"plain http:// to {host}")
