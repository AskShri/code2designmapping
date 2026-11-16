"""Configuration detectors: docker compose, Kubernetes manifests, Dockerfiles, Terraform, package
manifests, Prisma schemas, committed .env files and appsettings.json. They yield trust boundaries,
declared data stores (with encryption-at-rest and exposure where the descriptor states them),
service hostnames and declared service-to-service links, public exposure, dependency inventories
and credential weaknesses.
Coverage statement: literal values only; Helm templates and Terraform modules are not expanded."""
import json, os, re
import yaml
from ..model import PASSWORD_KEY_RX, PLACEHOLDER_RX, text_evidence

DET = "config@0.5"
IMAGE_TECH = [("postgres", "postgres"), ("pgvector", "postgres"), ("timescale", "postgres"), ("postgis", "postgres"), ("mysql", "mysql"), ("mariadb", "mysql"), ("percona", "mysql"), ("mongo", "mongodb"),
              ("redis", "redis"), ("valkey", "redis"), ("keydb", "redis"), ("memcached", "memcached"), ("elasticsearch", "elasticsearch"), ("opensearch", "elasticsearch"), ("kafka", "kafka"), ("redpanda", "kafka"),
              ("rabbitmq", "rabbitmq"), ("minio", "s3"), ("localstack", "s3"), ("mssql", "mssql"), ("sqlserver", "mssql"), ("azure-sql-edge", "mssql"), ("dynamodb", "dynamodb")]
TOOL_IMAGE_RX = re.compile(r"(express|commander|admin|adminer|-ui$|ui-|exporter|insight|kibana|dashboard|studio|browser|manager|proxy$|backup)", re.I)
INFRA_IMAGES = ("nginx", "traefik", "haproxy", "caddy", "envoy", "grafana", "prometheus", "kibana", "logstash", "jaeger", "zipkin", "otel", "pgadmin", "adminer", "mailhog", "maildev", "mailcatcher",
                "zookeeper", "consul", "vault", "portainer", "watchtower", "busybox", "alpine", "certbot", "fluentd", "loki", "tempo", "mongo-express", "redis-commander", "phpmyadmin")
TF_STORES = {"aws_db_instance": None, "aws_rds_cluster": None, "aws_s3_bucket": "s3", "aws_dynamodb_table": "dynamodb", "aws_elasticache_cluster": "redis", "aws_elasticache_replication_group": "redis",
             "aws_sqs_queue": "sqs", "aws_msk_cluster": "kafka", "aws_opensearch_domain": "elasticsearch", "aws_elasticsearch_domain": "elasticsearch", "google_sql_database_instance": None,
             "google_storage_bucket": "gcs", "google_redis_instance": "redis", "azurerm_postgresql_server": "postgres", "azurerm_postgresql_flexible_server": "postgres", "azurerm_mysql_server": "mysql",
             "azurerm_mssql_server": "mssql", "azurerm_redis_cache": "redis", "azurerm_storage_account": "unknown", "azurerm_cosmosdb_account": "unknown"}


def _ev(path, lines, start, end=None):
    return text_evidence(path, lines, start, end, DET)


def _line(lines, regex, start=0, default=1):
    rx = re.compile(regex)
    for i in range(start, len(lines)):
        if rx.search(lines[i]):
            return i + 1
    return default


def image_tech(image):
    """Data-store technology of a container image, or None (admin tools for a store are not the store)."""
    base = (image or "").split("@")[0].split(":")[0].split("/")[-1].lower()
    if not base or TOOL_IMAGE_RX.search(base):
        return None
    return next((t for k, t in IMAGE_TECH if base == k or base.startswith(k + "-") or base.startswith(k) and base[len(k):].isdigit() or base.endswith("-" + k) or base in (k + "db", k + "ql", "cp-" + k)), None)


def _is_literal_secret(value):
    v = str(value).strip("'\" ")
    return len(v) >= 3 and not v.startswith("$") and not PLACEHOLDER_RX.search(v)


def run(idx, facts):
    for rel in idx.config_files:
        fn = os.path.basename(rel)
        try:
            text = open(os.path.join(idx.root, rel), encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        lines = text.splitlines() or [""]
        if fn.startswith(("docker-compose", "compose")) and fn.endswith((".yml", ".yaml")):
            _compose(idx, facts, rel, text, lines)
        elif fn.startswith("Dockerfile"):
            ctx = os.path.dirname(rel) or "."
            ports = [p for l in lines if l.strip().upper().startswith("EXPOSE") for p in l.split()[1:]]
            facts.add("boundary_hint", DET, _ev(rel, lines, _line(lines, r"^\s*(EXPOSE|FROM)\b")), name=os.path.basename(ctx) if ctx != "." else "app", boundary_kind="container", source="dockerfile", context=ctx, ports=ports)
            for i, l in enumerate(lines, 1):
                m = re.match(r"\s*(?:ENV|ARG)\s+([A-Z0-9_]+)[= ]\s*(\S+)", l)
                if m and PASSWORD_KEY_RX.search(m.group(1)) and _is_literal_secret(m.group(2)):
                    facts.add("weakness", DET, _ev(rel, lines, i), file=rel, weakness_kind="plaintext_credentials", name=f"{m.group(1)} set in {fn}")
        elif fn == "package.json":
            try:
                pkg = json.loads(text)
            except ValueError:
                continue
            if not isinstance(pkg, dict):
                continue
            d = os.path.dirname(rel) or "."
            if pkg.get("name"):
                facts.add("module", DET, _ev(rel, lines, _line(lines, r"\"name\"\s*:")), path=d, name=str(pkg["name"]).split("/")[-1])
            deps = sorted((pkg.get("dependencies") or {}).items()) if isinstance(pkg.get("dependencies"), dict) else []
            if deps:
                facts.add("dependencies", DET, _ev(rel, lines, _line(lines, r"\"dependencies\"\s*:")), file=rel, ecosystem="npm", packages=[f"{k}@{v}" for k, v in deps])
        elif fn == "pyproject.toml":
            m = re.search(r"^\[(?:project|tool\.poetry)\][^\[]*?^name\s*=\s*[\"']([^\"']+)", text, re.M | re.S)
            if m:
                facts.add("module", DET, _ev(rel, lines, _line(lines, r"^name\s*=")), path=os.path.dirname(rel) or ".", name=m.group(1))
            dm = re.search(r"^dependencies\s*=\s*\[(.*?)\]", text, re.M | re.S)
            pk = re.findall(r"[\"']([^\"']+)[\"']", dm.group(1)) if dm else []
            if pk:
                facts.add("dependencies", DET, _ev(rel, lines, _line(lines, r"^dependencies\s*=")), file=rel, ecosystem="pypi", packages=sorted(pk))
        elif fn.startswith("requirements") and fn.endswith(".txt"):
            pk = sorted(l.strip() for l in lines if l.strip() and not l.strip().startswith(("#", "-")))
            if pk:
                facts.add("dependencies", DET, _ev(rel, lines, 1), file=rel, ecosystem="pypi", packages=pk)
        elif fn == "go.mod":
            m = re.search(r"^module\s+(\S+)", text, re.M)
            if m:
                facts.add("module", DET, _ev(rel, lines, _line(lines, r"^module\s")), path=os.path.dirname(rel) or ".", name=m.group(1).split("/")[-1])
            pk = sorted(set(re.findall(r"^\s+([\w./-]+\.[\w./-]+)\s+v[\w.+-]+", text, re.M)))
            if pk:
                facts.add("dependencies", DET, _ev(rel, lines, 1), file=rel, ecosystem="go", packages=pk)
        elif fn == "pom.xml":
            m = re.search(r"<artifactId>([^<]+)</artifactId>", re.sub(r"<parent>.*?</parent>", "", text, flags=re.S))
            if m:
                facts.add("module", DET, _ev(rel, lines, _line(lines, re.escape(m.group(0)))), path=os.path.dirname(rel) or ".", name=m.group(1))
            pk = sorted(set(f"{g}:{a}" for g, a in re.findall(r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>", text)))
            if pk:
                facts.add("dependencies", DET, _ev(rel, lines, _line(lines, r"<dependencies>")), file=rel, ecosystem="maven", packages=pk)
        elif fn.endswith(".prisma"):
            ds = re.search(r"datasource\s+\w+\s*\{[^}]*provider\s*=\s*\"(\w+)\"", text)
            tech = {"postgresql": "postgres", "postgres": "postgres", "mysql": "mysql", "sqlite": "sqlite", "mongodb": "mongodb", "sqlserver": "mssql", "cockroachdb": "postgres"}.get(ds.group(1) if ds else "", "sql")
            for m in re.finditer(r"^model\s+(\w+)\s*\{([^}]*)\}", text, re.M):
                s = text[:m.start()].count("\n") + 1
                fields = [{"name": f.group(1), "type": f.group(2)} for f in re.finditer(r"^\s*(\w+)\s+(\w+)", m.group(2), re.M) if not f.group(1).startswith("@@")]
                facts.add("schema", DET, _ev(rel, lines, s, s + m.group(0).count("\n")), file=rel, name=m.group(1), fields=fields, schema_kind="model")
                facts.add("store_access", DET, _ev(rel, lines, s), file=rel, technology=tech, operation="model_definition", logical_name=m.group(1))
        elif fn.startswith(".env") and not fn.endswith((".example", ".sample", ".template", ".dist", ".test", ".defaults")):
            for i, l in enumerate(lines, 1):
                m = re.match(r"\s*(?:export\s+)?([A-Z0-9_]+)\s*=\s*(.+)$", l)
                if m and PASSWORD_KEY_RX.search(m.group(1)) and _is_literal_secret(m.group(2)) and len(m.group(2).strip("'\" ")) > 3:
                    facts.add("weakness", DET, _ev(rel, lines, i), file=rel, weakness_kind="plaintext_credentials", name=f"{m.group(1)} committed in {fn}")
        elif fn.startswith("appsettings") and fn.endswith(".json"):
            for i, l in enumerate(lines, 1):
                m = re.search(r"\"([\w.]+)\"\s*:\s*\"([^\"]*(?:Password|Pwd)\s*=\s*([^;\"]+)[^\"]*)\"", l, re.I)
                if m and _is_literal_secret(m.group(3)):
                    facts.add("weakness", DET, _ev(rel, lines, i), file=rel, weakness_kind="plaintext_credentials", name=f"connection string {m.group(1)} embeds a password in {fn}")
    for rel in idx.k8s_files:
        _k8s(idx, facts, rel)
    for rel in idx.tf_files:
        _terraform(idx, facts, rel)


def _link_hosts(value, hosts):
    """Service hostnames referenced by an environment value (URL host, host:port, bare host)."""
    v = str(value)
    out = []
    for h in hosts:
        if re.search(r"(?:^|[/@=\s,])" + re.escape(h) + r"(?:[:/.\s,]|$)", v):
            out.append(h)
    return out


def _compose(idx, facts, rel, text, lines):
    try:
        doc = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        facts.add("unresolved", DET, _ev(rel, lines, 1), file=rel, detail="compose file could not be parsed")
        return
    services = doc.get("services") if isinstance(doc, dict) else None
    if not isinstance(services, dict):
        return
    base = os.path.dirname(rel)
    svc_start = _line(lines, r"^services\s*:") - 1
    names = sorted(str(k) for k in services)
    info = {}
    for name in names:
        svc = services[name]
        if not isinstance(svc, dict):
            continue
        line = _line(lines, r"^\s{1,4}['\"]?" + re.escape(name) + r"['\"]?\s*:\s*(#.*)?$", svc_start)
        image = str(svc.get("image") or "")
        build = svc.get("build")
        ctx = None
        if isinstance(build, str):
            ctx = os.path.normpath(os.path.join(base, build)).replace(os.sep, "/")
        elif isinstance(build, dict):
            ctx = os.path.normpath(os.path.join(base, str(build.get("context", ".")))).replace(os.sep, "/")
        env = svc.get("environment") or {}
        if isinstance(env, list):
            env = dict((str(e).split("=", 1) + [""])[:2] for e in env)
        ports = [str(p) for p in (svc.get("ports") or [])]
        tech = image_tech(image) if not build else None
        base_img = image.split(":")[0].split("/")[-1].lower()
        infra = (not tech) and (not build) and any(base_img == k or base_img.startswith(k) for k in INFRA_IMAGES)
        info[name] = dict(line=line, env=env, tech=tech, ctx=ctx, infra=infra)
        common = dict(name=name, boundary_kind="container", source="compose", host=name, ports=ports, image=image, exposed=bool(ports))
        if tech:
            facts.add("store_access", DET, _ev(rel, lines, line), file=rel, technology=tech, operation="service_definition", logical_name=name, host=name)
            facts.add("boundary_hint", DET, _ev(rel, lines, line), holds_store=True, technology=tech, context=None, **common)
        else:
            facts.add("boundary_hint", DET, _ev(rel, lines, line), context=ctx, infra=infra or ctx is None, **common)
        for k, v in sorted(env.items(), key=lambda kv: str(kv[0])):
            if PASSWORD_KEY_RX.search(str(k)) and v not in (None, "") and _is_literal_secret(v):
                facts.add("weakness", DET, _ev(rel, lines, _line(lines, r"\b" + re.escape(str(k)) + r"\b", line - 1, line)), file=rel, weakness_kind="plaintext_credentials", name=f"{k} set in compose service '{name}'")
    for name in names:
        if name not in info:
            continue
        targets = []
        for k, v in sorted(info[name]["env"].items(), key=lambda kv: str(kv[0])):
            targets += [(h, str(k)) for h in _link_hosts(v, [n for n in names if n != name])]
        svc = services[name]
        deps = svc.get("depends_on") or []
        deps = list(deps) if isinstance(deps, (list, dict)) else []
        seen = set()
        for h, key in targets:
            if h not in seen:
                seen.add(h)
                facts.add("declared_link", DET, _ev(rel, lines, _line(lines, r"\b" + re.escape(key) + r"\b", info[name]["line"] - 1, info[name]["line"])), file=rel, source_service=name, target_host=h, via=key)


def _k8s(idx, facts, rel):
    try:
        text = open(os.path.join(idx.root, rel), encoding="utf-8", errors="replace").read()
        docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
    except (OSError, yaml.YAMLError):
        return
    lines = text.splitlines() or [""]
    service_names = sorted({str((d.get("metadata") or {}).get("name")) for d in docs if d.get("kind") == "Service"})
    public = set()
    for d in docs:
        if d.get("kind") == "Service" and (d.get("spec") or {}).get("type") in ("LoadBalancer", "NodePort"):
            sel = ((d.get("spec") or {}).get("selector") or {})
            public |= {str(v) for v in sel.values()}
        if d.get("kind") == "Ingress":
            public |= set(re.findall(r"(?:serviceName|name):\s*([\w-]+)", yaml.safe_dump(d.get("spec") or {})))
    for d in docs:
        kind = d.get("kind"); meta = d.get("metadata") or {}; name = str(meta.get("name") or "?")
        line = _line(lines, r"^\s*name:\s*['\"]?" + re.escape(name) + r"['\"]?\s*$")
        if kind in ("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"):
            spec = (d.get("spec") or {})
            tmpl = ((spec.get("jobTemplate") or {}).get("spec") or spec).get("template") or {}
            containers = [c for c in ((tmpl.get("spec") or {}).get("containers") or []) if isinstance(c, dict)]
            images = [str(c.get("image", "")) for c in containers]
            tech = next((t for t in (image_tech(i) for i in images) if t), None)
            labels = {str(v) for v in ((tmpl.get("metadata") or {}).get("labels") or {}).values()} | {name}
            exposed = bool(labels & public)
            envs = [e for c in containers for e in (c.get("env") or []) if isinstance(e, dict)]
            common = dict(name=name, boundary_kind="container", source="k8s", host=name, ports=[], image=images[0] if images else "", exposed=exposed)
            if tech:
                facts.add("store_access", DET, _ev(rel, lines, line), file=rel, technology=tech, operation="service_definition", logical_name=name, host=name)
                facts.add("boundary_hint", DET, _ev(rel, lines, line), holds_store=True, technology=tech, context=None, **common)
            else:
                ctx = _guess_context(idx, name, images)
                facts.add("boundary_hint", DET, _ev(rel, lines, line), context=ctx, infra=ctx is None,
                          env_hosts={str(e["name"]): str(e.get("value")) for e in envs if "value" in e and re.search(r"(ADDR|HOST|URL|URI|ENDPOINT)", str(e.get("name")))}, **common)
            seen = set()
            for e in envs:
                ename = str(e.get("name"))
                eline = _line(lines, r"name:\s*['\"]?" + re.escape(ename) + r"['\"]?\s*$", line - 1, line)
                if "value" in e:
                    if PASSWORD_KEY_RX.search(ename) and _is_literal_secret(e["value"]):
                        facts.add("weakness", DET, _ev(rel, lines, eline), file=rel, weakness_kind="plaintext_credentials", name=f"{ename} literal in {kind} {name}")
                    for h in _link_hosts(e["value"], [s for s in service_names if s != name]):
                        if h not in seen:
                            seen.add(h)
                            facts.add("declared_link", DET, _ev(rel, lines, eline), file=rel, source_service=name, target_host=h, via=ename)
        elif kind == "Service":
            facts.add("service_host", DET, _ev(rel, lines, line), host=name, file=rel, selector=sorted(str(v) for v in ((d.get("spec") or {}).get("selector") or {}).values()))


def _guess_context(idx, name, images):
    cands = [f"src/{name}", name, f"services/{name}", f"apps/{name}", f"cmd/{name}"]
    for img in images:
        b = img.split("/")[-1].split(":")[0]
        cands += [f"src/{b}", b, f"services/{b}"]
    return next((c for c in cands if any(p.startswith(c + "/") for p in idx.files)), None)


def _terraform(idx, facts, rel):
    try:
        text = open(os.path.join(idx.root, rel), encoding="utf-8", errors="replace").read()
    except OSError:
        return
    lines = text.splitlines() or [""]
    for m in re.finditer(r"^resource\s+\"(\w+)\"\s+\"([\w-]+)\"\s*\{", text, re.M):
        rtype, rname = m.group(1), m.group(2)
        if rtype not in TF_STORES:
            continue
        depth = 0; i = m.end() - 1
        while i < len(text):
            depth += text[i] == "{"; depth -= text[i] == "}"
            if depth == 0:
                break
            i += 1
        body = text[m.end():i]
        start = text[:m.start()].count("\n") + 1
        tech = TF_STORES[rtype]
        if tech is None:
            eng = re.search(r"\b(?:engine|database_version)\s*=\s*\"([\w-]+)", body)
            e = (eng.group(1) if eng else "").lower()
            tech = "postgres" if "postgres" in e else "mysql" if ("mysql" in e or "maria" in e or "aurora" == e) else "mssql" if "sqlserver" in e else "sql"
        enc = "unknown"
        em = re.search(r"\b(storage_encrypted|encrypted|at_rest_encryption_enabled|server_side_encryption_enabled|enable_https_traffic_only)\s*=\s*(true|false)", body)
        if em:
            enc = "yes" if em.group(2) == "true" else "no"
        elif "server_side_encryption" in body or "kms_key" in body or "kms_master_key_id" in body:
            enc = "yes"
        pub = bool(re.search(r"\bpublicly_accessible\s*=\s*true", body) or re.search(r"\bacl\s*=\s*\"public-read", body) or re.search(r"authorized_networks[^}]*0\.0\.0\.0/0", body, re.S))
        ident = re.search(r"\b(?:identifier|bucket|name|cluster_identifier|cluster_id|replication_group_id)\s*=\s*\"([^\"$]+)\"", body)
        logical = ident.group(1) if ident else rname
        facts.add("store_access", DET, _ev(rel, lines, start), file=rel, technology=tech, operation="service_definition", logical_name=logical, host=None, encryption_at_rest=enc, public=pub, iac="terraform")
        if pub:
            facts.add("weakness", DET, _ev(rel, lines, start), file=rel, weakness_kind="public_data_store", name=f"{rtype}.{rname} is publicly accessible")
        if enc == "no":
            facts.add("weakness", DET, _ev(rel, lines, start), file=rel, weakness_kind="unencrypted_data_store", name=f"{rtype}.{rname} has encryption at rest disabled")
