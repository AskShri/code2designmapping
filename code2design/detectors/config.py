"""Configuration detectors: docker compose, Kubernetes manifests, Dockerfiles, package manifests,
Prisma schema, committed .env files. These yield boundaries, store technologies, service hostnames
(for cross-service flow resolution) and plaintext-credential weaknesses."""
import os, re
import yaml
from collections import OrderedDict
from ..model import PASSWORD_KEY_RX, classify_field

DET = "config@0.3"
IMAGE_TECH = [("postgres", "postgres"), ("pgvector", "postgres"), ("timescale", "postgres"), ("mysql", "mysql"), ("mariadb", "mysql"), ("percona", "mysql"), ("mongo", "mongodb"), ("redis", "redis"), ("valkey", "redis"), ("memcached", "memcached"), ("elasticsearch", "elasticsearch"), ("opensearch", "elasticsearch"), ("kafka", "kafka"), ("redpanda", "kafka"), ("rabbitmq", "rabbitmq"), ("minio", "s3"), ("localstack", "s3"), ("mssql", "mssql"), ("sqlserver", "mssql"), ("dynamodb", "dynamodb"), ("sqlite", "sqlite")]
INFRA_IMAGES = ("nginx", "traefik", "haproxy", "caddy", "envoy", "grafana", "prometheus", "kibana", "logstash", "jaeger", "zipkin", "otel", "pgadmin", "adminer", "mailhog", "maildev")


def _ev(path, s, e, lines, detector=DET):
    from ..model import span_hash
    return OrderedDict(path=path, start_line=s, end_line=e, detector=detector, content_hash=span_hash(lines[s - 1:e]))


def _line_of(lines, needle, start=0):
    for i, l in enumerate(lines[start:], start=start):
        if needle in l:
            return i + 1
    return 1


def run(idx, facts):
    for rel in idx.config_files:
        fn = os.path.basename(rel)
        full = os.path.join(idx.root, rel)
        try:
            text = open(full, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        lines = text.splitlines() or [""]
        if fn.startswith(("docker-compose", "compose")) and fn.endswith((".yml", ".yaml")):
            _compose(idx, facts, rel, text, lines)
        elif fn == "Dockerfile" or fn.startswith("Dockerfile"):
            for i, l in enumerate(lines):
                if l.strip().upper().startswith("EXPOSE"):
                    facts.add("boundary_hint", DET, [_ev(rel, i + 1, i + 1, lines)], boundary_kind="container", name=os.path.dirname(rel) or ".", context=os.path.dirname(rel) or ".", ports=l.split()[1:], source="dockerfile")
                m = re.match(r"\s*(ENV|ARG)\s+([A-Z0-9_]+)[= ]\s*(\S+)", l)
                if m and PASSWORD_KEY_RX.search(m.group(2)) and not m.group(3).startswith("$") and len(m.group(3)) > 3:
                    facts.add("weakness", DET, [_ev(rel, i + 1, i + 1, lines)], weakness_kind="plaintext_credentials", name=f"{m.group(2)} set in Dockerfile", file=rel)
        elif fn == "package.json":
            try:
                import json
                pkg = json.loads(text)
                facts.add("module", DET, [_ev(rel, 1, 1, lines)], path=os.path.dirname(rel) or ".", name=pkg.get("name") or (os.path.dirname(rel) or os.path.basename(idx.root)), workspaces=pkg.get("workspaces"))
                deps = sorted((pkg.get("dependencies") or {}).items())
                if deps:
                    facts.add("dependencies", DET, [_ev(rel, _line_of(lines, '"dependencies"'), _line_of(lines, '"dependencies"'), lines)], file=rel, ecosystem="npm", packages=[f"{k}@{v}" for k, v in deps])
            except ValueError:
                pass
        elif fn in ("requirements.txt",) or fn.startswith("requirements"):
            pk = [l.strip() for l in lines if l.strip() and not l.strip().startswith(("#", "-"))]
            if pk:
                facts.add("dependencies", DET, [_ev(rel, 1, 1, lines)], file=rel, ecosystem="pypi", packages=pk)
        elif fn.endswith(".prisma"):
            ds = re.search(r"datasource\s+\w+\s*\{[^}]*provider\s*=\s*\"(\w+)\"", text)
            tech = {"postgresql": "postgres", "mysql": "mysql", "sqlite": "sqlite", "mongodb": "mongodb", "sqlserver": "mssql"}.get(ds.group(1) if ds else "", "unknown")
            for m in re.finditer(r"^model\s+(\w+)\s*\{([^}]*)\}", text, re.M):
                fields = [{"name": f.group(1), "type": f.group(2)} for f in re.finditer(r"^\s*(\w+)\s+(\w+)", m.group(2), re.M)]
                s = text[:m.start()].count("\n") + 1
                facts.add("schema", DET, [_ev(rel, s, s + m.group(0).count("\n"), lines)], name=m.group(1), fields=fields, file=rel, schema_kind="prisma")
                facts.add("store_access", DET, [_ev(rel, s, s, lines)], technology=tech, operation="model_definition", logical_name=m.group(1), method="prisma_model", file=rel, handler=None, local="prisma")
        elif fn.startswith(".env") and not fn.endswith((".example", ".sample", ".template", ".dist", ".test")):
            for i, l in enumerate(lines):
                m = re.match(r"\s*(?:export\s+)?([A-Z0-9_]+)\s*=\s*(.+)$", l)
                if m and PASSWORD_KEY_RX.search(m.group(1)) and len(m.group(2).strip("'\" ")) > 3 and not re.search(r"(example|changeme|your|xxx|<)", m.group(2), re.I):
                    facts.add("weakness", DET, [_ev(rel, i + 1, i + 1, lines)], weakness_kind="plaintext_credentials", name=f"{m.group(1)} committed in {fn}", file=rel)
    for rel in idx.k8s_files:
        _k8s(idx, facts, rel)


def _compose(idx, facts, rel, text, lines):
    try:
        doc = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        facts.add("unresolved", DET, [_ev(rel, 1, 1, lines)], detail="compose file could not be parsed", file=rel)
        return
    services = doc.get("services") or {}
    if not isinstance(services, dict):
        return
    base = os.path.dirname(rel)
    for name, svc in sorted(services.items()):
        if not isinstance(svc, dict):
            continue
        line = _line_of(lines, f"{name}:")
        image = str(svc.get("image") or "")
        build = svc.get("build")
        ctx = None
        if isinstance(build, str):
            ctx = os.path.normpath(os.path.join(base, build))
        elif isinstance(build, dict):
            ctx = os.path.normpath(os.path.join(base, build.get("context", ".")))
        tech = next((t for k, t in IMAGE_TECH if k in image.lower()), None)
        env = svc.get("environment") or {}
        if isinstance(env, list):
            env = dict(e.split("=", 1) if "=" in e else (e, "") for e in env)
        ports = [str(p) for p in (svc.get("ports") or [])]
        if tech:
            facts.add("store_access", DET, [_ev(rel, line, line, lines)], technology=tech, operation="service_definition", logical_name=name, method="compose_service", file=rel, handler=None, local=None, host=name, image=image)
            facts.add("boundary_hint", DET, [_ev(rel, line, line, lines)], boundary_kind="container", name=name, context=None, ports=ports, source="compose", holds_store=True, technology=tech, host=name)
        elif any(k in image.lower() for k in INFRA_IMAGES):
            facts.add("boundary_hint", DET, [_ev(rel, line, line, lines)], boundary_kind="container", name=name, context=ctx, ports=ports, source="compose", infra=True, host=name, image=image)
        else:
            facts.add("boundary_hint", DET, [_ev(rel, line, line, lines)], boundary_kind="container", name=name, context=ctx or ".", ports=ports, source="compose", host=name, image=image)
        for k, v in sorted(env.items()):
            if PASSWORD_KEY_RX.search(str(k)) and v not in (None, "") and not str(v).startswith("$") and len(str(v)) > 2:
                facts.add("weakness", DET, [_ev(rel, _line_of(lines, str(k), line - 1), _line_of(lines, str(k), line - 1), lines)], weakness_kind="plaintext_credentials", name=f"{k} set in compose service '{name}'", file=rel)
        if "0.0.0.0" in text and ports:
            pass


def _k8s(idx, facts, rel):
    full = os.path.join(idx.root, rel)
    text = open(full, encoding="utf-8", errors="replace").read(); lines = text.splitlines() or [""]
    try:
        docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
    except yaml.YAMLError:
        return
    for d in docs:
        kind = d.get("kind"); meta = d.get("metadata") or {}; name = meta.get("name") or "?"
        line = _line_of(lines, f"name: {name}")
        if kind in ("Deployment", "StatefulSet", "DaemonSet"):
            containers = (((d.get("spec") or {}).get("template") or {}).get("spec") or {}).get("containers") or []
            images = [str(c.get("image", "")) for c in containers]
            tech = next((t for img in images for k, t in IMAGE_TECH if k in img.lower()), None)
            envs = [e for c in containers for e in (c.get("env") or []) if isinstance(e, dict)]
            if tech:
                facts.add("store_access", DET, [_ev(rel, line, line, lines)], technology=tech, operation="service_definition", logical_name=name, method="k8s_workload", file=rel, handler=None, local=None, host=name, image=images[0] if images else None)
                facts.add("boundary_hint", DET, [_ev(rel, line, line, lines)], boundary_kind="container", name=name, context=None, ports=[], source="k8s", holds_store=True, technology=tech, host=name)
            else:
                facts.add("boundary_hint", DET, [_ev(rel, line, line, lines)], boundary_kind="container", name=name, context=_guess_context(idx, name, images), ports=[], source="k8s", host=name, image=images[0] if images else None,
                          env_hosts={e["name"]: str(e.get("value")) for e in envs if "value" in e and re.search(r"(ADDR|HOST|URL|URI|ENDPOINT)", str(e.get("name")))})
            for e in envs:
                if PASSWORD_KEY_RX.search(str(e.get("name"))) and "value" in e and len(str(e["value"])) > 3:
                    facts.add("weakness", DET, [_ev(rel, line, line, lines)], weakness_kind="plaintext_credentials", name=f"{e['name']} literal in {kind} {name}", file=rel)
        elif kind == "Service":
            ports = [str(p.get("port")) for p in ((d.get("spec") or {}).get("ports") or []) if isinstance(p, dict)]
            facts.add("service_host", DET, [_ev(rel, line, line, lines)], host=name, ports=ports, file=rel)
        elif kind == "Ingress":
            facts.add("boundary_hint", DET, [_ev(rel, line, line, lines)], boundary_kind="internet", name=f"ingress {name}", context=None, ports=[], source="k8s", infra=True, host=name)


def _guess_context(idx, name, images):
    cands = [f"src/{name}", name, f"services/{name}", f"apps/{name}"]
    for img in images:
        base = img.split("/")[-1].split(":")[0]
        cands += [f"src/{base}", base]
    for c in cands:
        if any(p.startswith(c + "/") for p in idx.files):
            return c
    return None
