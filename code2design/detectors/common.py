"""Helpers shared by the language detectors."""
import re
from ..model import evidence, LOCAL_HOSTS, PLACEHOLDER_RX

SQL_TABLE_RX = re.compile(r"\b(?:FROM|INTO|UPDATE|JOIN|TABLE)\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?[`\"'\[]?([A-Za-z_][A-Za-z0-9_.]*)", re.I)
SQL_COLUMNS_RX = [re.compile(r"INSERT\s+INTO\s+[`\"']?([A-Za-z_][\w.]*)[`\"']?\s*\(([^)]*)\)", re.I),
                  re.compile(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"']?([A-Za-z_][\w.]*)[`\"']?\s*\(([^;]*)\)", re.I | re.S)]
SQL_KEYWORDS = {"select", "set", "where", "values", "dual", "information_schema", "the", "a", "exists"}
URL_RX = re.compile(r"\b(https?)://([A-Za-z0-9.-]+\.[A-Za-z]{2,}|localhost|\d+\.\d+\.\d+\.\d+|[a-z][a-z0-9-]*)(?::\d+)?")


def sql_operation(sql):
    if re.search(r"\b(INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TRUNCATE|REPLACE)\b", sql, re.I):
        return "write"
    if re.search(r"\bSELECT\b", sql, re.I):
        return "read"
    return "unknown"


def sql_table(sql):
    m = SQL_TABLE_RX.search(sql or "")
    if m and m.group(1).lower() not in SQL_KEYWORDS:
        return m.group(1).split(".")[-1]
    return None


def sql_schema(sql):
    """(table, [columns]) from an INSERT/CREATE TABLE literal, or None."""
    for rx in SQL_COLUMNS_RX:
        m = rx.search(sql or "")
        if m:
            cols = [c.strip().strip('`"[]').split()[0] for c in m.group(2).split(",")
                    if c.strip() and not c.strip().upper().startswith(("PRIMARY", "FOREIGN", "UNIQUE", "CONSTRAINT", "KEY", "INDEX", "CHECK"))]
            cols = [c for c in cols if re.match(r"^[A-Za-z_]\w*$", c)]
            if cols:
                return m.group(1).split(".")[-1], cols
    return None


def host_of_url(url):
    """(host, scheme) for a literal URL, else (None, None)."""
    m = re.match(r"^(https?)://([^/:${}`'\"\s<>]+)", url or "")
    if m and re.match(r"^[A-Za-z0-9.-]+$", m.group(2)):
        return m.group(2).lower(), m.group(1)
    return None, None


def is_local(host):
    return bool(host) and (host in LOCAL_HOSTS or host.startswith(("127.", "localhost")))


def looks_like_secret_literal(value):
    v = (value or "").strip("'\"` ")
    return len(v) >= 6 and not PLACEHOLDER_RX.search(v) and not v.startswith(("process.env", "os.environ", "$")) and " " not in v.strip()


def grpc_service_name(raw):
    """CartServiceImpl / hipstershop.CartService / add_CartServiceServicer_to_server -> CartService."""
    raw = re.sub(r"^add_|_to_server$", "", raw.split(".")[-1])
    raw = re.sub(r"(Servicer|Impl|Server|Handler)$", "", raw)
    if raw and raw.lower() != "health" and not raw.endswith("Service"):
        raw += "Service"
    return raw or "Service"


def ev(sf, start, end=None, det="", symbol=None):
    return evidence(sf, start, end, det, symbol)


# Database driver packages named in dependency manifests -> SQL engine. Used only when code and
# configuration name no engine, so an ORM model still lands on the right technology.
DRIVER_ENGINES = [
    (r"\b(psycopg2?|psycopg-binary|asyncpg|pg8000|org\.postgresql|Npgsql[\w.]*|github\.com/(?:lib/pq|jackc/pgx))\b|\"pg\"", "postgres"),
    (r"\b(pymysql|mysqlclient|mysql-connector[\w-]*|aiomysql|mysql-connector-j|mysql2|Pomelo\.EntityFrameworkCore\.MySql|MySql\.EntityFrameworkCore|go-sql-driver/mysql)\b", "mysql"),
    (r"\b(Microsoft\.EntityFrameworkCore\.SqlServer|pyodbc|pymssql|mssql-jdbc|tedious|denisenkom/go-mssqldb)\b", "mssql"),
    (r"\b(Microsoft\.EntityFrameworkCore\.Sqlite|sqlite3|better-sqlite3|mattn/go-sqlite3)\b", "sqlite"),
]
MANIFESTS = ("requirements", "pyproject.toml", "Pipfile", "package.json", "pom.xml", "build.gradle", "go.mod")


def manifest_engine(idx):
    """The single SQL engine whose driver the dependency manifests declare, else None."""
    import os
    import re as _re
    hits = set()
    for rel in idx.config_files:
        fn = os.path.basename(rel)
        if not (fn.startswith(MANIFESTS) or fn.endswith(".csproj")):
            continue
        try:
            with open(os.path.join(idx.root, rel), encoding="utf-8", errors="replace") as fh:
                text = fh.read(200000)
        except OSError:
            continue
        for rx, tech in DRIVER_ENGINES:
            if _re.search(rx, text):
                hits.add(tech)
    if len(hits) > 1:
        hits.discard("sqlite")
    return sorted(hits)[0] if len(hits) == 1 else None
