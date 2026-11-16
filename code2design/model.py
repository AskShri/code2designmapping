"""Shared vocabulary: stable IDs, evidence, the fact registry, and the controlled vocabularies
(technologies, protocols, data classes, control kinds, weakness taxonomy)."""
import base64, hashlib, json, re
from collections import OrderedDict


# ------------------------------------------------------------------ IDs and evidence
def sid(kind, *identity):
    """Stable content-addressed ID: <kind>:<base32(sha256(identity tuple))[:10]>."""
    h = hashlib.sha256(json.dumps([kind, *identity]).encode()).digest()
    return f"{kind}:{base64.b32encode(h).decode().lower()[:10]}"


def span_hash(lines):
    """Whitespace-insensitive hash of a span, so `verify` can tell changed code from moved code."""
    return "sha256:" + hashlib.sha256(" ".join(" ".join(l.split()) for l in lines).encode()).hexdigest()


def evidence(sf, start, end=None, detector="", symbol=None):
    """Evidence span on a SourceFile-like object (1-based inclusive lines)."""
    end = end or start
    e = OrderedDict(path=sf.path, start_line=start, end_line=end, detector=detector,
                    content_hash=span_hash(sf.lines[start - 1:end]))
    if symbol:
        e["symbol"] = symbol
    return e


def text_evidence(path, lines, start, end=None, detector=""):
    end = end or start
    return OrderedDict(path=path, start_line=start, end_line=end, detector=detector, content_hash=span_hash(lines[start - 1:end]))


# ------------------------------------------------------------------ fact registry
# kind -> required attribute names. Detectors may add optional attributes; synth reads only
# documented ones (see docs/facts.md). Unknown kinds or missing required attributes raise.
FACT_KINDS = {
    "module":        ("path", "name"),
    "dependencies":  ("file", "ecosystem", "packages"),
    "app":           ("file",),                                   # an application entry (framework bootstrap)
    "listener":      ("file", "port", "tls"),
    "router":        ("file", "local", "own_prefix", "root"),      # a router object; root=True for app objects / auto-mounted controllers
    "router_mount":  ("file", "parent", "prefix", "child_file", "child_local"),
    "global_prefix": ("file", "prefix"),
    "entry_point":   ("file", "protocol", "method", "path", "router"),
    "control":       ("file", "control_kind", "name", "scope"),   # scope: route | router | service | handler
    "call_edge":     ("file", "line", "target_file", "target_symbol"),
    "store_access":  ("file", "technology", "operation"),         # operation: read | write | unknown | client_init | model_definition | service_definition
    "outbound_call": ("file", "protocol", "operation"),
    "schema":        ("file", "name", "fields", "schema_kind"),   # schema_kind: validation | request | model | sql
    "config_value":  ("file", "name", "data_class"),
    "weakness":      ("file", "weakness_kind", "name"),
    "boundary_hint": ("name", "boundary_kind", "source"),
    "service_host":  ("host", "file"),
    "declared_link": ("file", "source_service", "target_host"),   # env var in a deployment descriptor naming another service
    "unresolved":    ("file", "detail"),
}


class FactStore:
    def __init__(self):
        self.facts = []
        self._by_kind = {}

    def add(self, kind, detector, ev, **attrs):
        req = FACT_KINDS.get(kind)
        if req is None:
            raise ValueError(f"unknown fact kind {kind!r}")
        missing = [k for k in req if k not in attrs]
        if missing:
            raise ValueError(f"fact {kind!r} from {detector} is missing {missing}")
        if not ev:
            raise ValueError(f"fact {kind!r} from {detector} has no evidence")
        fid = f"fact_{len(self.facts) + 1:05d}"
        f = OrderedDict(id=fid, kind=kind, detector=detector)
        f.update(attrs)
        f["evidence"] = ev if isinstance(ev, list) else [ev]
        self.facts.append(f)
        self._by_kind.setdefault(kind, []).append(f)
        return fid

    def by_kind(self, kind):
        return self._by_kind.get(kind, [])

    def get(self, fid):
        return self.facts[int(fid.split("_")[1]) - 1]


# ------------------------------------------------------------------ vocabularies (mirror the IR schema)
PROTOCOLS = ("http", "https", "grpc", "graphql", "websocket", "amqp", "kafka", "sqs", "pubsub", "sql", "redis", "mongo", "file", "s3", "smtp", "cli", "in_process", "unknown")
TECH_PROTOCOL = {"postgres": "sql", "mysql": "sql", "sqlite": "sql", "mssql": "sql", "sql": "sql", "mongodb": "mongo", "dynamodb": "https", "redis": "redis", "memcached": "unknown",
                 "elasticsearch": "https", "kafka": "kafka", "rabbitmq": "amqp", "sqs": "sqs", "s3": "s3", "gcs": "https", "filesystem": "file", "unknown": "unknown"}
TECH_LABEL = {"postgres": "Postgres", "mysql": "MySQL", "sqlite": "SQLite", "mssql": "SQL Server", "sql": "SQL database", "mongodb": "MongoDB", "dynamodb": "DynamoDB", "redis": "Redis",
              "memcached": "Memcached", "elasticsearch": "Elasticsearch", "kafka": "Kafka", "rabbitmq": "RabbitMQ", "sqs": "SQS", "s3": "S3", "gcs": "GCS", "filesystem": "Filesystem", "unknown": "Data store"}
SQL_TECHS = ("postgres", "mysql", "sqlite", "mssql", "sql")
SENSITIVE_CLASSES = ("pii", "financial", "health", "credential", "secret")

# Field names are split into lower-case tokens (camelCase, snake_case, kebab-case) and matched on token
# boundaries, so "avatar" is not "vat" and "template" is not "lat".
_DATA_CLASS_TOKENS = [
    ("financial", r"card_token|credit_card|card_number|payment_token"),
    ("credential", r"password|passwd|pwd|secret|api_key|apikey|access_token|refresh_token|auth_token|private_key|credential|credentials|otp|mfa_secret|token|pin|passphrase"),
    ("financial", r"card|card_number|card_token|cvv|cvc|iban|bic|swift|account_number|routing_number|amount|price|balance|salary|invoice|payment|charge|tax_id|vat|vat_number|total_cents|total_amount|total_price|subtotal|grand_total|credit_card"),
    ("health", r"diagnosis|diagnoses|medical|health|patient|prescription|allergy|allergies|blood_type"),
    ("pii", r"email|e_mail|phone|mobile|telephone|address|street|city|zip|zipcode|postal|postcode|first_name|last_name|full_name|surname|firstname|lastname|birth|birthday|birthdate|dob|ssn|passport|national_id|gender|ip|ip_address|"
            r"geo|lat|lng|longitude|latitude|avatar|photo|username|user_name|bio|nickname"),
]
DATA_CLASS_RULES = [(cls, re.compile(r"(?<![a-z0-9])(?:" + alts + r")(?![a-z0-9])")) for cls, alts in _DATA_CLASS_TOKENS]


def _snake(name):
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name or "")
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")


CONFIG_SUFFIX_RX = re.compile(r"_(expiration|expires|expiry|ttl|minutes|hours|days|seconds|timeout|enabled|length|min_length|max_length|algorithm|rounds|url|uri|host|port|path|count|limit)$")


def classify_field(name):
    """Data class of a field name: credential, financial, health, pii, else internal."""
    s = _snake(name)
    if CONFIG_SUFFIX_RX.search(s):
        return "internal"           # JWT_VERIFY_EMAIL_EXPIRATION_MINUTES configures data, it does not hold it
    for cls, rx in DATA_CLASS_RULES:
        if rx.search(s):
            return cls
    return "internal"


SECRET_ENV_RX = re.compile(r"(SECRET|PASSWORD|PASSWD|PRIVATE_KEY|API_KEY|APIKEY|TOKEN|CLIENT_SECRET|ACCESS_KEY|DSN|CONNECTION_STRING|CREDENTIAL)", re.I)
PASSWORD_KEY_RX = re.compile(r"(PASSWORD|PASSWD|SECRET|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY|TOKEN)", re.I)
PLACEHOLDER_RX = re.compile(r"(example|changeme|change_me|your[-_ ]?|xxx|<[^>]*>|\{\{|\$\{|dummy|placeholder|todo)", re.I)
LOCAL_HOSTS = ("localhost", "127.0.0.1", "0.0.0.0", "::1", "::", "[::]", "[::1]")


def is_secret_name(name):
    return bool(SECRET_ENV_RX.search(name or "")) and not (name or "").upper().endswith(("_URL", "_URI", "_ADDR", "_HOST", "_PORT", "_PATH", "_FILE", "_EXPIRES", "_EXPIRATION", "_TTL", "_ALGORITHM"))


# ---- controls: classification by the middleware / decorator / annotation name (callee name only)
CONTROL_KINDS = ("authn", "authz", "input_validation", "rate_limit", "tls", "encryption_at_rest", "signing", "audit_log", "csrf", "cors", "security_headers")
# control kinds that stop a caller who lacks the credential or privilege; the rest mitigate but do not block
BLOCKING_KINDS = ("authn", "authz")
_CONTROL_RULES = [
    (re.compile(r"(rate_?limit|throttle|slow_?down|limiter)", re.I), "rate_limit"),
    (re.compile(r"(helmet|hsts|x_?frame|xframe|xss_?protection|nosniff|content_?security|referrer_?policy|lusca\.(?!csrf)\w+|secure_?headers|talisman)", re.I), "security_headers"),
    (re.compile(r"(csrf|csurf|xsrf|^lusca$|antiforgery)", re.I), "csrf"),
    (re.compile(r"(^cors$|cors\b|CORSMiddleware|flask_cors|CrossOrigin|UseCors)", re.I), "cors"),
    (re.compile(r"(authori[sz]|permission|role|can_|is_?admin|acl|rbac|scope|grant|has_?access|owner_?only|superuser|PreAuthorize|Secured|RolesAllowed)", re.I), "authz"),
    (re.compile(r"(auth|jwt|passport|login_?required|require_?user|protect|verify_?token|is_?authenticated|bearer|oauth|current_?user|get_?user|authenticate|ensure_?logged|guard)", re.I), "authn"),
    (re.compile(r"(validat|joi|zod|yup|celebrate|schema|sanitiz|hpp|xss|mongo_?sanitize|Valid\b|express_?validator|check_?schema)", re.I), "input_validation"),
    (re.compile(r"(audit|morgan|winston|pino|log_?request)", re.I), "audit_log"),
]
# registration plumbing that enforces nothing by itself
_PLUMBING_RX = re.compile(r"^(passport\.initialize|passport\.session|session|express_?session|cookie_?session|cookie_?parser|body_?parser(\.\w+)?|express\.json|express\.urlencoded|express\.static|compression|flash|errorhandler|methodOverride|favicon|serve_?static|"
                          r"UseAuthentication|AddAuthentication|AddJwtBearer|UseAuthorization|AddAuthorization|UseRouting|UseStaticFiles)$", re.I)
# optional authentication attaches identity when present but lets anonymous requests through
_OPTIONAL_RX = re.compile(r"(optional|maybe|try_?auth|soft_?auth|anonymous|allow_?anon|PermitAll|AllowAnonymous)", re.I)


def classify_control(name, args=""):
    """Control kind for a middleware / decorator name, or None. `args` is the call's argument text,
    used only to recognise non-enforcing variants such as AuthMiddleware(false)."""
    name = (name or "").strip()
    base = name.split("(")[0]
    if _PLUMBING_RX.search(base):
        return None
    if _OPTIONAL_RX.search(name):
        return None
    for rx, kind in _CONTROL_RULES:
        if rx.search(base):
            if kind == "authn" and re.fullmatch(r"\s*(false|False|0|required\s*[:=]\s*(false|False))\s*", args or "x"):
                return None
            return kind
    return None


def requires_auth(kinds):
    """An authorization check implies an authenticated caller."""
    return any(k in BLOCKING_KINDS for k in kinds)


def auth_scheme(control_names):
    """Flow authentication value (Threagile-compatible) from the names of the authn controls on a route."""
    names = " ".join(control_names).lower()
    if not names:
        return "none"
    if re.search(r"(jwt|bearer|token|oauth)", names):
        return "token"
    if re.search(r"(session|login_required|isauthenticated|ensureauth|cookie)", names):
        return "session_id"
    return "credentials"


# ---- weakness taxonomy: kind -> (CWE, severity, STRIDE categories, title)
WEAKNESSES = {
    "plaintext_credentials":       ("CWE-798", "high",   ["I", "E"], "Hard-coded or committed credentials"),
    "tls_verification_disabled":   ("CWE-295", "high",   ["S", "T", "I"], "TLS certificate verification disabled"),
    "unencrypted_transport":       ("CWE-319", "medium", ["T", "I"], "Cleartext transport to a non-local host"),
    "permissive_cors":             ("CWE-942", "medium", ["I"], "Permissive cross-origin policy"),
    "csrf_disabled":               ("CWE-352", "medium", ["T"], "CSRF protection disabled"),
    "public_data_store":           ("CWE-284", "high",   ["I", "T"], "Data store reachable from the internet"),
    "unencrypted_data_store":      ("CWE-311", "medium", ["I"], "Data store without encryption at rest"),
    "debug_mode_enabled":          ("CWE-489", "medium", ["I", "E"], "Debug mode enabled on the application server"),
    "unauthenticated_entry_point": ("CWE-306", "info",   ["S", "E"], "Entry point without a detected authentication control (review)"),
}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


# ---- paths: one template syntax ({param}) regardless of framework
_PARAM_RXS = [(re.compile(r"<(?:[^:>]+:)?([^>]+)>"), r"{\1}"),      # Flask <int:id>
              (re.compile(r"\{([A-Za-z_]\w*)[^}]*\}"), r"{\1}"),     # {id:regex}, {id?}
              (re.compile(r":([A-Za-z_]\w*)\??(\([^)]*\))?"), r"{\1}"),  # Express :id, :id?
              (re.compile(r"\*([A-Za-z_]\w*)"), r"{\1}")]            # gin *filepath


def norm_path(path):
    """Normalize a route path: leading slash, {param} placeholders, no duplicate or trailing slash."""
    p = (path or "").strip()
    if p in ("*", "/*"):
        return "*"
    for rx, rep in _PARAM_RXS:
        p = rx.sub(rep, p)
    p = "/" + p.lstrip("/")
    p = re.sub(r"/{2,}", "/", p)
    if len(p) > 1:
        p = p.rstrip("/")
    return p


def join_path(*parts):
    out = ""
    for part in parts:
        if not part or part == "/":
            continue
        out = out.rstrip("/") + "/" + str(part).lstrip("/")
    return out or "/"


def sorted_by_id(xs):
    return sorted(xs, key=lambda x: x["id"])
