"""IDs, evidence, vocabularies and data-class rules shared by every stage."""
import base64, hashlib, json, re
from collections import OrderedDict


def sid(kind, *identity):
    h = hashlib.sha256(json.dumps([kind, *identity]).encode()).digest()
    return f"{kind}:{base64.b32encode(h).decode().lower()[:10]}"


def span_hash(lines):
    return "sha256:" + hashlib.sha256(" ".join(" ".join(l.split()) for l in lines).encode()).hexdigest()


def evidence(sf, start, end, detector, symbol=None, fact_id=None):
    """Evidence span on a SourceFile (1-based inclusive lines)."""
    e = OrderedDict(path=sf.path, start_line=start, end_line=end, detector=detector,
                    content_hash=span_hash(sf.lines[start - 1:end]))
    if symbol: e["symbol"] = symbol
    if fact_id: e["fact_id"] = fact_id
    return e


class FactStore:
    def __init__(self):
        self.facts = []

    def add(self, kind, detector, ev, **attrs):
        fid = f"fact_{len(self.facts) + 1:04d}"
        f = OrderedDict(id=fid, kind=kind, detector=detector)
        f.update(attrs)
        f["evidence"] = ev
        self.facts.append(f)
        return fid

    def by_kind(self, kind):
        return [f for f in self.facts if f["kind"] == kind]


# ---- vocabularies (mirror schema/dfd-ir.schema.json)
PROTOCOLS = {"http", "https", "grpc", "graphql", "websocket", "amqp", "kafka", "sqs", "pubsub", "sql", "redis", "mongo", "file", "s3", "smtp", "cli", "in_process", "unknown"}
TECH_PROTOCOL = {"postgres": "sql", "mysql": "sql", "sqlite": "sql", "mssql": "sql", "mongodb": "mongo", "dynamodb": "https", "redis": "redis", "memcached": "unknown", "elasticsearch": "https", "kafka": "kafka", "rabbitmq": "amqp", "sqs": "sqs", "s3": "s3", "gcs": "https", "filesystem": "file", "unknown": "unknown"}

DATA_CLASS_RULES = [
    (re.compile(r"(password|passwd|pwd|secret|api_?key|access_?token|refresh_?token|private_?key|credential|otp|mfa)", re.I), "credential"),
    (re.compile(r"(card|cvv|cvc|iban|bic|swift|account_?number|routing|amount|price|total|balance|salary|invoice|payment|charge|tax_?id|vat)", re.I), "financial"),
    (re.compile(r"(diagnos|medical|health|patient|prescription|allerg|blood)", re.I), "health"),
    (re.compile(r"(email|e_mail|phone|mobile|address|street|zip|postal|first_?name|last_?name|full_?name|surname|birth|dob|ssn|passport|national_?id|gender|ip_?address|geo|lat|lng|longitude|latitude|avatar|photo|username|user_?name)", re.I), "pii"),
]


def classify_field(name):
    for rx, cls in DATA_CLASS_RULES:
        if rx.search(name):
            return cls
    return "internal"


SECRET_ENV_RX = re.compile(r"(SECRET|PASSWORD|PASSWD|PRIVATE_KEY|API_KEY|APIKEY|TOKEN|CLIENT_SECRET|ACCESS_KEY|DSN|CONNECTION_STRING|_URI$|_URL$|CREDENTIAL)", re.I)
PASSWORD_KEY_RX = re.compile(r"(PASSWORD|PASSWD|SECRET|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY|TOKEN)", re.I)

# control classification by middleware / decorator / identifier name
CONTROL_NAME_RULES = [
    (re.compile(r"(rate_?limit|throttle|slow_?down|limiter)", re.I), "rate_limit"),
    (re.compile(r"(csrf|csurf|xsrf|lusca)", re.I), "csrf"),
    (re.compile(r"(^cors$|cors\(|CORSMiddleware|flask_cors)", re.I), "cors"),
    (re.compile(r"(authori[sz]|permission|role|can_|is_?admin|acl|rbac|scope|grant|has_?access|owner_?only)", re.I), "authz"),
    (re.compile(r"(auth|jwt|passport|session|login_?required|require_?user|protect|verify_?token|is_?authenticated|bearer|oauth|current_?user|get_?user|authenticate|ensure_?logged)", re.I), "authn"),
    (re.compile(r"(validat|joi|zod|yup|celebrate|schema|sanitiz|check\(|body\(|param\(|query\(|helmet|hpp|xss|mongo_?sanitize|content_?security)", re.I), "input_validation"),
    (re.compile(r"(audit|morgan|winston|pino|log_?request)", re.I), "audit_log"),
]


PLUMBING_RX = re.compile(r"^(passport\.initialize|passport\.session|session|express_?session|cookie_?session|cookie_?parser|body_?parser(\.\w+)?|express\.json|express\.urlencoded|express\.static|compression|flash|morgan(\.\w+)?|errorhandler|errorHandler|methodOverride|favicon|serve_?static)$", re.I)


def classify_control(name):
    """Control kind for a middleware/decorator name, or None. Session and parser plumbing is not a
    control: passport.initialize enforces nothing by itself; only an explicit guard is authn."""
    if PLUMBING_RX.search(name):
        return "audit_log" if name.lower().startswith("morgan") else None
    for rx, kind in CONTROL_NAME_RULES:
        if rx.search(name):
            return kind
    return None


LOCAL_HOSTS = ("localhost", "127.0.0.1", "0.0.0.0", "::1", "::", "[::]", "[::1]")


def sorted_by_id(xs):
    return sorted(xs, key=lambda x: x["id"])
