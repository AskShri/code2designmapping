from code2design.model import classify_field, classify_control, norm_path
from code2design.detectors.go import _env_for
from code2design.routing import Routing


def test_classify_field_tokens():
    assert classify_field("email") == "pii"
    assert classify_field("customerEmail") == "pii"
    assert classify_field("cardToken") == "financial"            # financial before credential
    assert classify_field("password_hash") == "credential"
    assert classify_field("avatar") != "financial"               # "avatar" does not contain the token "vat"
    assert classify_field("template") == "internal"              # not "lat"
    assert classify_field("JWT_VERIFY_EMAIL_EXPIRATION_MINUTES") == "internal"


def test_classify_control_names():
    assert classify_control("requireJwt") == "authn"
    assert classify_control("PreAuthorize") == "authz"
    assert classify_control("authLimiter") == "rate_limit"
    assert classify_control("helmet") == "security_headers"
    assert classify_control("bodyParser.json") is None           # plumbing is not a control
    assert classify_control("passport.initialize") is None
    assert classify_control("auth.optional") is None              # optional auth does not block


def test_norm_path():
    assert norm_path("/a/:id/") == "/a/{id}"
    assert norm_path("/a/<int:id>") == "/a/{id}"
    assert norm_path("") == "/"


def test_go_env_for_terminates_on_cycles():
    assert _env_for("dial(&c.fooAddr, cfg.fooAddr)", "fooAddr") is None
    assert _env_for('mustMapEnv(&svc.cartAddr, "CART_ADDR")', "svc.cartAddr") == "CART_ADDR"


def test_for_routes_selection():
    ep = {"router": "CatsController", "method": "POST", "file": "src/cats.ts", "path": "", "evidence": [{"start_line": 1}]}
    c = {"routes": [("POST", "cats/:id")], "router_names": []}
    assert Routing._selected(c, ep, "/api/cats/{id}", "/api")
    assert not Routing._selected(c, dict(ep, method="GET"), "/api/cats/{id}", "/api")
    assert Routing._selected({"routes": [("ANY", "*")]}, ep, "/anything", "")
    assert Routing._selected({"routes": [], "router_names": ["CatsController"]}, ep, "/x", "")
