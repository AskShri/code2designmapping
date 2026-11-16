"""Regressions from the second review round (docs/review-findings.md, round 2)."""
import os
from conftest import ROOT
from helpers import model, by_route
from code2design.model import classify_control

FX = os.path.join(ROOT, "tests", "fixtures2")


def test_express_middleware_in_mount_call_guards_the_router():
    r = by_route(model(os.path.join(FX, "express_mount_mw")))
    assert "authn" in r["GET /api/items"][1]          # app.use('/api', requireAuth, router); auth.js is not a router


def test_flask_before_request_guard_and_csrf_exempt():
    r = by_route(model(os.path.join(FX, "flask_before_request")))
    assert r["GET /admin/users"][1] == ["authn"]
    assert r["GET /open"][1] == []                    # @csrf_exempt is not a CSRF control
    assert classify_control("csrf_exempt") is None


def test_gin_group_middleware():
    r = by_route(model(os.path.join(FX, "gin_group_mw")))
    assert r["GET /api/me"][1] == ["authn"] and r["GET /ping"][1] == []


def test_malformed_overrides_do_not_crash():
    import copy
    from code2design import overrides as ov
    ir = copy.deepcopy(model(os.path.join(FX, "gin_group_mw")))
    out = ov.apply(ir, ({"rename": ["oops", {"target": ["a"], "to": "b"}], "suppress": "x"}, []), "o.yaml")
    assert any("malformed" in g["detail"] for g in out["gaps"])
