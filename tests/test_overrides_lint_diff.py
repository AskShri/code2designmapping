import copy, datetime, os
from conftest import FIXTURES, EXAMPLE
from helpers import model
from code2design import overrides as ov
from code2design.lint import lint
from code2design.diff import markdown


def apply(ir, doc):
    return ov.apply(copy.deepcopy(ir), (doc, []), "overrides.yaml", today=datetime.date(2026, 1, 1))


def test_suppress_removes_every_reference():
    ir = model(EXAMPLE)
    target = next(s for s in ir["stores"] if s["name"].startswith("Redis"))
    out = apply(ir, {"suppress": [{"target": target["name"], "reason": "test", "author": "a"}]})
    assert target["id"] not in {s["id"] for s in out["stores"]}
    assert not [r for r in lint(out) if r[0] == "error"]
    assert all(target["id"] not in e["reaches"] for e in out["entry_points"])


def test_suppress_entry_point_removes_its_handler_and_control_links():
    ir = model(EXAMPLE)
    out = apply(ir, {"suppress": [{"target": "POST /orders", "author": "a"}]})
    assert [f"{e['method']} {e['path']}" for e in out["entry_points"]] == ["GET /orders/{id}"]
    assert not [r for r in lint(out) if r[0] == "error"]


def test_rename_changes_the_displayed_name_and_keeps_the_code_name():
    ir = model(EXAMPLE)
    out = apply(ir, {"rename": [{"target": "Stripe API", "to": "Stripe Payments", "author": "a"}]})
    e = next(e for e in out["entities"] if e.get("code_name") == "Stripe API")
    assert e["name"] == "Stripe Payments" and e["origin"] == "declared"


def test_set_data_class_on_a_flow_without_payload():
    ir = model(EXAMPLE)
    flow = next(f for f in ir["flows"] if not f.get("payload"))
    out = apply(ir, {"set_data_class": [{"target": flow["id"], "value": "secret", "author": "a"}]})
    assert next(f for f in out["flows"] if f["id"] == flow["id"])["payload"]["data_classes"] == ["secret"]


def test_add_boundary_recomputes_crossings():
    ir = model(EXAMPLE)
    out = apply(ir, {"add_boundary": [{"name": "payments zone", "kind": "network_segment", "contains": ["stripe"], "author": "a"}]})
    bid = next(b["id"] for b in out["boundaries"] if b["name"] == "payments zone")
    assert any(bid in f["crosses_boundary"] for f in out["flows"])


def test_missing_targets_and_expiry_become_gaps():
    ir = model(EXAMPLE)
    out = apply(ir, {"set_attribute": [{"target": "nope", "encryption": "tls", "author": "a"},
                                       {"target": "Postgres: orders", "encryption_at_rest": "yes", "author": "a", "expires": "2025-01-01"}]})
    kinds = [g["kind"] for g in out["gaps"]]
    assert kinds.count("override_target_missing") == 2


def test_lint_reports_dangling_references():
    ir = copy.deepcopy(model(EXAMPLE))
    ir["entry_points"][0]["controls"].append("ctl:aaaaaaaaaa")
    assert any(r[1] == "dangling-reference" for r in lint(ir))


def test_diff_reports_new_route_and_control_change():
    base = model(os.path.join(FIXTURES, "nest_app"))
    head = copy.deepcopy(base)
    guarded = next(e for e in head["entry_points"] if e["controls"])
    guarded["controls"] = []
    extra = copy.deepcopy(guarded)
    extra["id"], extra["path"] = "ep:aaaaaaaaaa", "/api/cats/{id}"
    head["entry_points"].append(extra)
    text = markdown(base, head)
    assert "### Changed (1)" in text and "controls -AuthMiddleware" in text
    assert "### New (1)" in text and "/api/cats/{id}" in text
    assert "Unchanged:" in text
