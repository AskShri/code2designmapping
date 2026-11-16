"""Each framework fixture is small enough to model by hand; the expected values are that hand model."""
import os
import pytest
from conftest import FIXTURES, EXAMPLE
from helpers import model, by_route


def fx(name):
    return os.path.join(FIXTURES, name)


def test_express_example():
    r = by_route(model(EXAMPLE))
    assert set(r) == {"GET /orders/{id}", "POST /orders"}
    ep, kinds, reaches = r["POST /orders"]
    assert kinds == ["authn", "rate_limit", "input_validation"]   # registration order, then the in-handler check
    assert reaches == ["Postgres: orders", "Redis: order:*", "Stripe API"]
    assert r["GET /orders/{id}"][2] == ["Postgres: orders", "Redis: order:*"]


def test_flask_blueprint_prefix_methods_and_auth():
    ir = model(fx("flask_app"))
    r = by_route(ir)
    assert {"GET /api/customers/{cid}", "DELETE /api/customers/{cid}", "POST /api/customers", "GET /api/health"} == set(r)
    assert r["GET /api/customers/{cid}"][1] == ["authn"] and r["DELETE /api/customers/{cid}"][1] == ["authn"]
    assert r["POST /api/customers"][1] == []
    assert r["POST /api/customers"][2] == ["Postgres: customers", "hooks.example.com"]
    assert r["GET /api/health"][0].get("infrastructure") is True
    # GET and DELETE share one handler function, so one handler process
    assert r["GET /api/customers/{cid}"][0]["process"] == r["DELETE /api/customers/{cid}"][0]["process"]
    store = next(s for s in ir["stores"] if s["name"] == "Postgres: customers")
    assert set(store["data_classes"]) >= {"pii", "financial"}
    assert [w["kind"] for w in ir["weaknesses"]] == ["unauthenticated_entry_point"]


def test_fastapi_dependency_aliases_and_sqlmodel():
    ir = model(fx("fastapi_app"))
    r = by_route(ir)
    assert set(r) == {"GET /api/v1/items", "GET /api/v1/items/public"}
    assert r["GET /api/v1/items"][1] == ["authn"]
    assert r["GET /api/v1/items/public"][1] == []
    assert r["GET /api/v1/items"][2] == ["Postgres: item"]       # engine from the psycopg dependency
    assert ir["provenance"]["generated_from"] == "items-api"      # name from pyproject.toml


def test_go_122_servemux_patterns():
    r = by_route(model(fx("go_mux")))
    assert set(r) == {"GET /items/{id}", "POST /items", "ANY /files/{path}"}
    assert all(v[2] == ["Postgres: items"] for v in r.values())


def test_spring_repository_to_table():
    r = by_route(model(fx("spring_app")))
    assert set(r) == {"GET /orders/{id}", "POST /orders"}
    assert r["GET /orders/{id}"][1] == ["authz"]
    assert r["POST /orders"][2] == ["Postgres: orders"]


def test_aspnet_controller_tokens_and_allow_anonymous():
    r = by_route(model(fx("aspnet_app")))
    assert set(r) == {"GET /api/Products", "GET /api/Products/{id}"}
    assert r["GET /api/Products/{id}"][1] == ["authn"]
    assert r["GET /api/Products"][1] == []                       # [AllowAnonymous] overrides the class [Authorize]
    assert r["GET /api/Products"][2] == ["Postgres: Product"]


def test_nest_global_prefix_and_for_routes_middleware():
    r = by_route(model(fx("nest_app")))
    assert set(r) == {"GET /api/cats", "POST /api/cats"}
    assert r["POST /api/cats"][1] == ["authn"]
    assert r["GET /api/cats"][1] == []                           # forRoutes binds POST only
    assert r["GET /api/cats"][2] == ["Postgres: cat"]


@pytest.mark.parametrize("name", ["flask_app", "fastapi_app", "go_mux", "spring_app", "aspnet_app", "nest_app"])
def test_every_element_has_evidence(name):
    ir = model(fx(name))
    for k in ("processes", "entities", "stores", "boundaries", "flows", "entry_points", "controls", "weaknesses", "assets", "threat_agents"):
        for n in ir[k]:
            assert n["evidence"], (k, n["id"])
            for e in n["evidence"]:
                assert e["path"] == "." or os.path.exists(os.path.join(fx(name), e["path"])), e
