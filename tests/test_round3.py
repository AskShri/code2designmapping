"""Coverage added in round 3 (docs/review-findings.md)."""
import os
from conftest import ROOT
from helpers import model, by_route

FX = os.path.join(ROOT, "tests", "fixtures2")


def test_drf_viewsets_views_and_permissions():
    r = by_route(model(os.path.join(FX, "drf_app")))
    assert {"GET /api/posts", "POST /api/posts", "GET /api/posts/{pk}", "PUT /api/posts/{pk}", "PATCH /api/posts/{pk}",
            "DELETE /api/posts/{pk}", "POST /api/posts/{pk}/publish", "GET /api/health", "GET /api/stats"} == set(r)
    assert r["GET /api/posts"][1] == ["authn"]                  # DEFAULT_PERMISSION_CLASSES
    assert r["GET /api/health"][1] == []                        # AllowAny
    assert r["GET /api/stats"][1] == ["authn", "authz"]         # IsAdminUser on top of the default
    assert all(v[2] == ["Postgres: Post"] for k, v in r.items() if "posts" in k)


def test_nextjs_file_system_routes():
    r = by_route(model(os.path.join(FX, "next_app")))
    assert set(r) == {"ANY /api/users/{id}", "GET /orders/{id}", "DELETE /orders/{id}"}   # (shop) is a route group
    assert r["GET /orders/{id}"][2] == ["SQL database: order"]


def test_imported_http_client_named_api_is_not_a_router(tmp_path):
    (tmp_path / "package.json").write_text('{"name": "x", "dependencies": {"express": "4", "axios": "1"}}')
    (tmp_path / "api.js").write_text('const axios = require("axios");\nmodule.exports = axios.create({ baseURL: "https://billing.example.com" });\n')
    (tmp_path / "server.js").write_text('const express = require("express");\nconst api = require("./api");\nconst app = express();\n'
                                        'app.get("/pay", async (req, res) => { await api.post("/charges", req.body); res.end(); });\napp.listen(3000);\n')
    from code2design.pipeline import analyze
    r = by_route(analyze(str(tmp_path))[3])
    assert set(r) == {"GET /pay"}


def test_chi_route_group_closures_and_with():
    r = by_route(model(os.path.join(FX, "chi_app")))
    assert set(r) == {"GET /health", "GET /articles", "POST /articles", "DELETE /articles/{id}", "GET /public"}
    assert r["POST /articles"][1] == ["authn"]          # Use inside Group applies to that group only
    assert r["GET /public"][1] == [] and r["GET /articles"][1] == []
    assert r["DELETE /articles/{id}"][1] == ["authz"]   # r.With(AdminOnly)


def test_spring_security_rules_first_match_wins():
    r = by_route(model(os.path.join(FX, "spring_sec")))
    assert r["GET /products/{id}"][1] == []             # permitAll for GET /products/**
    assert r["POST /products"][1] == ["authn"]          # falls through to anyRequest().authenticated()
    assert r["DELETE /admin/users/{id}"][1] == ["authz"]


def test_minimal_api_group_authorization_across_statements():
    r = by_route(model(os.path.join(FX, "minimal_api")))
    assert r["GET /orders/{id}"][1] == ["authn"] and r["DELETE /admin/users/{id}"][1] == ["authn"]
    assert r["GET /public/ping"][1] == []


def test_go_wrapper_middleware():
    r = by_route(model(os.path.join(FX, "go_wrap")))
    assert r["GET /me"][1] == ["authn"] and r["GET /ping"][1] == []


def test_go_calls_through_struct_fields():
    r = by_route(model(os.path.join(FX, "go_layers")))
    assert r["GET /me"][2] == ["Postgres: users"]


def test_fastify_plugin_routes_and_prehandler():
    r = by_route(model(os.path.join(FX, "fastify_app")))
    assert set(r) == {"GET /notes", "POST /notes"}
    assert r["POST /notes"][1] == ["authn"] and r["GET /notes"][1] == []
    assert r["GET /notes"][2] == ["Postgres: notes"]
