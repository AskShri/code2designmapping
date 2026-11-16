"""One routing model for every framework.

Detectors describe routing with four fact kinds:
  router        a router object (file, local): an app, an Express Router, a Flask Blueprint, a FastAPI
                APIRouter, a gin RouterGroup, a controller class. `root` marks objects that serve
                requests without being mounted (apps, auto-discovered controllers).
  router_mount  parent router --prefix--> child router (child_local None = "the router(s) that file exports")
  global_prefix a prefix applied to every route of the service that file belongs to
  control       scope "router" (on a router object, optionally path-scoped and order-sensitive),
                scope "route" (listed on the entry point) or scope "service"
This module turns those into, for each entry point, its full path and the controls that guard it.
"""
import re
from .model import join_path, norm_path


class Routing:
    def __init__(self, facts, service_of):
        self.service_of = service_of
        self.routers = {}
        for r in facts.by_kind("router"):
            self.routers.setdefault((r["file"], r["local"]), r)
        self.mounts = sorted(facts.by_kind("router_mount"), key=lambda m: (m["file"], m["evidence"][0]["start_line"], m["id"]))
        self.global_prefix = {}
        for g in sorted(facts.by_kind("global_prefix"), key=lambda g: g["id"]):
            self.global_prefix.setdefault(service_of(g["file"]), g["prefix"])
        self.router_controls = {}
        self.service_controls = {}
        for c in facts.by_kind("control"):
            if c["scope"] == "router":
                self.router_controls.setdefault((c.get("router_file") or c["file"], c.get("router")), []).append(c)
            elif c["scope"] == "service":
                self.service_controls.setdefault(service_of(c["file"]), []).append(c)

    def _mounts_of(self, key):
        exact = [m for m in self.mounts if m["child_file"] == key[0] and m["child_local"] == key[1] and (m["file"], m["parent"]) != key]
        if exact:
            return exact
        return [m for m in self.mounts if m["child_file"] == key[0] and m["child_local"] is None and (m["file"], m["parent"]) != key]

    def _chain(self, key, before_line, depth, seen):
        """-> (base prefix of `key`, [(router key, line before which controls apply, base prefix)], rooted)."""
        r = self.routers.get(key)
        own = (r or {}).get("own_prefix") or ""
        if (r and r["root"]) or depth > 8 or key in seen:
            base = join_path(self.global_prefix.get(self.service_of(key[0]), ""), own)
            return base, [(key, before_line, base)], bool(r and r["root"])
        ms = self._mounts_of(key)
        if not ms:
            base = join_path(self.global_prefix.get(self.service_of(key[0]), ""), own)
            return base, [(key, before_line, base)], False
        m = ms[0]
        pbase, pctx, rooted = self._chain((m["file"], m["parent"]), m["evidence"][0]["start_line"], depth + 1, seen | {key})
        base = join_path(pbase, m["prefix"], own)
        return base, pctx + [(key, before_line, base)], rooted

    def resolve(self, ep):
        """-> (full normalized path, [control facts], rooted) for an entry_point fact."""
        key = (ep.get("router_file") or ep["file"], ep["router"])
        line = ep["evidence"][0]["start_line"]
        base, ctx, rooted = self._chain(key, line, 0, frozenset())
        full = norm_path(join_path(base, ep["path"])) if ep["path"] != "*" else "*"
        out = []
        for rkey, before, rbase in ctx:
            for c in self.router_controls.get(rkey, ()):
                if c.get("ordered", True) and c["evidence"][0]["start_line"] >= before:
                    continue
                if c.get("path_prefix"):
                    want = norm_path(join_path(rbase, c["path_prefix"]))
                    if not (full == want or full.startswith(want.rstrip("/") + "/")):
                        continue
                out.append(c)
        gp = self.global_prefix.get(self.service_of(ep["file"]), "")
        for c in self.service_controls.get(self.service_of(ep["file"]), ()):
            if c.get("path_prefix") and not full.startswith(norm_path(c["path_prefix"])):
                continue
            if ("routes" in c or "router_names" in c) and not self._selected(c, ep, full, gp):
                continue
            out.append(c)
        return full, out, rooted

    @staticmethod
    def _selected(c, ep, full, gp):
        """Middleware bound to a route list (Nest forRoutes): by controller class, or by method and path
        pattern relative to the global prefix; '*' segments match anything."""
        if ep["router"] in (c.get("router_names") or ()):
            return True
        for method, pattern in c.get("routes") or ():
            if method not in ("ANY", ep["method"]):
                continue
            target = re.sub(r"\{[^}]*\}", "{}", full)
            for cand in sorted({norm_path(join_path(gp, pattern)), norm_path(pattern)}):
                if pattern.strip("/") in ("", "*"):
                    return True
                rx = "^" + re.escape(re.sub(r"\{[^}]*\}", "{}", cand)).replace(r"\*", ".*").replace(r"\{\}", "[^/]+") + "$"
                if re.match(rx, target):
                    return True
        return False
