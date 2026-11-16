import functools
from code2design.pipeline import analyze


@functools.lru_cache(maxsize=None)
def model(path):
    return analyze(path)[3]


def by_route(ir):
    """'METHOD /path' -> (entry point, control kinds, reached element names)"""
    names = {n["id"]: n["name"] for k in ("processes", "entities", "stores") for n in ir[k]}
    ctl = {c["id"]: c for c in ir["controls"]}
    return {f"{e['method']} {e['path']}": (e, [ctl[c]["kind"] for c in e["controls"]], sorted(names[x] for x in e["reaches"])) for e in ir["entry_points"]}
