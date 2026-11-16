"""The pipeline as one function, used by the CLI, the evaluation harness and the tests."""
from .index import RepoIndex
from .callgraph import ClassIndex, CallGraph
from .model import FactStore
from .detectors import ALL
from .synth import Synth


def analyze(root, name=None, include=None, exclude=None):
    """-> (index, facts, call graph, IR dict). Deterministic for a given tree."""
    idx = RepoIndex(root, include=include, exclude=exclude)
    idx.classes = ClassIndex(idx)
    facts = FactStore()
    for det in ALL:
        det(idx, facts)
    edges = [(f["file"], f["line"], f["target_file"], f["target_symbol"]) for f in facts.by_kind("call_edge")]
    cg = CallGraph(idx, idx.classes, extra_edges=edges)
    idx.callgraph = cg
    ir = Synth(idx, facts, cg, name=name, scope={"include": include, "exclude": exclude}).build()
    return idx, facts, cg, ir
