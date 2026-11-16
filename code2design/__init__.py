"""code2design: evidence-backed data flow diagrams from source code.

Pipeline: index (tree-sitter) -> detectors (validated facts) -> call graph -> synth (IR) ->
overrides -> lint -> render / export. Deterministic: every collection is sorted by stable ID and
no ID depends on a line number, a timestamp or a hash seed.
"""
__version__ = "0.5.1"
IR_VERSION = "0.2"
