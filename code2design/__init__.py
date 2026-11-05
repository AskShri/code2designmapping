"""code2design prototype: evidence-backed data flow diagrams from source code.

Pipeline: index (tree-sitter) -> detectors (facts) -> synth (IR) -> lint -> render.
Everything is deterministic: collections are sorted by stable ID before output.
"""
__version__ = "0.3.0-prototype"
