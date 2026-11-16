"""Detectors: (RepoIndex, FactStore) -> facts. Order is fixed so fact IDs are deterministic."""
from . import config, js, nest, py, go, java, csharp

ALL = [config.run, js.run, nest.run, py.run, go.run, java.run, csharp.run]
