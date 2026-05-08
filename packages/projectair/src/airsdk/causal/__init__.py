"""Project AIR Layer 2: causal reasoning over an AgDR chain.

Layer 1 (anchoring) lets a verifier prove what happened. Layer 2 lets
an analyst explain *why* it happened. We do that by walking an AgDR
chain, inferring step-to-step dependencies, and surfacing the load-
bearing records as a narrowed evidence excerpt.

Counterfactual replay (Q4 2026 per the v1 spec) is out of scope for
this release; the foundation it will build on (the causal graph) is in
this module.
"""
from __future__ import annotations

from airsdk.causal.explain import (
    Explanation,
    explain_finding,
    explain_step,
)
from airsdk.causal.inference import build_causal_graph
from airsdk.causal.types import CausalEdge, CausalGraph, CausalNode, EdgeKind

__all__ = [
    "CausalEdge",
    "CausalGraph",
    "CausalNode",
    "EdgeKind",
    "Explanation",
    "build_causal_graph",
    "explain_finding",
    "explain_step",
]
