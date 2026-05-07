"""Types for Layer 2 causal reasoning over AgDR chains.

Layer 1 lets a verifier prove what happened. Layer 2 lets an analyst
explain *why* it happened. We do that by inferring step-to-step
dependencies from the chain and surfacing the load-bearing records as a
narrowed evidence excerpt.

Edge kinds split into hard (derived from explicit fields) and soft
(heuristic content match). Hard edges carry confidence 1.0; soft edges
carry a real-valued confidence the CLI displays. A forensic tool that
confidently asserts "X caused Y" because of a substring false positive
destroys trust faster than Layer 1 can build it; the kind + confidence
together let an analyst say "I will rely on this hard edge in a report,
I will note this soft edge as supporting context".
"""
from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class EdgeKind(StrEnum):
    # Hard edges: derived from explicit AgDR fields. Confidence 1.0.
    CHAIN_LINK = "chain_link"          # prev_hash points at the immediately prior record
    LLM_PAIR = "llm_pair"              # LLM_END follows the LLM_START it answered
    TOOL_PAIR = "tool_pair"            # TOOL_END follows the TOOL_START that invoked it
    LLM_DECISION = "llm_decision"      # LLM_END decided the next TOOL_START (no LLM_END between)
    AGENT_MESSAGE = "agent_message"    # explicit source -> target message routing

    # Soft edges: inferred by content match. Confidence < 1.0.
    OUTPUT_REUSE = "output_reuse"      # text from a prior step appears in a later step's input


class CausalNode(BaseModel):
    """One step in the chain, with a numeric ordinal for human-readable display.

    The ordinal (0-based) matches the position of the record in the
    JSONL log; the step_id (UUIDv7) matches the AgDR record identity.
    Both are useful: ordinal for display ("step 6"), step_id for
    addressing.
    """

    model_config = ConfigDict(extra="forbid")

    ordinal: int
    step_id: str
    kind: str
    summary: str  # one-line human description, derived from payload


class CausalEdge(BaseModel):
    """A directed cause -> effect dependency between two nodes.

    Hard edges (kind in CHAIN_LINK / LLM_PAIR / TOOL_PAIR / AGENT_MESSAGE)
    have ``confidence == 1.0`` and a brief evidence string. Soft edges
    (OUTPUT_REUSE) have ``0 < confidence < 1`` and an evidence string
    that quotes the matched bytes.
    """

    model_config = ConfigDict(extra="forbid")

    from_ordinal: int
    to_ordinal: int
    kind: EdgeKind
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str = ""

    @property
    def is_hard(self) -> bool:
        return self.kind != EdgeKind.OUTPUT_REUSE


class CausalGraph(BaseModel):
    """Directed acyclic graph of causal dependencies inferred from a chain.

    The graph is sparse: most steps only connect to their immediate
    predecessor (CHAIN_LINK) plus any pair (LLM_PAIR / TOOL_PAIR) and
    any soft edges from earlier records whose output influenced them.
    """

    model_config = ConfigDict(extra="forbid")

    nodes: list[CausalNode]
    edges: list[CausalEdge]

    def node(self, ordinal: int) -> CausalNode:
        return self.nodes[ordinal]

    def incoming(self, ordinal: int) -> list[CausalEdge]:
        return [e for e in self.edges if e.to_ordinal == ordinal]

    def outgoing(self, ordinal: int) -> list[CausalEdge]:
        return [e for e in self.edges if e.from_ordinal == ordinal]

    def find_ordinal(self, step_id: str) -> int | None:
        for n in self.nodes:
            if n.step_id == step_id:
                return n.ordinal
        return None
