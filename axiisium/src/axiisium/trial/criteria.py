"""Trial eligibility criteria + scoring.

A sponsor's molecular inclusion/exclusion criteria for an AML trial. Mutations are
PREDICTED by the multimodal model (the expensive thing you'd otherwise sequence up front);
structured fields (age, blast %) are KNOWN from intake and applied as hard filters.

Example real criteria — a menin-inhibitor or FLT3-inhibitor trial:
  TrialCriteria("NPM1m FLT3-ITD-neg", require=["NPM1"], exclude=["FLT3_ITD"],
                min_age=18, min_blast_pct=20)
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TrialCriteria:
    name: str
    require_mutations: list[str] = field(default_factory=list)  # must be POSITIVE
    exclude_mutations: list[str] = field(default_factory=list)  # must be NEGATIVE
    min_age: int | None = None
    max_age: int | None = None
    min_blast_pct: float | None = None

    def passes_hard_filters(self, age: float, blast_pct: float) -> bool:
        if self.min_age is not None and age < self.min_age:
            return False
        if self.max_age is not None and age > self.max_age:
            return False
        if self.min_blast_pct is not None and blast_pct < self.min_blast_pct:
            return False
        return True

    def truly_eligible(self, age: float, blast_pct: float, true_muts: dict[str, int]) -> bool:
        """Ground-truth eligibility given confirmed mutation status (for economics eval)."""
        if not self.passes_hard_filters(age, blast_pct):
            return False
        if any(true_muts.get(m, 0) != 1 for m in self.require_mutations):
            return False
        if any(true_muts.get(m, 0) != 0 for m in self.exclude_mutations):
            return False
        return True


def eligibility_score(probs: dict[str, float], crit: TrialCriteria) -> float:
    """P(meets all molecular criteria) under an independence approximation.

    Conservative and interpretable: product of P(required positive) and P(excluded
    negative). Used only to RANK who to sequence first — never to enroll without
    confirmatory NGS.
    """
    p = 1.0
    for m in crit.require_mutations:
        p *= probs.get(m, 0.0)
    for m in crit.exclude_mutations:
        p *= 1.0 - probs.get(m, 0.0)
    return p
