"""Multimodal screening models + the trial screener.

MutationFusionModel : late-fusion predictor for ONE mutation (reuses Stage 0/2 pattern).
MultiMutationModel  : a panel of them, sharing one standardization, with a version hash
                      so the exact model is bound into the screening ledger.
TrialScreener       : ranks candidates by eligibility, banding by confidence into
                      auto-eligible / confirm-with-NGS / auto-exclude, and computes the
                      enrollment economics (NGS tests saved, enrichment factor).
"""
from __future__ import annotations

import numpy as np

from ..model import ModalityHead, _sigmoid
from ..trust import sha256_array
from .criteria import TrialCriteria, eligibility_score


class MutationFusionModel:
    def __init__(self) -> None:
        self.heads: dict[str, ModalityHead] = {}
        self.fusion: ModalityHead | None = None

    def fit(self, mods: dict[str, np.ndarray], y: np.ndarray) -> None:
        logits = []
        for name, x in mods.items():
            h = ModalityHead(dim=x.shape[1], lr=0.2, l2=1e-2, epochs=500)
            h.fit(x, y)
            self.heads[name] = h
            logits.append(h.logit(x))
        z = np.column_stack(logits)
        self.fusion = ModalityHead(dim=z.shape[1], lr=0.2, l2=1e-2, epochs=500)
        self.fusion.fit(z, y)

    def proba(self, mods: dict[str, np.ndarray]) -> np.ndarray:
        logits = [self.heads[n].logit(x) for n, x in mods.items()]
        return _sigmoid(self.fusion.logit(np.column_stack(logits)))

    def blob(self) -> np.ndarray:
        parts = [self.fusion.w, [self.fusion.b]]
        for n in sorted(self.heads):
            parts += [self.heads[n].w, [self.heads[n].b]]
        return np.concatenate([np.atleast_1d(p) for p in parts])


class MultiMutationModel:
    def __init__(self) -> None:
        self.stats: dict[str, tuple[np.ndarray, np.ndarray]] = {}
        self.models: dict[str, MutationFusionModel] = {}

    def _standardize(self, mods):
        return {n: (x - self.stats[n][0]) / self.stats[n][1] for n, x in mods.items()}

    def fit(self, mods, Y, mutations: list[str], targets: list[str]) -> None:
        for n, x in mods.items():
            self.stats[n] = (x.mean(0), x.std(0) + 1e-8)
        smods = self._standardize(mods)
        for m in targets:
            model = MutationFusionModel()
            model.fit(smods, Y[:, mutations.index(m)])
            self.models[m] = model

    def proba(self, mods) -> dict[str, np.ndarray]:
        smods = self._standardize(mods)
        return {m: self.models[m].proba(smods) for m in self.models}

    def version_hash(self) -> str:
        return sha256_array(np.concatenate([self.models[m].blob() for m in sorted(self.models)]))


class TrialScreener:
    def __init__(self, model: MultiMutationModel, criteria: TrialCriteria,
                 confirm_low: float = 0.15, confirm_high: float = 0.85) -> None:
        self.model = model
        self.criteria = criteria
        self.confirm_low = confirm_low
        self.confirm_high = confirm_high

    def screen(self, mods, age: np.ndarray, blast: np.ndarray) -> list[dict]:
        """Return per-candidate screening rows, ranked by eligibility score (desc)."""
        probs = self.model.proba(mods)
        n = len(age)
        rows = []
        for i in range(n):
            passes = self.criteria.passes_hard_filters(age[i], blast[i])
            pmap = {m: float(probs[m][i]) for m in probs}
            score = eligibility_score(pmap, self.criteria) if passes else 0.0
            if not passes:
                band = "excluded_hard_filter"
            elif score >= self.confirm_high:
                band = "likely_eligible"
            elif score <= self.confirm_low:
                band = "likely_ineligible"
            else:
                band = "confirm_with_ngs"
            rows.append({"candidate": i, "passes_filters": passes, "mutation_probs": pmap,
                         "eligibility_score": round(score, 3), "band": band})
        rows.sort(key=lambda r: r["eligibility_score"], reverse=True)
        return rows


def enrollment_economics(rows: list[dict], truly_eligible: np.ndarray, target: int) -> dict:
    """Compare naive (sequence everyone) vs Axiisium (sequence in rank order until filled)."""
    base_rate = float(truly_eligible.mean())
    n = len(rows)
    # Axiisium: walk ranked candidates, "sequence" each, stop when target eligible found.
    sequenced = 0
    enrolled = 0
    for r in rows:
        if r["band"] == "excluded_hard_filter":
            continue
        sequenced += 1
        if truly_eligible[r["candidate"]]:
            enrolled += 1
        if enrolled >= target:
            break
    # naive: to find `target` eligible at the base rate you sequence ~ target/base_rate
    naive_seq = int(round(target / base_rate)) if base_rate > 0 else n
    topk_rate = enrolled / sequenced if sequenced else 0.0
    return {
        "trial_target": target,
        "base_eligible_rate": round(base_rate, 3),
        "axiisium_sequenced_to_fill": sequenced,
        "axiisium_enrolled": enrolled,
        "naive_sequenced_to_fill": naive_seq,
        "ngs_tests_saved": max(0, naive_seq - sequenced),
        "enrichment_factor": round(topk_rate / base_rate, 2) if base_rate > 0 else None,
    }
