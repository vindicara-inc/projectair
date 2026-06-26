"""Synthetic PAIRED AML patient cohort for Stage 2.

Stage 2 predicts genetic mutations from imaging + other modalities. The published result
this reproduces: Eckardt et al. (Leukemia 2022) predict NPM1 mutation from bone-marrow
morphology alone at AUROC 0.92. So morphology carries a strong NPM1 signal — encoded here.

Each synthetic patient has:
  - morphology : a cell-image embedding (prod: aggregated DinoBloom embeddings from Stage 1)
  - flow       : flow-cytometry immunophenotype features
  - clinical   : age, blast %, WBC, labs
and a MUTATION PANEL (ELN 2022-relevant): NPM1, FLT3_ITD, CEBPA, RUNX1, TP53, IDH2.

Per-mutation signal strength by modality mirrors clinical reality:
  - NPM1   : morphology-dominant (cup-like nuclei / chromatin pattern) -> reproduces Eckardt
  - FLT3_ITD: weak morphology, some flow/clinical (high WBC) signal
  - TP53   : clinical/cytogenetic-leaning (complex karyotype), weak morphology
The point Stage 2 must show: FUSING modalities beats image-only for the mutations where
morphology is weak — the entire reason Axiisium is multimodal, not an image classifier.

This is synthetic. Real signal strengths come from the paired cohort (see stage2/README.md).
"""
from __future__ import annotations

import numpy as np

MUTATIONS = ["NPM1", "FLT3_ITD", "CEBPA", "RUNX1", "TP53", "IDH2"]

MOD_DIMS = {"morphology": 64, "flow": 24, "clinical": 6}

# how strongly each modality encodes each mutation (0 = none). morphology row reflects
# the literature: strong for NPM1, weak for FLT3_ITD/TP53.
SIGNAL = {
    #            morph  flow  clin
    "NPM1":     (1.00, 0.30, 0.25),
    "FLT3_ITD": (0.20, 0.55, 0.50),
    "CEBPA":    (0.55, 0.35, 0.25),
    "RUNX1":    (0.35, 0.50, 0.30),
    "TP53":     (0.15, 0.30, 0.65),
    "IDH2":     (0.45, 0.40, 0.35),
}
PREVALENCE = {"NPM1": 0.30, "FLT3_ITD": 0.25, "CEBPA": 0.10, "RUNX1": 0.12, "TP53": 0.10, "IDH2": 0.12}


def make_paired_cohort(n: int = 1500, seed: int = 11):
    """Return ({modality: X[n,dim]}, Y[n, n_mut], MUTATIONS).

    Each mutation has a latent binary state; each modality observes a noisy projection of
    the mutations it encodes, with per-mutation strength from SIGNAL.
    """
    rng = np.random.default_rng(seed)
    n_mut = len(MUTATIONS)
    Y = np.zeros((n, n_mut))
    for j, m in enumerate(MUTATIONS):
        Y[:, j] = (rng.random(n) < PREVALENCE[m]).astype(np.float64)

    mods = {}
    mod_order = ["morphology", "flow", "clinical"]
    for k, name in enumerate(mod_order):
        dim = MOD_DIMS[name]
        X = rng.standard_normal((n, dim)) * 0.45  # base noise (calibrated: NPM1 image-only ~ lit 0.9)
        # add each mutation's contribution along its own random direction
        for j, m in enumerate(MUTATIONS):
            strength = SIGNAL[m][k]
            if strength == 0:
                continue
            direction = rng.standard_normal(dim)
            direction /= np.linalg.norm(direction)
            X += strength * np.outer(Y[:, j] - PREVALENCE[m], direction)
        mods[name] = X
    return mods, Y, MUTATIONS


def split(mods, Y, frac=0.75, seed=11):
    rng = np.random.default_rng(seed)
    n = len(Y)
    idx = rng.permutation(n)
    cut = int(n * frac)
    tr, te = idx[:cut], idx[cut:]
    return (
        {k: v[tr] for k, v in mods.items()}, Y[tr],
        {k: v[te] for k, v in mods.items()}, Y[te],
    )
