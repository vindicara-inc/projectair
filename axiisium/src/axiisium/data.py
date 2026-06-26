"""Synthetic multimodal AML cohort for the Stage 0 feasibility skeleton.

This stands in for the real aligned cohort so the pipeline + trust layer run with zero
data dependency. The shapes mirror the real modalities Axiisium fuses:

  - pathology   : feature vector from a bone-marrow whole-slide image
                  PRODUCTION: MONAI + a pathology foundation model (Virchow / UNI) embedding
  - flow        : flow-cytometry immunophenotype features
                  PRODUCTION: encoded FCS gating / learned flow embedding
  - cytogenetics: karyotype / FISH indicator features
  - clinical    : age, blast %, labs

Prediction target for the skeleton: NPM1 mutation status (binary). NPM1 is a real,
clinically decisive AML marker (ELN 2022 favorable-risk when without adverse FLT3-ITD).
The synthetic data embeds a learnable signal across modalities so the AUC is meaningful
as a *pipeline* check — it says nothing about real-world accuracy. Stage 2 answers that
on paired image+genomic data.
"""
from __future__ import annotations

import numpy as np

MODALITY_DIMS = {
    "pathology": 32,
    "flow": 16,
    "cytogenetics": 8,
    "clinical": 4,
}


def make_cohort(
    n: int = 1200,
    seed: int = 7,
    signal: float = 0.9,
) -> tuple[dict[str, np.ndarray], np.ndarray]:
    """Return ({modality: X[n, dim]}, y[n]) with a cross-modal learnable signal.

    Each modality carries a partial, noisy projection of the latent mutation state, so
    fusing modalities should beat any single modality — the property Axiisium depends on.
    """
    rng = np.random.default_rng(seed)
    y = rng.integers(0, 2, size=n).astype(np.float64)  # latent NPM1 status

    modalities: dict[str, np.ndarray] = {}
    for name, dim in MODALITY_DIMS.items():
        # Each modality gets its own random projection of the label plus noise.
        # Pathology carries the strongest signal (mirrors morphology being decisive),
        # cytogenetics the weakest (often normal-karyotype in NPM1-mutated AML).
        strength = {"pathology": 1.0, "flow": 0.7, "cytogenetics": 0.3, "clinical": 0.5}[name]
        direction = rng.standard_normal(dim)
        direction /= np.linalg.norm(direction)
        noise = rng.standard_normal((n, dim))
        x = signal * strength * np.outer(y - 0.5, direction) + noise
        modalities[name] = x.astype(np.float64)
    return modalities, y


def train_test_split(
    modalities: dict[str, np.ndarray],
    y: np.ndarray,
    frac: float = 0.75,
    seed: int = 7,
) -> tuple[dict[str, np.ndarray], np.ndarray, dict[str, np.ndarray], np.ndarray]:
    rng = np.random.default_rng(seed)
    n = len(y)
    idx = rng.permutation(n)
    cut = int(n * frac)
    tr, te = idx[:cut], idx[cut:]
    train_mods = {k: v[tr] for k, v in modalities.items()}
    test_mods = {k: v[te] for k, v in modalities.items()}
    return train_mods, y[tr], test_mods, y[te]
