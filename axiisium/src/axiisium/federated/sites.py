"""Partition the AML cohort across sites NON-IID, the way real centers differ.

Real federated AML is non-IID: each center has its own patient mix and mutation
prevalence (a pediatric center, a transplant referral center, a community hospital see
different distributions). We simulate that so the federation result is honest — IID
partitions make federation look easier than it is.
"""
from __future__ import annotations

import numpy as np


def partition_noniid(
    X: np.ndarray,
    y: np.ndarray,
    site_pos_fraction: dict[str, float],
    seed: int = 5,
) -> dict[str, tuple[np.ndarray, np.ndarray]]:
    """Split (X, y) into sites with different positive-class prevalence.

    site_pos_fraction: {site_id: target fraction of that site's samples that are positive}.
    Each site gets a disjoint slice; prevalence is shaped by sampling pos/neg accordingly.
    """
    rng = np.random.default_rng(seed)
    pos_idx = list(rng.permutation(np.where(y == 1)[0]))
    neg_idx = list(rng.permutation(np.where(y == 0)[0]))

    n_sites = len(site_pos_fraction)
    per_site = len(y) // n_sites
    sites: dict[str, tuple[np.ndarray, np.ndarray]] = {}
    for sid, frac in site_pos_fraction.items():
        n_pos = min(int(per_site * frac), len(pos_idx))
        n_neg = min(per_site - n_pos, len(neg_idx))
        take = pos_idx[:n_pos] + neg_idx[:n_neg]
        del pos_idx[:n_pos]
        del neg_idx[:n_neg]
        rng.shuffle(take)
        take = np.array(take)
        sites[sid] = (X[take], y[take])
    return sites
