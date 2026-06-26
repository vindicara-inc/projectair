"""FedAvg over a logistic model (numpy reference for NVIDIA FLARE).

The model is warm-startable: each round, every site receives the current global weights,
takes local gradient steps on ITS OWN data only, and returns updated weights + sample
count. The server averages weighted by sample count (McMahan et al. FedAvg). Raw data
never leaves a site — only weight vectors move.

PRODUCTION: this loop is an NVIDIA FLARE job — the server is a FLARE `Controller` running
the FedAvg workflow, each site is an `Executor` training locally; FLARE handles transport,
secure aggregation, and TEE/GPU confidential computing. See stage3/README.md.
"""
from __future__ import annotations

import numpy as np


def _sigmoid(z: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(z, -30, 30)))


class LogisticModel:
    """Warm-startable logistic regression. Weights are the only thing that crosses sites."""

    def __init__(self, dim: int) -> None:
        self.w = np.zeros(dim)
        self.b = 0.0

    def copy(self) -> "LogisticModel":
        m = LogisticModel(len(self.w))
        m.w = self.w.copy()
        m.b = self.b
        return m

    def local_train(self, x: np.ndarray, y: np.ndarray, epochs: int = 50, lr: float = 0.2, l2: float = 1e-2) -> None:
        n = len(y)
        for _ in range(epochs):
            p = _sigmoid(x @ self.w + self.b)
            self.w -= lr * (x.T @ (p - y) / n + l2 * self.w)
            self.b -= lr * float(np.mean(p - y))

    def proba(self, x: np.ndarray) -> np.ndarray:
        return _sigmoid(x @ self.w + self.b)

    def blob(self) -> np.ndarray:
        return np.concatenate([self.w, [self.b]])


def fedavg_round(global_model: LogisticModel, sites: dict[str, tuple[np.ndarray, np.ndarray]],
                 local_epochs: int = 50):
    """One FedAvg round. Returns (new_global, {site_id: (LogisticModel, n)})."""
    updates: dict[str, tuple[LogisticModel, int]] = {}
    for sid, (x, y) in sites.items():
        local = global_model.copy()
        local.local_train(x, y, epochs=local_epochs)
        updates[sid] = (local, len(y))
    total = sum(n for _, n in updates.values())
    new_w = sum((n / total) * m.w for m, n in updates.values())
    new_b = sum((n / total) * m.b for m, n in updates.values())
    agg = LogisticModel(len(new_w))
    agg.w, agg.b = new_w, new_b
    return agg, updates
