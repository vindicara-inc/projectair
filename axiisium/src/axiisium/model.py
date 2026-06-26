"""Late-fusion multimodal classifier (numpy reference).

The skeleton trains one linear head per modality, concatenates their logits, and learns a
fusion weight — late fusion, the standard pattern for clinical multimodal models where
modalities are missing-at-random (a patient may lack flow OR cytogenetics). The numpy
logistic regression below is the *placeholder*; the architecture is what matters.

PRODUCTION SWAP: each per-modality encoder becomes a real network on GPU —
  pathology    -> MONAI + pathology foundation model (Virchow/UNI) embedding + MLP head
  flow         -> set-transformer / MLP over gated flow features
  fusion       -> attention-based fusion (e.g., MONAI multimodal) with missing-modality masking
Train on NVIDIA GPU (Inception credits); federate with NVIDIA FLARE across centers.
"""
from __future__ import annotations

import numpy as np


def _sigmoid(z: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(z, -30, 30)))


class ModalityHead:
    """L2-regularized logistic regression for one modality (the per-encoder placeholder)."""

    def __init__(self, dim: int, lr: float = 0.1, l2: float = 1e-3, epochs: int = 300) -> None:
        self.w = np.zeros(dim)
        self.b = 0.0
        self.lr, self.l2, self.epochs = lr, l2, epochs

    def fit(self, x: np.ndarray, y: np.ndarray) -> None:
        n = len(y)
        for _ in range(self.epochs):
            p = _sigmoid(x @ self.w + self.b)
            grad_w = x.T @ (p - y) / n + self.l2 * self.w
            grad_b = float(np.mean(p - y))
            self.w -= self.lr * grad_w
            self.b -= self.lr * grad_b

    def logit(self, x: np.ndarray) -> np.ndarray:
        return x @ self.w + self.b


class FusionModel:
    """Late fusion: per-modality logits -> learned fusion logistic head."""

    def __init__(self) -> None:
        self.heads: dict[str, ModalityHead] = {}
        self.fusion = ModalityHead(dim=0)  # dim set at fit time

    def fit(self, mods: dict[str, np.ndarray], y: np.ndarray) -> None:
        logits = []
        for name, x in mods.items():
            head = ModalityHead(dim=x.shape[1])
            head.fit(x, y)
            self.heads[name] = head
            logits.append(head.logit(x))
        z = np.column_stack(logits)
        self.fusion = ModalityHead(dim=z.shape[1])
        self.fusion.fit(z, y)

    def predict_proba(self, mods: dict[str, np.ndarray]) -> np.ndarray:
        logits = [self.heads[name].logit(x) for name, x in mods.items()]
        z = np.column_stack(logits)
        return _sigmoid(self.fusion.logit(z))

    def weights_blob(self) -> np.ndarray:
        """Flatten all weights — hashed into the ledger so the exact model is provable."""
        parts = [self.fusion.w, np.array([self.fusion.b])]
        for name in sorted(self.heads):
            parts.append(self.heads[name].w)
            parts.append(np.array([self.heads[name].b]))
        return np.concatenate(parts)


def roc_auc(y: np.ndarray, p: np.ndarray) -> float:
    """ROC AUC via the rank (Mann-Whitney U) identity. No sklearn dependency."""
    pos = p[y == 1]
    neg = p[y == 0]
    if len(pos) == 0 or len(neg) == 0:
        return float("nan")
    order = np.argsort(p, kind="mergesort")
    ranks = np.empty(len(p), dtype=np.float64)
    ranks[order] = np.arange(1, len(p) + 1)
    # average ranks for ties
    _, inv, counts = np.unique(p, return_inverse=True, return_counts=True)
    sums = np.zeros(len(counts))
    np.add.at(sums, inv, ranks)
    avg = sums / counts
    ranks = avg[inv]
    r_pos = ranks[y == 1].sum()
    auc = (r_pos - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg))
    return float(auc)
