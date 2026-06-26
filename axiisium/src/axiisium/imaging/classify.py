"""Classifier heads + evaluation for Stage 1.

Two tasks on the cell embeddings:
  - blast detection (binary): myeloblast vs rest — the AML-relevant signal, robust to the
    dataset's heavy class imbalance. Reported as ROC AUC.
  - morphology classification (multiclass): one-vs-rest logits + balanced accuracy.

The head is numpy logistic regression (reused from the Stage 0 model). PRODUCTION swaps it
for a small MLP fine-tuned on GPU; the eval metrics are unchanged.
"""
from __future__ import annotations

import numpy as np

from ..model import ModalityHead, _sigmoid, roc_auc


def standardize(train: np.ndarray, *others: np.ndarray):
    mu = train.mean(axis=0)
    sd = train.std(axis=0) + 1e-8
    return ((train - mu) / sd, *[(o - mu) / sd for o in others])


def blast_labels(labels: list[str], blast_classes: set[str]) -> np.ndarray:
    return np.array([1.0 if lbl in blast_classes else 0.0 for lbl in labels])


def train_blast_detector(xtr, ytr, xte, yte) -> tuple[float, ModalityHead]:
    head = ModalityHead(dim=xtr.shape[1], lr=0.2, l2=1e-2, epochs=500)
    head.fit(xtr, ytr)
    p = _sigmoid(head.logit(xte))
    return roc_auc(yte, p), head


def train_multiclass(xtr, ytr_idx, xte, yte_idx, n_classes: int) -> float:
    """One-vs-rest logistic heads; return balanced accuracy on the test split."""
    logits = np.zeros((len(yte_idx), n_classes))
    for c in range(n_classes):
        yc = (ytr_idx == c).astype(np.float64)
        if yc.sum() == 0:
            logits[:, c] = -1e9
            continue
        head = ModalityHead(dim=xtr.shape[1], lr=0.2, l2=1e-2, epochs=400)
        head.fit(xtr, yc)
        logits[:, c] = head.logit(xte)
    pred = logits.argmax(axis=1)
    # balanced accuracy = mean per-class recall
    recalls = []
    for c in range(n_classes):
        mask = yte_idx == c
        if mask.sum() > 0:
            recalls.append(float((pred[mask] == c).mean()))
    return float(np.mean(recalls)) if recalls else float("nan")
