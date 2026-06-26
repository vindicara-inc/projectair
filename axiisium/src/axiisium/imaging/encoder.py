"""Cell-image encoders: a runnable smoke encoder + the production foundation-model path.

The encoder turns each single-cell image into an embedding vector that a light classifier
head sits on top of. Two implementations behind one `.embed(paths) -> np.ndarray`:

  SmokeEncoder       : pure numpy color/texture statistics. Runs anywhere, no torch.
                       Proves the loader -> embed -> head -> eval -> signed-run path.

  FoundationEncoder  : PRODUCTION. A hematology cell foundation model on GPU.
                       Recommended: DinoBloom (Koch et al. 2024, a DINOv2 ViT trained on
                       380k+ blood/marrow cells) — purpose-built for single-cell hematology
                       embeddings, unlike tissue-WSI models (Virchow/UNI). MONAI handles the
                       transforms + loading. Falls back to a MONAI/timm ViT if DinoBloom
                       weights aren't present. Requires torch + monai + timm (see requirements).
"""
from __future__ import annotations

from pathlib import Path

import numpy as np

from .dataset import load_image_array


class SmokeEncoder:
    """Numpy embedding: per-channel mean/std + coarse 4x4 spatial color grid. ~83 dims."""

    name = "smoke-numpy-colorstats"
    grid = 4

    def embed(self, paths: list[Path], size: int = 144) -> np.ndarray:
        out = []
        for p in paths:
            img = load_image_array(p, size=size)  # HxWx3 in [0,1]
            feats = [img.mean(axis=(0, 1)), img.std(axis=(0, 1))]
            step = size // self.grid
            for gy in range(self.grid):
                for gx in range(self.grid):
                    cell = img[gy * step:(gy + 1) * step, gx * step:(gx + 1) * step]
                    feats.append(cell.mean(axis=(0, 1)))
            out.append(np.concatenate(feats))
        return np.asarray(out, dtype=np.float64)


class FoundationEncoder:
    """PRODUCTION encoder. Lazy-imports torch so the smoke path never needs it.

    Usage on GPU:
        enc = FoundationEncoder(weights="dinobloom_vitb14.pth", device="cuda")
        X = enc.embed(paths)        # [n, 768] cell embeddings
    """

    name = "dinobloom-vit (production)"

    def __init__(self, weights: str | None = None, device: str = "cuda", size: int = 224) -> None:
        self.weights = weights
        self.device = device
        self.size = size
        self._model = None

    def _load(self) -> None:
        try:
            import timm  # noqa: F401
            import torch
        except ImportError as e:  # pragma: no cover - production-only path
            raise RuntimeError(
                "FoundationEncoder needs torch + timm (+ monai). Install the Stage 1 extras "
                "and run on a GPU box. For a no-dependency dry run use SmokeEncoder."
            ) from e
        import timm

        # DINOv2 ViT-B/14 backbone; load DinoBloom hematology weights if provided.
        model = timm.create_model("vit_base_patch14_dinov2", pretrained=self.weights is None, num_classes=0)
        if self.weights:
            import torch

            state = torch.load(self.weights, map_location="cpu")
            model.load_state_dict(state, strict=False)
        self._model = model.eval().to(self.device)

    def embed(self, paths: list[Path]) -> np.ndarray:  # pragma: no cover - production-only path
        import torch
        from monai.transforms import Compose, NormalizeIntensity, Resize

        if self._model is None:
            self._load()
        tf = Compose([Resize((self.size, self.size)), NormalizeIntensity(channel_wise=True)])
        embs = []
        with torch.no_grad():
            for p in paths:
                img = load_image_array(p, size=self.size).transpose(2, 0, 1)  # CHW
                x = torch.as_tensor(tf(img), dtype=torch.float32).unsqueeze(0).to(self.device)
                embs.append(self._model(x).cpu().numpy()[0])
        return np.asarray(embs, dtype=np.float64)
