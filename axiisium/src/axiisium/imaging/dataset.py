"""Dataset loader for the Munich AML-Cytomorphology_LMU single-cell images.

The TCIA collection ships as one subdirectory per morphological class, each holding
single-cell TIFF/PNG crops. We discover classes from the directory tree (so we never
hardcode label spellings that might drift) and expose (path, label) pairs.

  Source : TCIA AML-Cytomorphology_LMU, DOI 10.7937/tcia.2019.36f5o9ld
           Matek et al. 2019, Nature Machine Intelligence. 18,365 cells, 15 classes,
           100 AML patients + 100 controls. License: TCIA Data Usage Policy (cite).
  Layout : <root>/<CLASS>/<image>.tif

`make_smoke_dataset` writes a tiny synthetic version (colored noise crops in class
folders) so the whole pipeline runs with zero download — used to prove the code path.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

import numpy as np

IMAGE_EXTS = {".tif", ".tiff", ".png", ".jpg", ".jpeg", ".bmp"}


@dataclass
class Sample:
    path: Path
    label: str


def discover_classes(root: str | Path) -> list[str]:
    root = Path(root)
    classes = sorted(p.name for p in root.iterdir() if p.is_dir())
    if not classes:
        raise ValueError(f"No class subdirectories under {root}")
    return classes


def load_index(root: str | Path) -> tuple[list[Sample], list[str]]:
    """Return (samples, classes) by walking <root>/<CLASS>/*.{tif,png,...}."""
    root = Path(root)
    classes = discover_classes(root)
    samples: list[Sample] = []
    for cls in classes:
        for p in sorted((root / cls).iterdir()):
            if p.suffix.lower() in IMAGE_EXTS:
                samples.append(Sample(path=p, label=cls))
    if not samples:
        raise ValueError(f"No images found under {root}")
    return samples, classes


def load_image_array(path: str | Path, size: int = 144) -> np.ndarray:
    """Load an image as a normalized HxWx3 float array in [0,1]. Requires Pillow."""
    from PIL import Image  # local import: only the loader needs Pillow

    img = Image.open(path).convert("RGB").resize((size, size))
    return np.asarray(img, dtype=np.float64) / 255.0


def index_hash(samples: list[Sample]) -> str:
    """Stable hash of the exact sample set (paths + labels) bound into the run ledger."""
    h = hashlib.sha256()
    for s in sorted(samples, key=lambda x: str(x.path)):
        h.update(str(s.path).encode())
        h.update(s.label.encode())
    return h.hexdigest()


def make_smoke_dataset(root: str | Path, per_class: int = 40, size: int = 144, seed: int = 3) -> Path:
    """Write a tiny synthetic folder-per-class dataset to prove the pipeline runs.

    Each class gets a distinct color/texture bias so a real encoder + head can separate
    them — this validates plumbing, not morphology. Blast class 'MYB' is included.
    """
    from PIL import Image

    rng = np.random.default_rng(seed)
    root = Path(root)
    # mimic a few real class abbreviations incl. the AML-relevant myeloblast (MYB)
    classes = {
        "MYB": (0.75, 0.35, 0.55),  # myeloblast (blast)
        "NGS": (0.45, 0.45, 0.75),  # segmented neutrophil
        "LYT": (0.40, 0.65, 0.45),  # typical lymphocyte
        "MON": (0.70, 0.60, 0.40),  # monocyte
        "EOS": (0.75, 0.55, 0.35),  # eosinophil
    }
    for cls, (r, g, b) in classes.items():
        d = root / cls
        d.mkdir(parents=True, exist_ok=True)
        for i in range(per_class):
            base = np.array([r, g, b])
            noise = rng.normal(0, 0.12, size=(size, size, 3))
            arr = np.clip(base + noise, 0, 1)
            Image.fromarray((arr * 255).astype(np.uint8)).save(d / f"{cls}_{i:03d}.png")
    return root
