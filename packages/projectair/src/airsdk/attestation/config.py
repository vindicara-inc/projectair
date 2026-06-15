"""Configuration for the GPU attestation layer (W1, experimental)."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

# NRAS v3 GPU attestation endpoint. The exact endpoint and auth model for
# programmatic calls from inside a CC instance is a W1 open decision to lock
# with NVIDIA (spec 2.8); this default tracks the public NRAS documentation.
DEFAULT_NRAS_URL: Final[str] = "https://nras.attestation.nvidia.com/v3/attest/gpu"

VerifyMode = Literal["online", "offline"]


@dataclass(frozen=True)
class GPUAttestationConfig:
    """How AIR collects and verifies NVIDIA NRAS attestation.

    ``mode`` selects the verification trust anchor:

    - ``online``: validate the EAT against NRAS JWKS / the NVIDIA
      attestation signing certificate chain fetched live.
    - ``offline``: validate the EAT against a cached NVIDIA attestation
      signing certificate plus cached RIM / OCSP reference values, so
      verification does not hard-depend on NRAS being reachable.

    The cached reference set (signing cert, RIM, OCSP) and its rotation
    cadence is a W1 open decision locked with NVIDIA (spec 2.8).
    """

    nras_url: str = DEFAULT_NRAS_URL
    mode: VerifyMode = "online"
    timeout_seconds: float = 10.0
    gpu_arch: str = "hopper"  # "hopper" | "blackwell" | "vera_rubin"
    # Online verification: JWKS endpoint. Derived from ``nras_url`` origin
    # when None.
    jwks_url: str | None = None
    # Offline verification trust anchors.
    cached_signing_cert_path: Path | None = None
    cached_rim_path: Path | None = None
    cached_ocsp_path: Path | None = None
