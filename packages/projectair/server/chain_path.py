"""Containment for the ceremony server's user-supplied evidence-chain name.

The ``chain`` field on ``POST /authorize/verify`` is attacker-controlled, and it
selects the file the tamper-evident AgDR chain is written to. Left unchecked, a
value like ``"../../etc/cron.d/x"`` or ``"/etc/passwd"`` would steer forensic
evidence to an arbitrary path — the worst possible outcome for an evidence
product (CodeQL ``py/path-injection`` alert #18).

The fix lives at this trust boundary, not in :class:`airsdk.recorder.AIRRecorder`:
the recorder is a general SDK component that legitimately writes to temp dirs,
CLI-supplied paths, and absolute locations, so confining it would break trusted
callers. Only this HTTP endpoint takes the name from an untrusted request body.

Kept free of WebAuthn / FastAPI imports so the containment logic is unit-testable
on its own, without standing up the optional ``[webauthn]`` stack.
"""
from __future__ import annotations

import re
from pathlib import Path

# Chains are flat files under a single root anchored to this package directory
# (not the launch CWD), so the root is stable wherever ``uvicorn`` is started.
CHAIN_LOG_ROOT = (Path(__file__).resolve().parent / "chains").resolve()

# Chain names are short identifiers, never paths. This allowlist rejects path
# separators, "..", control characters, and anything otherwise exotic.
_CHAIN_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def safe_chain_path(chain: str, root: Path = CHAIN_LOG_ROOT) -> Path:
    """Resolve an untrusted ``chain`` value to a path confined under ``root``.

    Returns an absolute, resolved path inside ``root``. Raises :class:`ValueError`
    if the name is empty, contains anything outside the allowlist, or resolves
    outside ``root``.
    """
    root = root.resolve()
    # Path.name reduces any path to its final component, so "../../etc/passwd"
    # and "/etc/passwd" collapse to a bare filename. A lone "." yields "" (caught
    # by the allowlist); a lone ".." survives as "..", so reject it explicitly
    # rather than leaning on the containment guard alone.
    name = Path(str(chain)).name
    if name in (".", "..") or not _CHAIN_NAME_RE.fullmatch(name):
        raise ValueError(f"invalid chain name: {chain!r}")
    candidate = (root / name).resolve()
    # Containment guard in the raising form CodeQL recognizes as a path-injection
    # barrier: re-raises ValueError if the resolved path escapes the root.
    candidate.relative_to(root)
    return candidate
