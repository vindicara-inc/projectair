"""Erasable content vault for capture-time referencing (PHI fork).

When a :class:`airsdk.types.CapturePolicy` references a field, the signed chain
keeps only a **salted** BLAKE3 digest of the plaintext, never the plaintext and
never the salt. The salt makes the digest non-reversible (a low-entropy value
like an SSN cannot be brute-forced from the digest without the salt) and
non-correlatable (identical plaintexts get different salts, so identical values
do not produce identical digests in the chain or in any public anchor).

The salt and plaintext live here instead: a separate, access-controlled,
erasable sidecar the operator owns. Two consequences follow:

- **Erasure (GDPR / HIPAA):** delete a vault entry and the anchored digest for
  that field becomes permanently non-reversible. The immutable chain is
  unaffected and still verifies; the content is simply gone.
- **Verification:** an authorized holder of the vault entry can prove a given
  plaintext matches the chain digest by recomputing ``BLAKE3(salt ‖ plaintext)``.

The vault file is created mode ``0600``. It is NOT part of the signed chain and
is NOT anchored.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from airsdk.agdr import _blake3_hex, _canonical_json


def _field_bytes(value: Any) -> bytes:
    """Canonical bytes for a payload value (str direct, else canonical JSON)."""
    return value.encode("utf-8") if isinstance(value, str) else _canonical_json(value)


def salted_digest(value: Any, salt: bytes) -> str:
    """Return the ``"blake3:<hex>"`` reference for ``value`` under ``salt``."""
    return f"blake3:{_blake3_hex(salt + _field_bytes(value))}"


class ReferenceVault:
    """Append-only sidecar mapping a content reference to its salt + plaintext."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path).expanduser()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # Create restrictive before first write so plaintext is never world-readable.
        if not self._path.exists():
            self._path.touch(mode=0o600)
        else:
            self._path.chmod(0o600)

    @property
    def path(self) -> Path:
        return self._path

    def store(self, ref: str, salt: bytes, field: str, plaintext: Any) -> None:
        """Record the salt and plaintext behind a chain reference."""
        line = json.dumps(
            {"ref": ref, "salt": salt.hex(), "field": field, "plaintext": plaintext},
            separators=(",", ":"),
            ensure_ascii=False,
        )
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    def resolve(self, ref: str) -> tuple[bytes, Any] | None:
        """Return ``(salt, plaintext)`` for ``ref``, or ``None`` if erased/absent."""
        if not self._path.exists():
            return None
        found: tuple[bytes, Any] | None = None
        with self._path.open(encoding="utf-8") as handle:
            for raw in handle:
                raw = raw.strip()
                if not raw:
                    continue
                entry = json.loads(raw)
                if entry.get("ref") == ref:
                    found = (bytes.fromhex(entry["salt"]), entry["plaintext"])
        return found

    def verify(self, ref: str) -> bool:
        """True if the vault's stored plaintext + salt reproduce ``ref``."""
        resolved = self.resolve(ref)
        if resolved is None:
            return False
        salt, plaintext = resolved
        return salted_digest(plaintext, salt) == ref
