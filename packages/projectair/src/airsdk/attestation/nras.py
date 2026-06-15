"""NRAS client: submit evidence, parse the signed EAT response (W1, experimental).

AIR's job here is narrow and well-bounded: generate a freshness nonce bound
to chain genesis, drive evidence collection, call NRAS, and record NRAS's
signed token verbatim as a first-class record in the chain. AIR does not
re-sign NVIDIA's token.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol

from airsdk.attestation.config import GPUAttestationConfig
from airsdk.attestation.evidence import collect_evidence, derive_nonce
from airsdk.attestation.types import (
    EvidenceBundle,
    GPUAttestation,
    NRASResponseError,
    NRASResult,
    NRASUnreachableError,
)

__all__ = ["AttestationProvider", "NRASClient", "attest_session", "parse_nras_response"]

_JsonValue = (
    None | bool | int | float | str | list["_JsonValue"] | dict[str, "_JsonValue"]
)


class AttestationProvider(Protocol):
    """Anything that can turn a nonce into a parsed NRAS attestation result.

    Implemented by :class:`NRASClient` (live service) and
    ``airsdk.attestation.fixture.FixtureNRAS`` (simulated NRAS for tests
    and demos).
    """

    @property
    def nras_url(self) -> str: ...

    def attest(self, *, nonce: str, gpu_arch: str) -> NRASResult: ...


class NRASClient:
    """Calls the NVIDIA Remote Attestation Service over HTTPS.

    ``post_json`` is injectable for tests; the default posts with urllib,
    matching the project's stdlib-HTTP pattern in ``anchoring/rekor.py``.
    """

    def __init__(
        self,
        config: GPUAttestationConfig,
        *,
        post_json: Callable[[str, dict[str, _JsonValue], float], _JsonValue] | None = None,
    ) -> None:
        self._config = config
        self._post_json = post_json if post_json is not None else _post_json_urllib

    @property
    def nras_url(self) -> str:
        return self._config.nras_url

    def attest(self, *, nonce: str, gpu_arch: str) -> NRASResult:
        """Collect evidence on this host, submit it to NRAS, parse the EAT."""
        bundle = collect_evidence(nonce, gpu_arch=gpu_arch)
        return self.attest_evidence(bundle)

    def attest_evidence(self, bundle: EvidenceBundle) -> NRASResult:
        """Submit pre-collected evidence to NRAS and parse the response."""
        request_body: dict[str, _JsonValue] = {
            "nonce": bundle.nonce,
            "arch": bundle.gpu_arch.upper(),
            "evidence_list": [
                {
                    "evidence": device.evidence_b64,
                    "certificate": device.certificate_b64,
                }
                for device in bundle.devices
            ],
        }
        try:
            raw = self._post_json(
                self._config.nras_url, request_body, self._config.timeout_seconds
            )
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            raise NRASUnreachableError(
                f"NRAS endpoint {self._config.nras_url} unreachable: {exc}"
            ) from exc
        return parse_nras_response(raw)


def parse_nras_response(raw: _JsonValue) -> NRASResult:
    """Parse an NRAS attestation response into a typed result.

    Two shapes are accepted, because the exact NRAS response envelope for
    in-instance programmatic calls is a W1 open decision (spec 2.8):

    - object form: ``{"detached_eat": <jwt>, "device_eats": [<jwt>, ...],
      "claims_version": <str>, "rim_matched": <bool>}``
    - array form (NRAS v3 token array): ``[["JWT", <overall_jwt>],
      {"<device>": <jwt>, ...}]``, where per-device order follows the
      evidence list.

    Anything else fails closed with :class:`NRASResponseError`.
    """
    if isinstance(raw, dict):
        return _parse_object_form(raw)
    if isinstance(raw, list):
        return _parse_array_form(raw)
    raise NRASResponseError(f"unrecognized NRAS response type: {type(raw).__name__}")


def attest_session(
    genesis_content_hash: str,
    config: GPUAttestationConfig,
    *,
    provider: AttestationProvider | None = None,
) -> GPUAttestation:
    """Produce the GPUAttestation for one session, nonce-bound to genesis.

    Called by the recorder right after the DELEGATION and INTENT_DECLARATION
    genesis records so the resulting GPU_ATTESTATION record is covered by the
    first anchored BLAKE3 root.
    """
    nonce = derive_nonce(genesis_content_hash)
    resolved: AttestationProvider = provider if provider is not None else NRASClient(config)
    result = resolved.attest(nonce=nonce, gpu_arch=config.gpu_arch)
    return GPUAttestation(
        nonce=nonce,
        nras_url=resolved.nras_url,
        detached_eat=result.detached_eat,
        device_eats=result.device_eats,
        gpu_arch=config.gpu_arch,
        claims_version=result.claims_version,
        rim_matched=result.rim_matched,
        measured_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        verification_hint="nras_jwks" if config.mode == "online" else "cached_rim_ocsp",
    )


def _parse_object_form(raw: dict[str, _JsonValue]) -> NRASResult:
    detached_eat = raw.get("detached_eat")
    device_eats = raw.get("device_eats")
    if not isinstance(detached_eat, str) or not isinstance(device_eats, list):
        raise NRASResponseError(
            "NRAS object response missing detached_eat or device_eats"
        )
    eats: list[str] = []
    for entry in device_eats:
        if not isinstance(entry, str):
            raise NRASResponseError("device_eats entries must be JWT strings")
        eats.append(entry)
    claims_version = raw.get("claims_version")
    rim_matched = raw.get("rim_matched")
    return NRASResult(
        detached_eat=detached_eat,
        device_eats=eats,
        claims_version=claims_version if isinstance(claims_version, str) else "",
        rim_matched=bool(rim_matched) if isinstance(rim_matched, bool) else False,
    )


def _parse_array_form(raw: list[_JsonValue]) -> NRASResult:
    if len(raw) < 2:
        raise NRASResponseError("NRAS array response must carry [overall, devices]")
    overall, devices = raw[0], raw[1]
    if (
        not isinstance(overall, list)
        or len(overall) != 2
        or overall[0] != "JWT"
        or not isinstance(overall[1], str)
    ):
        raise NRASResponseError('NRAS array response first element must be ["JWT", <jwt>]')
    if not isinstance(devices, dict):
        raise NRASResponseError("NRAS array response second element must map device -> EAT")
    eats: list[str] = []
    for device_id, token in devices.items():
        if not isinstance(token, str):
            raise NRASResponseError(f"device EAT for {device_id!r} must be a JWT string")
        eats.append(token)
    claims = _decode_unverified_claims(overall[1])
    claims_version = claims.get("eat_profile") or claims.get("claims_version")
    overall_result = claims.get("x-nvidia-overall-att-result")
    return NRASResult(
        detached_eat=overall[1],
        device_eats=eats,
        claims_version=claims_version if isinstance(claims_version, str) else "",
        rim_matched=overall_result is True or overall_result == "PASS",
    )


def _decode_unverified_claims(token: str) -> dict[str, _JsonValue]:
    """Read JWT claims WITHOUT verifying. Parsing convenience only.

    Trust decisions never run on this output; signature verification happens
    in ``airsdk.attestation.verify`` against NRAS JWKS or a cached signing
    certificate.
    """
    import jwt as pyjwt

    try:
        claims = pyjwt.decode(token, options={"verify_signature": False})
    except pyjwt.InvalidTokenError as exc:
        raise NRASResponseError(f"overall EAT is not a parseable JWT: {exc}") from exc
    if not isinstance(claims, dict):
        raise NRASResponseError("overall EAT claims must be a JSON object")
    return claims


def _post_json_urllib(
    url: str, body: dict[str, _JsonValue], timeout_seconds: float
) -> _JsonValue:
    if not url.startswith("https://"):
        raise NRASUnreachableError(
            f"NRAS endpoint must be https://, got {url!r}; the fixture scheme "
            "never reaches the network (FixtureNRAS attests in-process)"
        )
    request = urllib.request.Request(  # noqa: S310 (scheme enforced above)
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310
        parsed: _JsonValue = json.loads(response.read().decode("utf-8"))
        return parsed
