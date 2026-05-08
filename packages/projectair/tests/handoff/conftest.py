"""Shared fixtures for Layer 4 handoff tests."""
from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)


def _b64u(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@contextmanager
def _spawn_jwks_server(kid: str, pub_numbers: Any) -> Iterator[str]:
    body = json.dumps(
        {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": kid,
                    "n": _b64u(pub_numbers.n),
                    "e": _b64u(pub_numbers.e),
                }
            ]
        }
    ).encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path.endswith("/.well-known/jwks.json"):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *_args: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    issuer = f"http://127.0.0.1:{server.server_address[1]}/"
    Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield issuer
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def rsa_signer():
    """Yield (issuer, pem, kid) for a freshly generated in-process JWKS server."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    kid = "test-kid"
    with _spawn_jwks_server(kid, priv.public_key().public_numbers()) as issuer:
        yield issuer, pem, kid


@pytest.fixture
def adapter(rsa_signer):
    from airsdk.handoff.idp.auth0 import Auth0Adapter

    issuer, pem, kid = rsa_signer
    return Auth0Adapter(
        domain="vindicara.us.auth0.com",
        audience="agent:cabinet-coach.v2",
        issuer=issuer,
        jwks_uri=f"{issuer}.well-known/jwks.json",
        signing_key_pem=pem,
        signing_kid=kid,
    )
