"""Shared fixtures for containment tests.

The ``mock_idp`` fixture spins up an in-process JWKS endpoint backed by
a real RSA keypair. Tests that exercise ``Auth0Verifier`` use this
instead of mocking the verifier itself, so the real PyJWT verification
path is exercised end to end. The verifier cannot tell this from a real
Auth0 tenant - the only difference is the issuer URL and the JWKS
location.
"""
from __future__ import annotations

import json
import time
from collections.abc import Iterator
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


@dataclass
class MockIdP:
    issuer: str
    audience: str
    jwks_uri: str
    private_pem: bytes
    public_pem: bytes
    kid: str

    def issue_token(
        self,
        *,
        sub: str = "auth0|test-user",
        email: str | None = "approver@example.com",
        ttl_seconds: int = 300,
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": sub,
            "iat": now,
            "exp": now + ttl_seconds,
            "jti": f"jti-{now}-{sub}",
        }
        if email is not None:
            claims["email"] = email
        if extra_claims:
            claims.update(extra_claims)
        return jwt.encode(
            claims,
            self.private_pem,
            algorithm="RS256",
            headers={"kid": self.kid},
        )


@pytest.fixture
def mock_idp() -> Iterator[MockIdP]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = priv.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    public_pem = priv.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    kid = "test-key-1"
    pub_numbers = priv.public_key().public_numbers()
    n_b64 = _int_to_b64url(pub_numbers.n)
    e_b64 = _int_to_b64url(pub_numbers.e)
    jwks_body = json.dumps(
        {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": kid,
                    "n": n_b64,
                    "e": e_b64,
                },
            ],
        },
    ).encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path.endswith("/.well-known/jwks.json"):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(jwks_body)))
                self.end_headers()
                self.wfile.write(jwks_body)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *_args: Any) -> None:  # silence test output
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    issuer = f"http://127.0.0.1:{port}/"
    yield MockIdP(
        issuer=issuer,
        audience="https://api.vindicara.io",
        jwks_uri=f"{issuer}.well-known/jwks.json",
        private_pem=private_pem,
        public_pem=public_pem,
        kid=kid,
    )

    server.shutdown()
    server.server_close()


def _int_to_b64url(value: int) -> str:
    import base64

    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
