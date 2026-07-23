"""Container entrypoint for the self-hosted / air-gapped Enterprise unit.

``air-server`` is what the deployable image runs. It does exactly two things,
in this order and no other:

1. **Gate.** Run the offline license preflight (:mod:`airsdk_pro.deploy`). If the
   license is missing, invalid, expired, wrong-tier, or the preflight raises for
   *any* reason, print the cause and exit non-zero. The workload never starts.
   This is the whole security contract of the tier: no valid Enterprise license,
   no server.
2. **Serve.** Only on a clean gate, build the AIR Cloud ingest app backed by
   durable filesystem stores (so chains, tenants, and keys survive restarts with
   no external database) and hand it to uvicorn.

Configuration is environment-only, so the image needs no config file:

- ``AIRSDK_LICENSE_PATH``  path to the signed license (default: ``~/.airsdk/license.json``)
- ``AIRSDK_DATA_DIR``      durable data directory (default: ``/var/lib/airsdk``)
- ``AIRSDK_HOST``          bind host (default: ``0.0.0.0``)
- ``AIRSDK_PORT``          bind port (default: ``8080``)
- ``AIRSDK_AIR_GAPPED``    ``1``/``true`` (default) surfaces the air-gapped anchoring advisory
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from airsdk_pro.deploy import StartupReport, preflight

if TYPE_CHECKING:
    from fastapi import FastAPI

DEFAULT_DATA_DIR = "/var/lib/airsdk"
DEFAULT_HOST = "0.0.0.0"  # noqa: S104 - a server container is meant to bind all interfaces
DEFAULT_PORT = 8080


def _truthy(value: str | None, *, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def run_gate(*, license_path: Path | None, air_gapped: bool) -> StartupReport:
    """Run the license preflight, failing closed on *any* error.

    Returns the :class:`StartupReport` on success. On any exception, prints the
    cause to stderr and raises ``SystemExit(1)`` so the container entrypoint
    exits non-zero and the server is never started. A non-license exception is
    treated as fatal too: an unexpected error must not fall through to booting an
    unlicensed server.
    """
    try:
        return preflight(license_path=license_path, air_gapped=air_gapped)
    except Exception as exc:  # fail-closed: the gate must never let the server boot on error
        print(f"[air-server] refusing to start: {exc}", file=sys.stderr)
        print(
            "[air-server] a valid Enterprise license is required to run the "
            "self-hosted unit. Install one with `air install-license --license <token>` "
            "(mounted at AIRSDK_LICENSE_PATH), then restart.",
            file=sys.stderr,
        )
        raise SystemExit(1) from exc


def build_app(*, data_dir: str) -> FastAPI:
    """Build the AIR Cloud ingest app backed by durable filesystem stores.

    Capsules land in an append-only JSONL log; workspaces and API keys persist
    to JSON files. All three live under ``data_dir`` so a restart (or container
    recycle) recovers the full forensic history and tenancy with no external
    database.
    """
    from vindicara.cloud.capsule_store import JSONLCapsuleStore
    from vindicara.cloud.factory import create_air_cloud_app
    from vindicara.cloud.file_stores import JSONApiKeyStore, JSONWorkspaceStore

    root = Path(data_dir).expanduser()
    return create_air_cloud_app(
        capsule_store=JSONLCapsuleStore(root / "capsules"),
        workspace_store=JSONWorkspaceStore(root),
        api_key_store=JSONApiKeyStore(root),
        title="AIR Enterprise (self-hosted)",
    )


def _default_serve(app: FastAPI, *, host: str, port: int) -> None:
    import uvicorn

    uvicorn.run(app, host=host, port=port)


def main(serve_fn: Callable[[FastAPI], None] | None = None) -> None:
    """Entrypoint: gate, then serve. Never serves without a clean gate.

    ``serve_fn`` is an injection seam for tests: it is called with the built app
    only after the gate passes, so a test can assert it is *not* called when the
    license is missing or invalid.
    """
    license_env = os.environ.get("AIRSDK_LICENSE_PATH")
    license_path = Path(license_env) if license_env else None
    air_gapped = _truthy(os.environ.get("AIRSDK_AIR_GAPPED"), default=True)
    data_dir = os.environ.get("AIRSDK_DATA_DIR", DEFAULT_DATA_DIR)
    host = os.environ.get("AIRSDK_HOST", DEFAULT_HOST)
    port = int(os.environ.get("AIRSDK_PORT", str(DEFAULT_PORT)))

    report = run_gate(license_path=license_path, air_gapped=air_gapped)

    print(
        f"[air-server] license OK: {report.email} (tier={report.tier}, "
        f"{report.days_remaining} day(s) remaining)"
    )
    for warning in report.warnings:
        print(f"[air-server] warning: {warning}", file=sys.stderr)
    print(f"[air-server] serving AIR Enterprise on {host}:{port}, data dir {data_dir}")

    app = build_app(data_dir=data_dir)
    if serve_fn is not None:
        serve_fn(app)
    else:
        _default_serve(app, host=host, port=port)


if __name__ == "__main__":
    main()


__all__ = ["build_app", "main", "run_gate"]
