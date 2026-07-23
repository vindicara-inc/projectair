"""Mint a demo Enterprise license and write it in the on-disk installed format.

Operator-only: requires the vendor signing key at ``~/.airsdk-vendor/``. The
output file is what the container mounts at ``AIRSDK_LICENSE_PATH``. Usage::

    python deploy/make_demo_license.py enterprise ./license.json

The first arg is the tier (default ``enterprise``); pass ``team`` to demo the
wrong-tier rejection. The second arg is the output path.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "packages" / "projectair-pro" / "tools"))
sys.path.insert(0, str(ROOT / "packages" / "projectair-pro" / "src"))

from airsdk_pro.license import install_license  # noqa: E402
from issue_license import issue  # noqa: E402

VENDOR_KEY_PATH = Path.home() / ".airsdk-vendor" / "license_signing.key"


def main() -> None:
    tier = sys.argv[1] if len(sys.argv) > 1 else "enterprise"
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "deploy" / "license.json"
    if not VENDOR_KEY_PATH.exists():
        raise SystemExit(f"vendor signing key not found at {VENDOR_KEY_PATH}; cannot mint a demo license")

    token = issue(
        email="demo-enterprise@vindicara.io",
        tier=tier,
        duration_days=365,
        features=["air-cloud-client", "report-nist-ai-rmf", "report-soc2-ai"],
        private_key_path=VENDOR_KEY_PATH,
    )
    install_license(json.dumps(token), path=out)
    print(f"wrote {tier} license to {out}")


if __name__ == "__main__":
    main()
