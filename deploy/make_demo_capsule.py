"""Emit one validly signed AgDR capsule as JSON on stdout.

Used by ``demo_selfhosted.sh`` to POST a real Signed Intent Capsule into the
self-hosted unit, so the persistence proof (POST -> restart -> GET) exercises the
same ingest + verify path a customer's agent would. The record is self-verifying:
it carries its own signer public key, so an ephemeral key is fine for the demo.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from airsdk.agdr import verify_record
from airsdk.recorder import AIRRecorder
from airsdk.types import AgDRRecord


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        log = Path(tmp) / "chain.log"
        recorder = AIRRecorder(log_path=log, user_intent="self-hosted persistence demo")
        recorder.llm_start(prompt="Is this chain durable across a container restart?")
        recorder.llm_end(response="It is: the JSONL capsule log lives on the mounted volume.")

        line = log.read_text(encoding="utf-8").splitlines()[0]
        record = AgDRRecord.model_validate_json(line)
        ok, reason = verify_record(record)
        if not ok:
            raise SystemExit(f"internal: demo capsule failed to verify: {reason}")
        # Emit the wire form the /v1/capsules route expects (a single record).
        print(json.dumps(json.loads(record.model_dump_json(exclude_none=True))))


if __name__ == "__main__":
    main()
