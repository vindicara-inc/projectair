"""End-to-end demo: AIR forensic recording over the Google Gemini SDK.

Wraps a ``google.genai.Client`` with ``airsdk.integrations.gemini.instrument_gemini``
so every model call emits a Signed Intent Capsule. The wrapped client is a
transparent proxy: ``client.models``, ``client.chats``, and ``client.aio`` are
instrumented; everything else falls through unchanged.

Prerequisites:

    pip install projectair google-genai
    export GEMINI_API_KEY=...   # from https://aistudio.google.com/apikey

Run:

    python packages/projectair/examples/gemini_demo.py

The script sends a single prompt to ``gemini-2.5-flash``, records the call
as a Signed Intent Capsule, verifies the resulting chain, and prints the
captured response.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from airsdk.agdr import load_chain, verify_chain
from airsdk.integrations.gemini import instrument_gemini
from airsdk.recorder import AIRRecorder
from airsdk.types import VerificationStatus

GEMINI_MODEL = "gemini-2.5-flash"
LOG_PATH = Path(__file__).parent / "gemini_demo_trace.log"


def main() -> int:
    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        print("error: set GEMINI_API_KEY (or GOOGLE_API_KEY) from https://aistudio.google.com/apikey", file=sys.stderr)
        return 2

    try:
        from google import genai
    except ImportError:
        print("error: pip install google-genai", file=sys.stderr)
        return 2

    if LOG_PATH.exists():
        LOG_PATH.unlink()

    recorder = AIRRecorder(log_path=LOG_PATH, user_intent="Demo: AIR records a Gemini call.")
    raw_client = genai.Client(api_key=api_key)
    client = instrument_gemini(raw_client, recorder)

    print(f"Calling {GEMINI_MODEL} via Google Gemini API ...")
    response = client.models.generate_content(
        model=GEMINI_MODEL,
        contents="Reply with exactly the word OK.",
    )
    answer = (response.text or "").strip()
    print(f"Gemini responded: {answer!r}")

    records = load_chain(LOG_PATH)
    print(f"Wrote {len(records)} signed records to {LOG_PATH}")
    result = verify_chain(records)
    if result.status != VerificationStatus.OK:
        print(f"chain verification FAILED: {result.status}", file=sys.stderr)
        return 1

    print("Chain verifies. Public key:", recorder.public_key_hex)
    print("ALL CHECKS PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
