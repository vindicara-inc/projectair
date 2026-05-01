"""End-to-end demo: AIR forensic recording over the Google ADK.

Attaches AIR callbacks to a Google ADK ``LlmAgent`` via
``airsdk.integrations.adk.instrument_adk``. AIR's callback fires first on
every ``before_model``, ``after_model``, ``before_tool``, and ``after_tool``
event, recording a Signed Intent Capsule before chaining to any user-supplied
callback.

Prerequisites:

    pip install projectair google-adk
    export GOOGLE_API_KEY=...   # from https://aistudio.google.com/apikey
    export GOOGLE_GENAI_USE_VERTEXAI=False

Run:

    python packages/projectair/examples/adk_demo.py

The script constructs an ``LlmAgent``, instruments it, runs a single turn
through ``Runner``, verifies the resulting Signed Intent Capsule chain, and
prints the response.
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from airsdk.agdr import load_chain, verify_chain
from airsdk.integrations.adk import instrument_adk
from airsdk.recorder import AIRRecorder
from airsdk.types import VerificationStatus

ADK_MODEL = "gemini-2.5-flash"
APP_NAME = "air-adk-demo"
USER_ID = "demo-user"
SESSION_ID = "demo-session"
LOG_PATH = Path(__file__).parent / "adk_demo_trace.log"


async def run_demo() -> int:
    api_key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("error: set GOOGLE_API_KEY (or GEMINI_API_KEY) from https://aistudio.google.com/apikey", file=sys.stderr)
        return 2
    os.environ.setdefault("GOOGLE_GENAI_USE_VERTEXAI", "False")

    try:
        from google.adk.agents import LlmAgent
        from google.adk.runners import Runner
        from google.adk.sessions import InMemorySessionService
        from google.genai import types as genai_types
    except ImportError:
        print("error: pip install google-adk", file=sys.stderr)
        return 2

    if LOG_PATH.exists():
        LOG_PATH.unlink()

    recorder = AIRRecorder(log_path=LOG_PATH, user_intent="Demo: AIR records a Google ADK agent turn.")

    agent = LlmAgent(
        name="demo_agent",
        model=ADK_MODEL,
        instruction="Reply with exactly the word OK.",
    )
    instrument_adk(agent, recorder)

    session_service = InMemorySessionService()
    await session_service.create_session(app_name=APP_NAME, user_id=USER_ID, session_id=SESSION_ID)
    runner = Runner(agent=agent, app_name=APP_NAME, session_service=session_service)

    print(f"Running ADK agent on {ADK_MODEL} ...")
    user_message = genai_types.Content(role="user", parts=[genai_types.Part(text="Say OK.")])
    final_text = ""
    async for event in runner.run_async(user_id=USER_ID, session_id=SESSION_ID, new_message=user_message):
        if event.is_final_response() and event.content and event.content.parts:
            final_text = (event.content.parts[0].text or "").strip()
    print(f"ADK agent responded: {final_text!r}")

    records = load_chain(LOG_PATH)
    print(f"Wrote {len(records)} signed records to {LOG_PATH}")
    result = verify_chain(records)
    if result.status != VerificationStatus.OK:
        print(f"chain verification FAILED: {result.status}", file=sys.stderr)
        return 1

    print("Chain verifies. Public key:", recorder.public_key_hex)
    print("ALL CHECKS PASS")
    return 0


def main() -> int:
    return asyncio.run(run_demo())


if __name__ == "__main__":
    raise SystemExit(main())
