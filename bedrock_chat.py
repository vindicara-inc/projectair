"""Gradio chat UI for Claude on AWS Bedrock (Vindicara account).

Dogfoods the AIR stack: every turn is recorded as a signed AgDR chain and
mirrored into Langfuse by :class:`airsdk.integrations.langfuse.LangfuseTransport`,
so this app is also the end-to-end check that the transport produces good
traces against a real model.

Run:

    export LANGFUSE_PUBLIC_KEY=pk-lf-... LANGFUSE_SECRET_KEY=sk-lf-...
    export LANGFUSE_BASE_URL=https://hipaa.cloud.langfuse.com
    python bedrock_chat.py

Without Langfuse credentials the app still runs and still writes signed
chains to disk; only the Langfuse mirror is skipped.
"""

import os
import uuid
from pathlib import Path

import gradio as gr
from anthropic import AnthropicBedrock

from airsdk.integrations.anthropic import instrument_anthropic
from airsdk.recorder import AIRRecorder
from airsdk.transport import FileTransport

MODEL = "us.anthropic.claude-opus-4-6-v1"
CHAIN_DIR = Path(os.environ.get("AIR_CHAIN_DIR", "air-chat-chains"))

# One Langfuse client for the process. Built lazily and only when credentials
# are present, so a developer without them still gets a working app and a
# signed chain rather than an import-time crash.
_LANGFUSE_READY = bool(
    os.environ.get("LANGFUSE_PUBLIC_KEY") and os.environ.get("LANGFUSE_SECRET_KEY")
)


def _transports(log_path: Path, session_id: str):
    """Disk is the evidence path; Langfuse is the best-effort behavioural mirror."""
    transports = [FileTransport(log_path)]
    if not _LANGFUSE_READY:
        return transports
    from airsdk.integrations.langfuse import LangfuseTransport

    transports.append(
        LangfuseTransport(
            # One Langfuse trace per turn, grouped into one session per
            # conversation: the per-turn model keeps traces small and makes the
            # session view a readable replay of the whole conversation.
            session_id=session_id,
            tags=["bedrock", "chat"],
        )
    )
    return transports


def chat(message: dict, history: list[dict], request: gr.Request) -> str:
    session_id = request.session_hash or "anonymous"
    user_text = message["text"]

    CHAIN_DIR.mkdir(parents=True, exist_ok=True)
    log_path = CHAIN_DIR / f"{session_id}-{uuid.uuid4().hex[:8]}.log"

    recorder = AIRRecorder(
        log_path=log_path,
        # The user's message is the intent for this turn: it anchors the ASI01
        # goal-hijack detector and becomes the Langfuse trace input.
        user_intent=user_text,
        transports=_transports(log_path, session_id),
    )
    client = instrument_anthropic(
        AnthropicBedrock(aws_profile="vindicara", aws_region="us-west-2"), recorder
    )

    messages = [{"role": msg["role"], "content": msg["content"]} for msg in history]
    messages.append({"role": "user", "content": user_text})

    try:
        response = client.messages.create(model=MODEL, max_tokens=4096, messages=messages)
        answer = response.content[0].text
        recorder.agent_finish(final_output=answer)
        return answer
    finally:
        # Flush the turn's chain to Langfuse before the request returns, and
        # close any observation the call left open if it raised.
        for transport in recorder.transports:
            transport.drain(timeout=5.0)


demo = gr.ChatInterface(fn=chat, title="Claude Opus 4.6 (Bedrock / Vindicara)")

if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0")
