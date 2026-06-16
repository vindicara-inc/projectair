"""Gradio chat UI for Claude on AWS Bedrock (Vindicara account)."""

import gradio as gr
from anthropic import AnthropicBedrock

client = AnthropicBedrock(
    aws_profile="vindicara",
    aws_region="us-west-2",
)

MODEL = "us.anthropic.claude-opus-4-6-v1"


def chat(message: dict, history: list[dict]) -> str:
    messages = []
    for msg in history:
        messages.append({"role": msg["role"], "content": msg["content"]})
    messages.append({"role": "user", "content": message["text"]})

    response = client.messages.create(
        model=MODEL,
        max_tokens=4096,
        messages=messages,
    )
    return response.content[0].text


demo = gr.ChatInterface(fn=chat, title="Claude Opus 4.6 (Bedrock / Vindicara)")

if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0")
