"""Framework integrations for airsdk.

Each submodule provides a small wrapper that instruments a specific AI SDK
to emit AgDR records through an :class:`airsdk.recorder.AIRRecorder`.

Available:
    - openai  (instrument_openai)

Planned:
    - anthropic
    - llamaindex
"""
