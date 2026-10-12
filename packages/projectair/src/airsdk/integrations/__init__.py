"""Framework integrations for airsdk.

Each submodule provides a small wrapper that instruments a specific AI SDK
to emit AgDR records through an :class:`airsdk.recorder.AIRRecorder`.

Available:
    - openai      (instrument_openai)
    - anthropic   (instrument_anthropic)
    - llamaindex  (instrument_llamaindex)

Observability sinks (a transport, not a wrapper: covers every integration
above at once because the recorder fans each record out to every transport):
    - langfuse    (LangfuseTransport)

Planned:
    - crewai
    - autogen
"""
