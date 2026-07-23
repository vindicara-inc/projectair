"""End-to-end demo: faithful capture of a non-deterministic decision.

Runs a single stochastic LLM call through the OpenAI instrumentation and
shows that the signed chain captures not just *what* the model said, but the
non-deterministic conditions that produced it: the resolved model snapshot,
the backend fingerprint, the sampling parameters, and the shape of the
probability distribution the output was sampled from.

The claim this earns is precise: **faithful, attributable, tamper-evident
capture of a non-deterministic decision, mapped to ALCOA+.** It does NOT
claim the decision is reproducible (hosted stochastic inference is not
bitwise reproducible even with a fixed seed) and it does NOT make the
system a validated (CSV/GAMP 5) system for regulated use. It makes the
*record* faithful.

No network and no ``openai`` package required: the demo uses a stand-in
client shaped exactly like ``openai.OpenAI()`` so a customer can run it in
under 60 seconds with zero setup.

    PYTHONPATH=src python scripts/e2e_provenance.py
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from types import SimpleNamespace

from airsdk.agdr import load_chain, verify_chain
from airsdk.integrations.openai import instrument_openai
from airsdk.recorder import AIRRecorder
from airsdk.types import StepKind, VerificationStatus


def _stand_in_client() -> SimpleNamespace:
    """A client shaped like ``openai.OpenAI()`` that returns a realistic response.

    Carries the same provenance surface a real OpenAI chat completion does:
    a resolved snapshot (``model``), a ``system_fingerprint``, token ``usage``,
    and per-token ``logprobs`` on the chosen tokens.
    """
    token_logprobs = [
        SimpleNamespace(logprob=-0.02),  # "Approve"
        SimpleNamespace(logprob=-0.71),  # the model was less sure here
        SimpleNamespace(logprob=-0.15),
    ]
    message = SimpleNamespace(content="Approve the refund of $840.", tool_calls=None)
    choice = SimpleNamespace(
        message=message,
        index=0,
        finish_reason="stop",
        logprobs=SimpleNamespace(content=token_logprobs),
    )
    response = SimpleNamespace(
        id="chatcmpl-demo",
        choices=[choice],
        model="gpt-4o-2024-08-06",  # resolved snapshot, not the "gpt-4o" alias
        system_fingerprint="fp_44709d6fcb",
        usage=SimpleNamespace(prompt_tokens=214, completion_tokens=8),
    )
    create = SimpleNamespace(create=lambda **_: response)
    return SimpleNamespace(chat=SimpleNamespace(completions=create))


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        log_path = Path(tmp) / "decision.log"
        recorder = AIRRecorder(log_path=log_path, user_intent="Adjudicate a customer refund")
        client = instrument_openai(_stand_in_client(), recorder)

        # A non-deterministic decision: temperature > 0, so the output is sampled.
        client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Customer disputes an $840 charge. Decide."}],
            temperature=0.7,
            top_p=0.95,
            seed=7,
            max_tokens=64,
            logprobs=True,
        )

        records = load_chain(log_path)
        decision = next(r for r in records if r.kind is StepKind.LLM_END)
        prov = decision.payload.provenance
        assert prov is not None, "provenance was not captured"

        print("Decision captured:", decision.payload.response)
        print()
        print("Non-deterministic provenance recorded in the signed chain:")
        print(f"  model (requested)   : {prov.model}")
        print(f"  model_version       : {prov.model_version}   <- resolved snapshot")
        print(f"  system_fingerprint  : {prov.system_fingerprint}   <- silent backend change is detectable")
        print(f"  temperature/top_p   : {prov.temperature} / {prov.top_p}")
        print(f"  seed                : {prov.seed}")
        print(f"  finish_reason       : {prov.finish_reason}")
        print(f"  tokens (in/out)     : {prov.prompt_tokens} / {prov.completion_tokens}")
        if prov.logprobs is not None and prov.logprobs.available:
            lp = prov.logprobs
            print(f"  logprobs            : mean {lp.mean_logprob:.3f}, "
                  f"min {lp.min_logprob:.3f} over {lp.token_count} tokens  <- distribution shape")
        print()

        status = verify_chain(records).status
        print(f"Chain verifies: {status.value}")

        # Provenance is inside the signed content: altering it breaks verification.
        prov.temperature = 0.0
        tampered = verify_chain(records).status
        print(f"After rewriting the recorded temperature, chain verifies: {tampered.value}")

        ok = status is VerificationStatus.OK and tampered is not VerificationStatus.OK
        print()
        print("PASS: the stochastic conditions are captured and tamper-evident."
              if ok else "FAIL")
        return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
