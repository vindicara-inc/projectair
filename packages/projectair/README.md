<p align="center">
  <strong>Project AIR™</strong><br>
  Forensic governance for autonomous AI agents.
</p>

<p align="center">
  <a href="https://vindicara.io">vindicara.io</a> ·
  <a href="https://vindicara.io/blog/secure-ai-agents-5-minutes">Quickstart</a> ·
  <a href="https://vindicara.io/pricing">Pricing</a>
</p>

---

## What this is

When an AI agent breaks something in production, Project AIR is how you prove what happened, explain why, and stop it from happening again.

Every agent decision is written as a **Signed Intent Capsule** (the pattern named in [OWASP Top 10 for Agentic Applications v12.6](https://owasp.org/www-project-top-10-for-large-language-model-applications/) as ASI01 mitigation #5: a signed envelope binding the declared goal, constraints, and context to each execution cycle). Each capsule carries a BLAKE3 content hash and an Ed25519 signature, chained to the previous step. The chain root is anchored to two independent public proofs: an RFC 3161 trusted timestamp and a [Sigstore Rekor](https://docs.sigstore.dev/) transparency-log entry. The result is evidence that:

- **Survives subpoena.** Any auditor can verify the chain using only public infrastructure (FreeTSA, `rekor.sigstore.dev`) plus the chain file itself. No Vindicara API call required.
- **Survives the vendor.** No party, including Vindicara, the customer, or the agent vendor, can backdate or alter the chain after the fact.
- **Survives the auditor's first question.** "Who could have edited this?" has a one-word answer: nobody.
- **Survives compliance review.** When a high-value action requires human authorization, the chain records the authenticated approver via Auth0 step-up. The chain is not just an audit trail. It is a consent record.

Project AIR is the governance standard for agent runtime accountability.

## Install

```bash
pip install projectair
```

This installs the `air` terminal command and the `airsdk` Python library.

## Try it cold

```bash
air demo
```

That generates a fresh signed capsule chain (the SSH-exfiltration attack narrative), verifies every signature, runs the detectors, and writes a `forensic-report.json` next to you. Full cold-start in one command, no agent wiring required.

## The four-layer stack

| Layer | What it does | Status |
|---|---|---|
| **1. External Trust Anchor** | RFC 3161 trusted timestamps + Sigstore Rekor transparency log | shipped (0.4.0) |
| **2. Causal Reasoning** | `air explain` walks the chain, explains why a step happened | shipped (0.5.0) |
| **3. Containment + Step-Up** | Halt agent actions; require Auth0-verified human approval for high-stakes calls | shipped (0.6.0, 0.6.1) |
| **4. AgDR Handoff Protocol (A2A)** | Cryptographically linked Parent Trace IDs across multi-agent, multi-org chains | roadmap |

Layers 1-3 secure the single agent. Layer 4 secures the distributed agentic economy.

### Layer 1: anchor your chain to public infrastructure

```python
from airsdk import AIRRecorder
from airsdk.anchoring import (
    AnchoringOrchestrator, AnchoringPolicy, RFC3161Client, RekorClient, load_anchoring_key,
)

recorder = AIRRecorder("chain.jsonl", user_intent="Refactor the auth module.")
orchestrator = AnchoringOrchestrator(
    signer=recorder.signer,
    transports=recorder.transports,
    rfc3161_client=RFC3161Client(),                       # FreeTSA by default
    rekor_client=RekorClient(signing_key=load_anchoring_key()),
    policy=AnchoringPolicy(anchor_every_n_steps=100, anchor_every_n_seconds=10),
)
recorder.attach_orchestrator(orchestrator)
```

Verify any chain using only public infrastructure:

```bash
air verify-public chain.jsonl
```

**Live verification proof.** A reference chain produced by `scripts/e2e_layer1.py` was anchored to the public Sigstore Rekor on 2026-05-07 and re-verified from a clean environment. Look it up at <https://search.sigstore.dev/?logIndex=1455601514>. The entry's existence is independent of Vindicara.

### Layer 2: explain why a step happened

```bash
air explain chain.jsonl --finding ASI02
```

The output is a narrowed evidence excerpt: the load-bearing 5-7 records that caused the finding, with edges marked **hard** (derived from explicit AgDR fields) or **soft** (inferred by content match). Hard edges go in your report. Soft edges go in your supporting context.

For the SSH-exfil demo chain, `air explain --finding ASI02` returns:

```
step 2  tool_start  read_file(./README.md)
step 3  tool_end    poisoned README content
step 4  llm_start   prompt with README content       ~~ 3 (output_reuse)
step 5  llm_end     "I'll fetch the SSH key"         <- 4 (llm_pair)
step 6  tool_start  read_file(/.ssh/id_rsa)          <- 5 (llm_decision)
step 7  tool_end    leaked SSH key
* step 8  tool_start  http_post(attacker URL)        <- 5 (llm_decision)
                                                     ~~ 7 (output_reuse)
```

That is the forensic narrative an analyst can put in a report.

### Layer 3: containment with Auth0-verified step-up

Halt the agent before a high-stakes action runs. Require an authenticated human to approve. Record the approval as part of the chain.

```python
from airsdk import AIRRecorder
from airsdk.containment import (
    Auth0Verifier, ContainmentPolicy, StepUpRequiredError,
)

policy = ContainmentPolicy(
    deny_tools=["shell_exec"],                         # never, under any circumstances
    deny_arg_patterns={"http_post": {"url": r"attacker\."}},
    block_on_findings=["AIR-01"],                      # halt if prompt injection detected upstream
    step_up_for_actions=[                              # require human approval for these
        {"tool": "stripe_charge"},
        {"tool": "send_email", "to_domain": "external"},
    ],
)
verifier = Auth0Verifier(
    issuer="https://my-tenant.us.auth0.com/",
    audience="https://api.acme.io",
)

recorder = AIRRecorder(
    "chain.jsonl",
    containment=policy,
    auth0_verifier=verifier,
)

# Inside the agent loop:
try:
    recorder.tool_start(tool_name="stripe_charge", tool_args={"amount_cents": 99999})
except StepUpRequiredError as e:
    # Halt. Present e.challenge_id to the responsible human via Auth0 push,
    # email, Slack, or your own dispatcher. They authenticate against your
    # Auth0 tenant. You receive an access token. Then:
    recorder.approve(e.challenge_id, auth0_token)
    # Action resumes; HUMAN_APPROVAL record carries the verified Auth0 claims
    # plus the signed JWT for offline re-verification.
```

For headless agents, `air approve --device --client-id <id>` runs the OAuth 2.0 Device Authorization Grant from your terminal. The CLI prints a user code and verification URL. The operator authenticates on their phone. The CLI polls until done, then submits the approval.

For browser flows, `air approve --authorize-url --client-id <id> --redirect-uri <uri>` prints a well-formed Auth0 `/authorize` URL with PKCE.

The `HUMAN_APPROVAL` record on the chain binds the action to the authenticated human who authorized it. This maps directly to **EU AI Act Article 14** (human oversight), **GDPR Article 22** (automated decision-making with human intervention), and **SOC 2 access controls**.

### Layer 4: AgDR Handoff Protocol (A2A)

Cross-organization, multi-agent workflows. When Agent A (finance) hires Agent B (travel) to book a flight, Agent B's chain physically includes a Handoff Step that references Agent A's latest Rekor-anchored hash. Causal continuity across chains. Proof of delegation. Cabinet (Vindicara's commercial UI) renders these as a global cross-org accountability graph. **In active design.**

## Detector coverage

The chain itself is production-grade cryptography. The detectors are honest first-pass heuristics: they will produce false positives and false negatives. Coverage today across three taxonomies:

**OWASP Top 10 for Agentic Applications (10 of 10 implemented):**

| Detector | Mapping |
|---|---|
| ASI01 Agent Goal Hijack | implemented |
| ASI02 Tool Misuse & Exploitation | implemented |
| ASI03 Identity & Privilege Abuse | Zero-Trust-for-agents via operator-declared `AgentRegistry` |
| ASI04 Agentic Supply Chain Vulnerabilities | partial: MCP supply-chain risk only |
| ASI05 Unexpected Code Execution | implemented |
| ASI06 Memory & Context Poisoning | implemented |
| ASI07 Insecure Inter-Agent Communication | implemented |
| ASI08 Cascading Failures | implemented |
| ASI09 Human-Agent Trust Exploitation | implemented |
| ASI10 Rogue Agents | Zero-Trust behavioral-scope enforcement via declared `BehavioralScope` |

**OWASP Top 10 for LLM Applications (3 categories covered):**

| Detector | Mapping |
|---|---|
| AIR-01 Prompt Injection | OWASP LLM01 |
| AIR-02 Sensitive Data Exposure | OWASP LLM06 |
| AIR-03 Resource Consumption | OWASP LLM04 |

**AIR-native (1 detector):** AIR-04 Untraceable Action (forensic-chain-integrity check, no direct OWASP equivalent).

Total: **10 + 3 + 1 = 14 detectors** running over every chain, mapped to public taxonomies wherever possible.

## Instrument your agent

### LangChain

```python
from airsdk import AIRCallbackHandler
from langchain.agents import AgentExecutor

handler = AIRCallbackHandler(
    key="...",                           # Ed25519 signing key (hex or PEM); auto-generated when omitted
    log_path="my-agent.log",
    user_intent="Draft a Q3 sales report from the CRM data",
)
agent = AgentExecutor(callbacks=[handler], ...)
```

### OpenAI SDK (and any OpenAI-compatible endpoint)

```python
from openai import OpenAI
from airsdk import AIRRecorder
from airsdk.integrations.openai import instrument_openai

recorder = AIRRecorder(log_path="my-agent.log", user_intent="Draft a Q3 sales report")
client = instrument_openai(OpenAI(), recorder)

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "..."}],
)
```

The same wrapper works with **NVIDIA NIM**, **vLLM**, **TGI**, **Together AI**, **Groq**, **Mistral**, and **Fireworks** by pointing the `OpenAI()` client at the target endpoint. See `examples/nim_demo.py` for a runnable Llama 3.3 70B Instruct example.

### Anthropic SDK

```python
from anthropic import Anthropic
from airsdk import AIRRecorder
from airsdk.integrations.anthropic import instrument_anthropic

recorder = AIRRecorder(log_path="my-agent.log", user_intent="Draft a Q3 sales report")
client = instrument_anthropic(Anthropic(), recorder)

response = client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=1024,
    messages=[{"role": "user", "content": "..."}],
)
```

### LlamaIndex

```python
from llama_index.llms.openai import OpenAI as LlamaOpenAI
from airsdk import AIRRecorder
from airsdk.integrations.llamaindex import instrument_llamaindex

recorder = AIRRecorder(log_path="my-agent.log", user_intent="Draft a Q3 sales report")
llm = instrument_llamaindex(LlamaOpenAI(model="gpt-4o"), recorder)

response = llm.complete("Draft the opening paragraph.")
```

The wrapped LLM is a duck-typed proxy. It works wherever LlamaIndex calls the LLM directly; components that run Pydantic validation against the `LLM` type (some query engines, `Settings.llm`) will reject the proxy. In those flows, instrument call sites in your own code or attach the recorder to a callback. Requires llama-index >= 0.10.

### Google Gemini SDK and Google ADK

```python
from google import genai
from airsdk import AIRRecorder, instrument_gemini, instrument_adk
```

`instrument_gemini` wraps a `google.genai.Client` for `models.generate_content`, `chats.send_message`, and `aio.*` async calls. `instrument_adk` attaches AIR callbacks to a constructed `LlmAgent` via the four ADK callback hooks.

### Custom code (any framework)

```python
from airsdk import AIRRecorder

recorder = AIRRecorder(log_path="my-agent.log")
recorder.llm_start(prompt="...")
recorder.llm_end(response="...")
recorder.tool_start(tool_name="crm_read", tool_args={"account": "acme"})
recorder.tool_end(tool_output="...")
recorder.agent_finish(final_output="...")
```

For tool calls your code executes, wrap them with `recorder.tool_start(...)` / `recorder.tool_end(...)` so the forensic chain captures them too.

## CLI surface

```
air demo                  Run the brutal cold-start demo end to end
air trace <chain>         Verify signatures, run detectors, emit forensic report
air verify <chain>        Verify chain integrity (signatures + chain links)
air verify-public <chain> Verify the chain using only public infrastructure
air anchor <chain>        Force-emit an anchor record covering the unanchored tail
air explain <chain>       Causal explanation: --step <id> | --finding <detector_id>
air approve               Layer 3 step-up approval: --token | --device | --authorize-url
air report article72      Generate EU AI Act Article 72 post-market monitoring template
```

## Why AIR exists

The prevention layer is crowded. Lakera, NeMo Guardrails, Bedrock Guardrails, and a dozen other tools sit in front of your agent and try to stop bad things from happening. None of them tell you what actually happened when an agent ran, none of them produce evidence an auditor or regulator or insurance carrier can use, and none of them bind a high-stakes action to the authenticated human who authorized it.

AIR is the forensic, causal, and containment layer that runs behind those tools. It does not replace them. It gives you a signed record of every agent decision, an explanation of why each step happened, and a runtime contract that halts unauthorized actions and captures who approved the ones that proceeded.

## Roadmap

- **Layer 4 AgDR Handoff Protocol (A2A):** in active design. Cryptographically linked Parent Trace IDs for multi-agent, multi-org workflows.
- **ML-DSA-65 post-quantum hybrid signatures:** Layer 1 v2, planned Q3 2026.
- **Notary co-signing network:** Layer 1 v3, 2027.
- **CrewAI, AutoGen, AG2 framework integrations:** queued.
- **Cabinet:** the commercial enterprise UI for cross-org workflow visualization.

## License

MIT. See [LICENSE](LICENSE).

## Contributing

The chain crypto is locked; the detector heuristics evolve. Issues, traces that break the detectors, and new ASI detector PRs are all welcome at <https://github.com/vindicara-inc/projectair>.
