# ASI07 Insecure Inter-Agent Communication — Detector Design

Status: shipped in `projectair 0.2.0` on 2026-04-20. This doc is retained as reference for the implementation rationale; the canonical spec is the source code (`packages/projectair/src/airsdk/detections.py::detect_insecure_inter_agent_communication`) and the OWASP v12.6 spec it maps to.

## What OWASP says

OWASP Top 10 for Agentic Applications v12.6, category ASI07 ("Insecure Inter-Agent Communication"), gives six common examples:

1. Unencrypted / unauthenticated channel between agents.
2. Message tampering in transit.
3. Replay on trust chains.
4. Protocol downgrade (signed to unsigned mid-session).
5. Message-routing attacks / descriptor forgery (the sender's claimed `agent_card` or `well_known/agent.json` identity doesn't match their signing key).
6. Metadata analysis (out of scope for a detector; monitoring primitive).

The recommended mitigations (#2 specifically): *"Digitally sign messages, hash both payload and context, and validate for hidden or modified natural-language instructions."*

AIR already ships the primitives (BLAKE3 content hash, Ed25519 signature, prev-hash chain). ASI07 coverage is a **schema extension + detector**, not a crypto build.

## Schema extension

Current `StepKind` (in `packages/projectair/src/airsdk/types.py`):

```
LLM_START | LLM_END | TOOL_START | TOOL_END | AGENT_FINISH
```

Add one new kind:

```python
class StepKind(StrEnum):
    ...existing...
    AGENT_MESSAGE = "agent_message"
```

Extend `AgDRPayload` with four optional fields (extra="allow" today, but make them first-class for mypy + schema docs):

```python
class AgDRPayload(BaseModel):
    ...existing...
    source_agent_id: str | None = None   # who sent
    target_agent_id: str | None = None   # who received
    message_content: str | None = None   # the inter-agent message payload
    message_id: str | None = None        # UUIDv7 nonce for replay detection
```

The existing record-level `signature` + `signer_key` fields are unchanged. Each `AGENT_MESSAGE` record is signed by the sending agent's Ed25519 key exactly the same way every other record is signed today. That gives us message integrity (#2) and per-message authentication for free; the detector just has to verify + compare.

Bump `AGDR_VERSION` from `"0.1"` to `"0.2"`. Chain verification already tolerates missing optional payload fields, so v0.1 chains stay readable; v0.2 chains fail verification on v0.1-only clients, which is the right default.

## Detector logic

New module entry: `detect_insecure_inter_agent_communication(records) -> list[Finding]`, wired into `run_detectors()`.

Session-scoped state maintained while walking the chain:

- `claimed_keys: dict[str, str]` — first `signer_key` observed for each `source_agent_id`. Any later `AGENT_MESSAGE` from that agent with a different `signer_key` is flagged as impersonation (covers example #5).
- `seen_message_ids: set[str]` — every `message_id` observed. A repeat is a replay (covers #3).
- `prior_signed: dict[tuple[str, str], bool]` — per (`source_agent_id`, `target_agent_id`) pair, whether we've seen a signed message. A later unsigned/missing-sig message from the same pair is a downgrade (covers #4).

Five checks, five finding shapes. All `detector_id="ASI07"`:

| Check | Trigger | Severity | Covers |
|---|---|---|---|
| Missing identity | `AGENT_MESSAGE` with `source_agent_id` or `target_agent_id` empty | high | #1 unauthenticated channel |
| Missing signature | `AGENT_MESSAGE` with `signature` empty or malformed | high | #1, #2 |
| Sender/key mismatch | `signer_key` for a `source_agent_id` differs from first-observed | critical | #5 descriptor forgery / impersonation |
| Replay | `message_id` seen earlier in the session | high | #3 replay |
| Protocol downgrade | Pair (`src`, `dst`) had a signed message earlier, now sends unsigned | high | #4 downgrade |

Message tampering (#2) is covered by existing chain verification, which already runs before detectors; a tampered `AGENT_MESSAGE` record fails signature verification and aborts the trace before `detect_insecure_inter_agent_communication` is called. Document this explicitly in the module docstring so reviewers see the full coverage story.

Metadata analysis (#6) is explicitly out of scope for v0.2.

## Coverage scoring after ship

- OWASP Agentic Top 10: **4 of 10** (ASI01, ASI02, ASI04 partial, ASI07). Not 5. 5/10 requires one more detector; ASI06 Memory & Context Poisoning is the cheapest next candidate (pattern scan over context/memory payload fields for known-bad shapes: tool-description injection, retrieved-doc instruction smuggling, system-prompt overwrite patterns).
- `packages/projectair/README.md`, `/Users/KMiI/Desktop/vindicara/README.md`, and `CLAUDE.md` detector tables all have to update in the same PR that ships the detector. Do not let the claims and the code drift.

## Backwards compatibility

- `AGENT_MESSAGE` is a new enum value; existing single-agent traces don't emit it and are unaffected.
- Downstream readers pinned to `projectair<0.2` will fail `AGDR_VERSION` check on v0.2 chains. Release notes for 0.2.0 must call this out explicitly.
- CLI (`air trace`) falls back gracefully: if no `AGENT_MESSAGE` records appear, no ASI07 findings surface and the detector is a no-op. Single-agent users see zero behavioral change.

## Build estimate

- Schema bump + validation tests: 1 hour.
- Detector + unit tests (five checks, five finding shapes, adversarial cases): 2 to 3 hours.
- README / CLAUDE.md / `vindicara 0.2.0` changelog sync: 30 minutes.
- Demo trace extension (add two inter-agent steps to `_demo.py` so `air demo` surfaces an ASI07 finding alongside the existing two): 30 minutes.

Total: roughly half a day. Ship as `projectair 0.2.0` because `AGDR_VERSION` bumps.

## Open questions before coding

1. Does the MIT product want an agent-identity registry (config file mapping `agent_id -> expected_pubkey`) for strict sender verification, or do we stay session-scoped first-seen-wins? First-seen-wins is cheaper and catches impersonation-within-a-trace; registry catches impersonation-at-ingest. Probably session-scoped for 0.2, registry as a 0.3 follow-up.
2. Do we want to emit a CycloneDX-compatible agent-card reference in the `AGENT_MESSAGE` payload now (to enable #5 descriptor-forgery detection against a real AIBOM), or defer that to the CycloneDX ingestion work on the v0.3 roadmap? Defer. The session-scoped sender-key check already covers the most important subset of #5.
3. Should `detect_insecure_inter_agent_communication` require both `signature` and `signer_key` to be non-empty, or trust the record schema (which already requires them)? Pydantic enforces them, so trust the schema; only flag when the *claim* is missing (no `source_agent_id`) versus the crypto being malformed (already caught in chain verification).
