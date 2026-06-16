# Detector Taxonomy

Full detector coverage for Project AIR. Referenced from root `CLAUDE.md`. For architecture and layered trust contracts, see `docs/ARCHITECTURE.md`.

## OWASP Top 10 for Agentic Applications (10 of 10)

- `ASI01` Agent Goal Hijack
- `ASI02` Tool Misuse & Exploitation
- `ASI03` Identity & Privilege Abuse (shipped 0.3.0; Zero-Trust-for-agents via `AgentRegistry`: identity forgery / unknown agent / out-of-scope tool / privilege-tier escalation)
- `ASI04` Agentic Supply Chain Vulnerabilities (partial, MCP only)
- `ASI05` Unexpected Code Execution (shipped 0.2.2)
- `ASI06` Memory & Context Poisoning (shipped 0.2.1)
- `ASI07` Insecure Inter-Agent Communication (shipped 0.2.0)
- `ASI08` Cascading Failures (shipped 0.2.4; oscillating-pair threshold 4 cycles + fan-out threshold 5 distinct targets / 10-record window, operating over AGENT_MESSAGE records)
- `ASI09` Human-Agent Trust Exploitation (shipped 0.2.3)
- `ASI10` Rogue Agents (shipped 0.3.0; Zero-Trust behavioral-scope enforcement via `BehavioralScope`: unexpected tool / fan-out breach / off-hours activity / session tool budget)

`UNIMPLEMENTED_DETECTORS` is now empty.

## OWASP Top 10 for LLM Applications (3 categories)

Implemented as AIR-specific detectors:

- `AIR-01` -> LLM01 Prompt Injection
- `AIR-02` -> LLM06 Sensitive Information Disclosure
- `AIR-03` -> LLM04 Model Denial of Service

## AIR-native detectors

- `AIR-04` Untraceable Action (forensic-chain-integrity check; no direct OWASP equivalent)
- `AIR-05` NemoGuard Safety Classification (critical/high/medium severity scaled by safety category; 0.9.0)
- `AIR-06` NemoGuard Corroboration (cross-corroboration between AIR heuristic detectors and NemoGuard NIM classifiers; 0.9.0)

## Correct public framing (as of 0.9.0)

**"10 OWASP Agentic + 3 OWASP LLM + 3 AIR-native."** Detector count is **16 total**. Every public claim must cite this exact taxonomy. Never revert to the "14" or "8 of 10" framing from earlier releases.

## ASI10 framing discipline

**ASI10 is Zero-Trust enforcement, not anomaly detection.** Frame it as declared-scope enforcement in every doc, docstring, README, and HN post. The learned-baseline anomaly-detection variant (statistical profiling, peer comparison) is explicitly on the roadmap for a later release and is labelled as such in `detections.py`. Calling the shipped detector "anomaly detection" is overclaim.

## AIR-04 vs ASI10: do not conflate

AIR-04 detects gaps in our own chain (missing tool_end records, silent intervals). ASI10 Rogue Agents is about agents acting outside their authorization scope / stealth infiltration. OWASP lists signed audit logs as a *mitigation* for ASI10, not a detection signal. Calling AIR-04 "ASI10 coverage" is overclaim. Real ASI10 coverage requires a behavioral-scope detector.
