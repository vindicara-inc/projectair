# NVIDIA ICC Summary Deck Content
## Vindicara / Project AIR

Copy-paste into the PPTX template. Trebuchet MS font, black/grey/green palette.

---

### SLIDE 1: Title

- **Company Name:** Vindicara
- **Date:** May 2026
- **Website:** vindicara.io
- **Founders:** Kevin Minn, Cameron Guyot

---

### SLIDE 2: Company Summary

**Vindicara builds the forensic evidence layer for AI agents.**

Project AIR is an open-source Python SDK that produces cryptographically signed, tamper-evident audit trails for every action an autonomous AI agent takes. Think of it as the black box flight recorder for AI: every decision, every tool call, every data access is captured in a chain that no one, not the vendor, not the cloud provider, not the operator, can alter after the fact.

- Founded: March 2026, Los Angeles, CA
- Incorporated: Vindicara, Inc. (Delaware C-Corp)
- Product: Project AIR (MIT-licensed SDK + AIR Cloud hosted service)
- Live on PyPI: projectair 0.8.1, 14 OWASP-aligned detectors, four cryptographic layers
- NVIDIA Inception member + NVIDIA Healthcare Developer Program

---

### SLIDE 3: The Problem

**AI agents are making decisions with zero forensic accountability.**

By 2028, 33% of enterprise software will include agentic AI (Gartner). These agents read patient records, execute financial transactions, and modify production infrastructure. When something goes wrong, there is no signed record of what happened, no tamper-proof chain of evidence, and no way to prove to an auditor or regulator what the agent actually did.

- HIPAA requires audit trails for every PHI access (45 CFR 164.312). AI agents accessing electronic health records produce no compliant evidence today.
- The EU AI Act (Article 72) mandates post-market monitoring for high-risk AI systems, effective August 2026. No commercial tool produces the required evidence automatically.
- The January 2025 HIPAA Security Rule NPRM eliminates "addressable" safeguards. Every audit control becomes mandatory.

The prevention layer (guardrails, sandboxes) is crowded. The evidence layer does not exist.

---

### SLIDE 4: Your Solution

**Project AIR: cryptographically signed forensic evidence for AI agents.**

Four lines of Python. Every agent action becomes a Signed Intent Capsule: content-hashed with BLAKE3, signed with Ed25519, chained so tampering breaks the chain at the exact altered record. Anchored to public Sigstore Rekor so anyone can verify without trusting Vindicara.

Four layers, independently adoptable:
1. **Detection:** 10/10 OWASP Agentic Top 10 + 3 LLM + 1 AIR-native (14 detectors)
2. **Verification:** RFC 3161 timestamps + Sigstore Rekor inclusion proofs
3. **Explanation:** Causal reasoning graph shows why each step happened
4. **Containment:** Auth0-verified human-in-the-loop halts unauthorized actions

Works today with LangChain, OpenAI, Anthropic, Google Gemini, Google ADK, LlamaIndex, and any OpenAI-compatible endpoint (NVIDIA NIM, NemoClaw/OpenShell, vLLM, Groq). One pip install: `pip install projectair`.

---

### SLIDE 5: What Makes You Unique

**No one else produces cryptographic evidence. Everyone else produces logs.**

| | Guardrails (Lakera, NeMo) | Observability (LangSmith, Arize) | Project AIR |
|---|---|---|---|
| Prevents bad actions | Yes | No | Yes (Layer 3) |
| Records what happened | No | Yes (logs) | Yes (signed chain) |
| Tamper-evident | No | No | Yes (BLAKE3 + Ed25519) |
| Publicly verifiable | No | No | Yes (Sigstore Rekor) |
| Human identity in chain | No | No | Yes (Auth0 JWT) |
| HIPAA audit controls | No | No | Yes (164.312 b/c/d) |

The moat: once a customer's signed chains are anchored to public Sigstore Rekor, switching away means losing the cryptographic proof history. The evidence is the lock-in, not the vendor.

Not replicable without building: Ed25519 chain signing, BLAKE3 content hashing, RFC 3161 timestamping, Sigstore integration, causal graph inference, Auth0 containment, and 14 OWASP detectors. 18 months of security engineering in a single pip install.

---

### SLIDE 6: Current Traction

- **Open source:** projectair on PyPI, MIT license, 0.8.1 shipped
- **NVIDIA Inception:** member (accepted April 2026)
- **NVIDIA Healthcare Developer Program:** member (accepted May 2026)
- **AIR Cloud:** live at cloud.vindicara.io (deployed May 12, 2026)
- **Framework coverage:** 7 integrations shipped (LangChain, OpenAI, Anthropic, Gemini, ADK, LlamaIndex) + any OpenAI-compatible endpoint (NIM, NemoClaw/OpenShell, vLLM)
- **Compliance reports:** EU AI Act Article 72, NIST AI RMF, SOC 2 AI templates ship in the SDK
- **Healthcare demo:** `air demo --healthcare` runs a HIPAA-aligned clinical AI scenario in 30 seconds
- **Dogfooding:** Vindicara runs AIR on its own production API, anchored to public Sigstore Rekor every 60 seconds

Pipeline: targeting health-tech companies deploying clinical AI on NVIDIA NemoClaw. First conversations in progress through NVIDIA Healthcare Developer Program channels.

---

### SLIDE 7: Funding

- **Currently raised:** $0 (bootstrapped)
- **Raising:** $750K pre-seed
- **Use of funds:**
  - **Engineering (50%):** hire 2 engineers. Ship Layer 4 Wave 2 (cross-tenant federation), NeMo Guardrails ingestion, enterprise IdP adapters (Okta, Entra ID). SOC 2 Type I certification.
  - **GTM (30%):** healthcare vertical sales. First 3 paying health system pilots. NVIDIA co-marketing through Inception + Healthcare Developer Program. AWS Startup Spotlight listing.
  - **Operations (20%):** legal (customer BAA template, HIPAA compliance counsel), infrastructure, 12-month runway buffer.
- **Why now:** the HIPAA NPRM comment period closed. The EU AI Act Article 72 deadline is August 2026. Healthcare AI deployments are accelerating. The compliance gap is opening faster than any vendor is closing it.

---

### SLIDE 8: Your Team

**Kevin Minn**
CEO / Founder
Cybersecurity + AI. Built 6 AI products at SLTR Digital including Luminetic. Full-stack engineer. Designed and shipped all four cryptographic layers of Project AIR. Los Angeles, CA.

**Cameron Guyot**
COO / Co-Founder
HR, operations, and growth. Leads team building, partnerships, and brand strategy at Vindicara. Drives go-to-market execution and NVIDIA program relationships.
