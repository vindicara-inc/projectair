# Nullify AI

## AI Decision Control for Regulated Industries

### The One-Liner

Nullify AI intercepts, evaluates, and controls every decision an AI agent makes before it reaches the real world, preventing costly errors in regulated industries where a single bad AI decision carries a dollar figure.

---

## The Insight Nobody Is Acting On

The AI security market is crowded with companies protecting AI FROM attacks: prompt injection, jailbreaks, data poisoning, model theft. Lakera ($30M raised, acquired by Check Point for $190M), CalypsoAI (acquired by F5), Robust Intelligence (acquired by Cisco), HiddenLayer, Protect AI. They all ask the same question: "Is someone trying to hack this AI?"

Nobody is asking the more dangerous question: "What happens when the AI is working exactly as designed but makes a bad business decision?"

An insurance claims agent that approves 200 claims per hour at a 3% error rate costs the company $2.4M annually in bad payouts. The AI wasn't hacked. It wasn't jailbroken. It just miscalibrated. And nobody caught it because monitoring tools built for human-speed workflows have no answer for AI-speed decisions.

Lakera stops a hacker from tricking your AI. Nullify stops your AI from tricking your business.

---

## The Market

### Timing

The EU AI Act mandates real-time monitoring, human oversight, and documented controls for high-risk AI systems by August 2, 2026. Penalties: up to EUR 30 million or 6% of global revenue. This is not optional.

High-risk categories include: credit decisions, insurance underwriting, employment screening, healthcare triage, legal document analysis. Every company deploying AI in these domains needs runtime decision control.

### Size

- AI governance market: projected $109.9B by 2034 (65.8% CAGR)
- GRC tool investment: 50% growth by 2026 (Gartner)
- Enterprise AI security: $8.1B in 2025, growing to $38.2B by 2030
- Compliance automation alone: $12.3B market by 2028

### Who Pays

- Insurance companies using AI claims processing
- Banks and lenders using AI credit decisions
- Healthcare systems using AI triage and diagnosis support
- Legal firms using AI document review
- Any enterprise deploying AI agents in regulated workflows

These are not startups experimenting with AI. These are Fortune 500 companies with mandatory compliance budgets.

---

## The Product

### What Nullify Does

Nullify AI sits as a runtime control layer between an AI agent and the real world. Every decision the agent makes gets intercepted, evaluated against behavioral rules, and either approved, flagged, or blocked before it executes.

```
AI Agent Decision > Nullify API (intercept) > Behavioral Rules Engine > Verdict (approve/flag/block) > Execute or Halt
```

### Core Capabilities

**1. Decision Interception**
A single API call wraps any AI agent's output. Works with OpenAI, Anthropic Claude, AWS Bedrock, Azure OpenAI, Google Vertex AI, and any custom agent framework. Integration takes hours, not weeks.

```python
# Before: AI agent acts directly
result = agent.process_claim(claim_data)
execute(result)

# After: Nullify intercepts
result = agent.process_claim(claim_data)
verdict = nullify.evaluate(result, context=claim_data)
if verdict.approved:
    execute(result)
else:
    escalate_to_human(result, verdict.reason)
```

**2. Behavioral Rules Engine**
Not just "is this output safe?" but "does this decision make business sense?"

Rules examples:
- Insurance: "No claim approval above $50K without human review"
- Lending: "Reject any approval where debt-to-income exceeds 43%"
- Healthcare: "Flag any triage that downgrades severity from the initial assessment"
- Legal: "Block any contract modification that changes liability terms"

Rules are configurable per deployment, per agent, per use case. No code changes required.

**3. Behavioral Drift Detection**
Monitor patterns across thousands of decisions to detect when an AI agent's behavior shifts.

- Agent approved 12% of high-value claims last week, 23% this week. Why?
- Average processing time dropped 40%. Is the agent cutting corners?
- Agent is routing 3x more cases to "auto-approve" than baseline. Flag it.

This is the moat. The behavioral baselines improve with every decision processed. Competitors would need matching access to real decision data to replicate this.

**4. Compliance Evidence Generation**
Every decision, every rule evaluation, every verdict is logged with full audit trail. Exportable as structured evidence packages that map directly to:
- EU AI Act Article 9 (risk management), Article 12 (record-keeping), Article 14 (human oversight)
- NIST AI RMF (Govern, Map, Measure, Manage functions)
- ISO/IEC 42001 (AI management systems)
- SOC 2 AI controls

Auditors get evidence tied to specific AI executions, not dashboards and screenshots.

**5. Human-in-the-Loop Orchestration**
When Nullify blocks a decision, it doesn't just stop. It routes to the right human with the right context.

- Configurable escalation paths (Slack, email, ticketing systems, custom webhooks)
- Decision context summary: what the agent decided, why Nullify flagged it, what rules were triggered
- Human approves, modifies, or rejects. Decision logged. Agent learns from the correction.

---

## What Makes This Different

### The Existing Market Map

| Category | Players | What They Do | What They Miss |
|----------|---------|-------------|---------------|
| Input/Output Guardrails | Lakera, NeMo, LLM Guard | Block prompt injections, filter harmful content | Don't evaluate business logic or decision quality |
| AI Security Platforms | HiddenLayer, Protect AI | Detect adversarial attacks, model vulnerabilities | Focus on model-level threats, not decision-level control |
| AI Governance / GRC | Holistic AI, AIceberg, Credo AI | Documentation, risk assessments, policy management | Pre-deployment focus. No runtime decision interception. |
| Agent Runtime Security | GuardionAI, Keycard | Tool authorization, agent identity management | Authorize what agents CAN do, not whether what they DID was correct |

### Nullify's Position

None of these evaluate whether an AI agent's actual business decision is correct, compliant, and within acceptable parameters BEFORE it executes. They either protect the model from attacks or document governance after the fact. Nullify controls the decision in real time.

The closest analogy: Lakera is antivirus for AI. Nullify is a compliance officer for AI.

---

## Go-To-Market

### Phase 1: Insurance (Months 1-6)

Why insurance first:
- Highest dollar cost per bad AI decision (claims payouts are irreversible)
- Most advanced in AI agent adoption (claims processing, underwriting, fraud detection)
- Heavy regulatory pressure (state insurance commissioners + EU AI Act)
- Clear ROI calculation: reduce bad claim approvals by X% = $Y saved

Entry strategy:
- Target 3 mid-market insurance companies with active AI claims processing
- Offer 90-day pilot at reduced rate ($25K) with defined success metrics
- Hands-on onboarding: manually build behavioral rules for their specific workflows
- This is consulting disguised as software. The hands-on work builds the behavioral library.

### Phase 2: Expand to Lending + Healthcare (Months 6-12)

- Take insurance playbook and adapt rules for lending decisions (credit approvals, rate setting)
- Healthcare triage AI is growing fast and has life-safety implications
- Each vertical adds to the behavioral library, making the platform smarter across industries

### Phase 3: Self-Serve Platform (Months 12-18)

- Package the behavioral library into templates (insurance pack, lending pack, healthcare pack)
- Launch self-serve API with usage-based pricing
- Open marketplace for community-contributed rule sets

---

## Pricing

| Tier | Price | For |
|------|-------|-----|
| Pilot | $25K for 90 days | Initial deployment, custom rule building, hands-on support |
| Standard | $50K-$100K/year | Single workflow, up to 100K decisions/month, standard rules |
| Enterprise | $200K-$500K/year | Multi-workflow, unlimited decisions, custom rules, dedicated support |
| Platform (future) | Usage-based ($0.01-0.05 per decision) | Self-serve API for smaller deployments |

### Revenue Projections

Year 1: 3 pilot customers > 2 convert to annual = $150K ARR
Year 2: 8 enterprise customers across 2 verticals = $800K ARR
Year 3: 20 customers + self-serve launch = $3M+ ARR

---

## Technical Architecture

```
Enterprise AI Agent (OpenAI / Claude / Bedrock / Custom)
        |
        v
   Nullify SDK (lightweight wrapper)
        |
        v
   Nullify API Gateway (< 50ms latency)
        |
        v
   Rules Engine (behavioral rules + drift detection)
        |
        v
   Verdict: APPROVE / FLAG / BLOCK
        |
   +----+----+
   |         |
APPROVE    FLAG/BLOCK
   |         |
Execute    Route to human + log evidence
```

### Stack

| Component | Technology |
|-----------|-----------|
| API Gateway | Next.js API routes or Fastify on AWS |
| Rules Engine | Custom TypeScript engine with configurable rule DSL |
| Drift Detection | Statistical analysis on decision patterns (mean, variance, anomaly detection) |
| Data Store | DynamoDB (decisions, verdicts, audit logs) |
| Evidence Export | PDF/JSON structured reports mapped to EU AI Act articles |
| SDKs | Python, TypeScript, REST API |
| Hosting | AWS (you already have Amplify, Bedrock, DynamoDB experience) |
| Monitoring | CloudWatch + custom dashboards |

### Why You Can Build This

- You build with Claude, Bedrock, and OpenAI daily across six products. You understand the agent pipeline from the inside.
- Your cybersecurity degree covers exactly the compliance, risk management, and audit frameworks this product requires.
- The core product is an API layer with a rules engine. This is well within your technical capability as a solo founder.
- AWS is already offering to build alongside you with their AI Roadmap Workshop.

---

## Competitive Moat

### What Gets Stronger Over Time

1. **Behavioral Library**: Every customer deployment adds real-world decision patterns. After 12 months of processing insurance claims decisions, your rules and drift detection are trained on data no competitor can access without matching deployments.

2. **Compliance Templates**: Structured evidence packages that auditors have already accepted become the standard. Once an auditor approves Nullify's format for EU AI Act compliance, every customer in that industry wants the same format.

3. **Switching Cost**: Once behavioral rules are configured for a customer's specific workflows, switching to a competitor means rebuilding all rules from scratch and losing the behavioral baseline history.

---

## Risk Assessment

### Real Risks

| Risk | Severity | Mitigation |
|------|----------|-----------|
| Large players (AWS, Google, Microsoft) build this natively | High | They will build generic guardrails, not vertical-specific decision control. AWS Bedrock Guardrails already exists but only handles content filtering, not business logic evaluation. Stay vertical-specific. |
| Lakera/Check Point expands from security to decision control | Medium | Lakera's DNA is security (prompt injection, data loss). Decision-level business logic is a fundamentally different product. Possible but not their core competency. |
| Enterprises build in-house | Medium | Most enterprises lack the specialized AI compliance expertise. In-house solutions don't generate cross-industry behavioral data. Position as "build vs. buy" with clear ROI. |
| EU AI Act deadline postponed to Dec 2027 | Low-Medium | The European Commission proposed this but it is not confirmed. Plan for August 2026 and treat any extension as bonus runway. |
| Sales cycle too long for enterprise | High | Mitigate with pilot pricing ($25K/90 days) and clear ROI metrics. Target compliance teams, not engineering teams. Compliance has budget and urgency. |

### What Could Kill This

- If AI agent adoption slows dramatically in regulated industries (unlikely given current trajectory)
- If a well-funded competitor ($50M+) laser-focuses on the same position (monitor closely)
- If you cannot get 3 pilot customers in the first 6 months (validate demand immediately)

---

## Why This Founder

**Kevin Minn**

- **Cybersecurity student (4.0 GPA)**: The compliance frameworks (NIST RMF, ISO 42001, SOC 2) that this product maps to are literally what you study.
- **Solo technical founder with 6 shipped AI products**: You build with the same AI infrastructure (Claude, Bedrock, OpenAI) that your customers' agents run on. You understand the pipeline from the inside.
- **Security-first development philosophy**: Your entire engineering approach is root-cause, security-first. This is a cybersecurity product at its core.
- **AWS relationship**: AWS is already offering dedicated engineering support. Nullify would run on AWS infrastructure and could become an AWS Partner Network solution.

---

## The Ask

**$500K pre-seed**

Use of funds:
- 3 enterprise pilot deployments (travel, onboarding, custom rule building): $80K
- Engineering (infrastructure, API, SDKs, dashboards): $150K (your time + selective contractors)
- Compliance certifications (SOC 2 Type I): $50K
- Sales and marketing (enterprise, content, events): $100K
- Operations and legal: $60K
- Runway buffer: $60K

Timeline to milestones:
- Month 3: MVP deployed with first pilot customer
- Month 6: 3 pilots running, first annual conversion
- Month 9: Second vertical (lending) launched
- Month 12: $150K+ ARR, raise seed round

---

## Immediate Next Steps

### This Week
1. Validate demand: Contact 5 insurance companies that are publicly deploying AI for claims processing. Ask their compliance teams: "How are you monitoring your AI agents' decisions for accuracy and compliance?"
2. Research: Map every company deploying AI agents in insurance claims (Tractable, Shift Technology, Lemonade, Snapsheet). These are potential customers AND proof of market.
3. Register the domain (nullifyai.com or similar)

### This Month
4. Build MVP: A simple API that intercepts a decision payload, runs it through configurable rules, and returns approve/flag/block with a log entry. Start with a demo using a mock insurance claims agent.
5. Create a demo video showing: AI agent makes 10 claims decisions > Nullify catches 2 that violate rules > Routes to human > Logs everything for audit
6. Apply to accelerators with this pitch (Techstars, Plug and Play, EWOR)

### This Quarter
7. Land first pilot customer
8. Start building behavioral drift detection with real decision data
9. Publish thought leadership: "Why AI Security Isn't Enough: The Case for AI Decision Control"
10. Begin SOC 2 preparation

---

## The Core Pitch

"Every company deploying AI agents in regulated industries faces the same problem: the AI works faster than any human can review. One miscalibrated insurance claims agent costs millions before the next audit cycle catches it. One biased lending model violates fair lending laws across thousands of applications before anyone notices.

Existing AI security tools protect your AI from being hacked. They don't protect your business from your own AI making bad decisions.

Nullify AI sits between your AI agents and the real world. Every decision is intercepted, evaluated against behavioral rules, and either approved or blocked before it executes. When we block a decision, we route it to a human with full context. Every verdict is logged as structured compliance evidence that maps directly to EU AI Act requirements.

The EU AI Act mandates this by August 2026. The penalty for non-compliance is EUR 30 million or 6% of global revenue. Companies that build this infrastructure now have a compliance moat. Companies that wait will be scrambling.

I'm a cybersecurity student and solo technical founder who has shipped six AI-powered products. I build with the same AI infrastructure my customers' agents run on. I understand the pipeline from the inside. Nullify is where my cybersecurity education meets my engineering ability."
