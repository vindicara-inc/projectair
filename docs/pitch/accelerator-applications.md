# Accelerator Applications — Vindicara / Project AIR™

Two applications, one source of truth. Copy/paste the answers below into each form, fill the 3 personal-story placeholders flagged **[YOUR INPUT NEEDED]**, and submit.

**Guidance on voice:** YC and Techstars both prefer direct, concrete answers. No marketing adjectives. Specific numbers beat general claims. Solo founder is a disadvantage at YC and a neutral at Techstars — I've addressed both below.

---

# Shared Content (re-use across both forms)

## Company identity

| Field | Answer |
|---|---|
| Legal name | Vindicara, Inc. |
| DBA | Project AIR™ (flagship product) |
| State of incorporation | California (Delaware re-domicile in progress) |
| Principal office | 696 S New Hampshire Ave, Los Angeles, CA 90005 |
| Website | https://vindicara.io |
| GitHub | https://github.com/vindicara-inc/projectair |
| PyPI | https://pypi.org/project/projectair/ |
| Founder | Kevin Minn |
| Founder email | Kevin.Minn@vindicara.io |
| Legal contact | legal@vindicara.io |
| Stage | Pre-seed |
| Category | AI Security / Developer Tools / Compliance Infrastructure |

## 50-character company description (pick one)

> **Option A (50 chars):** `Forensic incident response for AI agents.`
> **Option B (48 chars):** `Admissible-by-design evidence for AI agents.`
> **Option C (50 chars):** `Signed forensic records for autonomous AI agents.`

My recommendation: Option A. Cleanest read. Sounds like a category, not a product.

## Two-sentence description

> Project AIR is the open-source forensic and incident-response layer for AI agents. Every agent action is cryptographically signed and chained, producing a tamper-evident record a court, regulator, or insurance carrier can accept as evidence.

## Longer product description (when the form asks for a paragraph)

> Vindicara builds Project AIR, the open-source forensic reconstruction and incident-response layer for AI agents. When an autonomous agent sends the wrong wire, leaks the wrong file, or approves something it shouldn't, prevention tools can only tell you what you tried to stop. They can't tell you what happened. Project AIR records every agent action (LLM calls, tool invocations, inter-agent messages, final outputs) as a signed Intent Capsule, hashed with BLAKE3 and signed with Ed25519, chained forward through the entire session. Alter any byte, and verification breaks at the exact step. We ship detectors for all ten OWASP Top 10 for Agentic Applications categories, three OWASP LLM Top 10 categories, and one AIR-native forensic-chain-integrity check. Shipped as MIT-licensed `projectair` on PyPI. The commercial tiers (AIR Cloud for teams at $1,499/mo, AIR Enterprise at $50K–$250K ACV for regulated industries) add hosted ingestion, SIEM integrations, regulator-ready compliance evidence packaging, and SSO/SAML. Admissibility-by-design architecture mapped to US Federal Rules of Evidence 901/902/803, EU eIDAS Articles 25-26, EU AI Act Article 72, and GDPR Article 30, publicly documented at vindicara.io/admissibility.

## Why now

> Three forcing functions converge in the next six months. **First:** autonomous AI agents are moving from demo to production at machine speed — the recent Anthropic Mythos leak showed that even frontier models meant to be tightly controlled escape into unknown hands, and companies deploying agents using those models have no forensic trail. **Second:** the EU AI Act enforcement deadline is August 2, 2026 — providers of high-risk AI systems need post-market monitoring evidence under Article 72, which the Article 72 evidence generator we ship produces as a signed, integrity-protected record. **Third:** the AI Security vendor landscape consolidated (CalypsoAI acquired by F5, Lakera acquired by Check Point), leaving the developer-first, independent, OSS-based tier of the market empty. Vindicara fills that gap. The window to establish the category reference is now.

## What's new about this

> Every prevention tool in the AI-security category answers "what did we try to stop?" Project AIR answers the next question: "what actually happened, and can you prove it?" It's the first open-source reference implementation of the full OWASP Top 10 for Agentic Applications v12.6 taxonomy, with cryptographic primitives (Ed25519, BLAKE3) chained forward into a tamper-evident log. The architecture is deliberately mapped to evidentiary frameworks — US Federal Rules of Evidence 902(13), EU eIDAS Article 25/26, EU AI Act Article 72, GDPR Article 30 — so the output can actually be used in court, regulatory proceedings, or insurance claims. No competitor ships this full stack under MIT license. Substitutes: operators write their own structured logs, pay Splunk for SIEM correlation after the fact, or hope their prevention tool was enough. None produce cryptographically admissible evidence.

## Traction

> - **April 22, 2026:** version 0.3.0 live on PyPI (`pip install projectair`)
> - **10 of 10** OWASP Top 10 for Agentic Applications detectors shipped
> - **3 of 10** OWASP Top 10 for LLM Applications categories covered
> - **200** tests passing; `mypy --strict` clean
> - **Framework integrations** shipped: LangChain, OpenAI SDK, Anthropic SDK
> - **Public admissibility architecture** deployed at vindicara.io/admissibility with live chain-explorer demo and FRE 902(13) certification generator
> - **3 warm design-partner conversations** in progress (security engineers at AI-forward companies); contact info on request
> - **Hacker News launch scheduled** for May 4, 2026
> - **Pitch materials:** full pitch deck, admissibility whitepaper, Article 72 evidence generator, 4 legal documents (ToS / Privacy / AUP / Security Disclosure) all v1.0 published

## Revenue model

> Three tiers. **OSS Free (MIT license):** `pip install projectair`. The land. Every install is a hook for the expand motion. **Team tier ($1,499/mo):** AIR Cloud hosted dashboard, SIEM integrations (Datadog, Splunk, Sumo, Sentinel), incident workflows + alerting, up to 25 agents. Target customer: security and platform teams with agents in production. **Enterprise tier ($50K–$250K ACV):** SSO/SAML/RBAC, branded regulator-ready PDF evidence packaging for EU AI Act Article 72, SB 53, SOC 2, NIST AI RMF; insurance carrier integrations; on-prem / VPC deployment; SLA; BAA. Target customer: regulated industries (fintech, healthtech, govtech, insurance). Pricing validated against comparable security tooling (Lacework, Wiz, Orca at $40K–$150K+ ACV for mid-market). Current OSS→paid conversion assumption: 2-3% of weekly installs land in a paid funnel.

## Who are your competitors

> **Direct (prevention, not forensics):** Lakera (acquired by Check Point, enterprise-only), Guardrails AI (prompt injection + hallucination detection, no forensic chain), NVIDIA NeMo Guardrails (toolkit, requires self-hosting), Galileo (observability-first, guardrails second). **Adjacent:** Miggo Security (runtime observability for AI-BOM), Cisco AI Defense (Zero-Trust for agents, enterprise networking), AQtive Guard / SandboxAQ (AI security posture management). **None of them ship cryptographically admissible forensic records.** Fear-most: NVIDIA NeMo if it gets a commercial hosted version with built-in signing; OpenAI or Anthropic baking forensic output into their SDKs natively. Counter: our product is the open-source reference implementation of the OWASP taxonomy; deep integration with that standard is our defensibility while the big players are busy with their own moats.

## What do you understand that competitors don't

> Admissibility is decided by courts, regulators, and insurance carriers — not by the security product vendor. Competitors chase detection accuracy metrics because they're easy to benchmark. We chase evidentiary integrity because that's what matters when an incident reaches a claim form or a subpoena. Everyone else is building the thermostat. We're building the fire alarm that insurance companies will pay out against.

## How solo founder / team

> **Solo founder by design for the first six months.** Shipping product, pitching investors, writing docs, and running the launch sprint all out of one head. The speed advantage is real — the `projectair` package went from 0.1.0 to 0.3.0 (full OWASP v12.6 coverage) in under four weeks. Will add a technical co-founder when we have paying customers and can recruit from a position of traction, not weakness. Until then, every hour is deployed on shipping.

## Kevin's background

**[YOUR INPUT NEEDED — replace this section]**

Template:

> I'm Kevin Minn. Previously [one-line: your prior role and company]. Before that [one-line if applicable]. Earned [degree or cert if noteworthy, otherwise skip]. I've been building [security tooling / developer infrastructure / AI systems] for [X years] and saw the agent-forensics gap firsthand when [specific triggering moment: a client incident, a project that needed this capability, etc.].

What to include (1-3 sentences):
- Your most recent role + company (especially if it's security-adjacent or credible)
- Why you saw this specific problem
- Your technical credentials that justify building cryptographic infrastructure

## Most impressive thing you've built outside this startup

**[YOUR INPUT NEEDED — replace this section]**

This is a YC staple question. They want one clean, specific, verifiable achievement. Don't list; pick ONE. Examples of the shape:

> "I built [specific tool / system / project]. It [specific metric: handled X requests/day, was adopted by Y teams, sold for Z, survived in production for N years]."

Options if you're short on candidates:
- A personal project you shipped that got users
- An engineering system at a past job (get permission to describe)
- An open-source contribution with stars/downloads
- A hack / prank / non-obvious achievement (YC loves these)

## "Hack a system to your advantage" story

**[YOUR INPUT NEEDED — replace this section]**

This is the YC-famous "most successfully hacked some (non-computer) system" question. They're probing for founder resourcefulness outside of code. Examples of the shape:

> "I needed [goal] but [constraint]. The normal path required [X time / X money / X permissions]. Instead I [unconventional method], which worked because [insight about the system]. Result: [specific win]."

Examples of types of answers that land:
- Got into a program, event, or community by unconventional route
- Convinced someone to do something against their initial inclination
- Found a loophole in a process that was gatekeeping something valuable
- Cold-pitched a senior executive and got a yes

Do NOT mention: anything illegal, anything that embarrassed someone, or anything that breaks the rules of a system you still benefit from.

## Anything else you want us to know

> I'm running the launch sprint this week: Hacker News on May 4, OWASP outreach for Solutions Landscape submission, first paying design partner conversations in progress. By the time you read this, Project AIR is live on PyPI and the admissibility architecture is public at vindicara.io/admissibility — you can verify every claim in this application by running `pip install projectair && air demo` in 30 seconds.

---

# YC Application

Answers below map to YC's published application questions. Paste into each field. Some fields accept longer answers; I've kept them tight because partners scan.

## Company

**Company name:** Vindicara, Inc.

**Company URL:** https://vindicara.io

**Describe what your company does in 50 characters or less:**
> Forensic incident response for AI agents.

**Company address, country:** 696 S New Hampshire Ave, Los Angeles, CA 90005, United States

**Phone number:** [YOUR PHONE]

**Company video URL (YouTube unlisted):** [YOUR VIDEO URL after upload]

## Founders

**How long have the founders known one another and how did you meet?**
> Solo founder. (See "Team" below for solo-founder rationale.)

**Who writes code?**
> I do. 100% of the code in the Project AIR repository is written by me, except for MIT-licensed open-source dependencies (cryptography, BLAKE3 library, Pydantic, Typer, LangChain-core, fpdf2, PyYAML). No contractors. No non-founder contributors.

**How much of the code is written by founders?**
> 100%.

## Product

**What is your company going to make?**
> Vindicara builds Project AIR, the open-source forensic reconstruction and incident-response layer for AI agents. When an autonomous agent takes an action — an LLM call, a tool invocation, a message to another agent, a final output — Project AIR produces a cryptographically signed Intent Capsule recording what happened. Records are hashed with BLAKE3, signed with Ed25519, and chained forward. Tamper with any byte and verification breaks at the exact step. We ship detectors for all 10 OWASP Top 10 for Agentic Applications categories and an EU AI Act Article 72 post-market-monitoring evidence generator. MIT license, on PyPI today.

**Where do you live now, and where would the company be based after YC?**
> Currently: Los Angeles, California. Post-YC: open to San Francisco Bay Area during the batch; plan to return to LA afterward unless hiring signals otherwise.

## The Idea

**Why did you pick this idea to work on? Do you have domain expertise?**

**[YOUR INPUT NEEDED — personalize]**

Template:
> I've been working in [security tooling / AI infrastructure / your specific domain] for [X years]. I saw the gap firsthand when [specific moment or customer pain]. Every prevention tool answers "did we try to stop it?" Nobody answers "what happened and can you prove it?" The OWASP Top 10 for Agentic Applications v12.6 (published December 2025) named the signed intent-capsule pattern as emerging; nobody shipped the open-source reference implementation. I shipped it.

**What's new about what you're making?**
> Three things. **First:** the first open-source reference implementation of the full OWASP Top 10 for Agentic Applications taxonomy. All 10 ASI detectors, MIT-licensed. **Second:** admissibility-by-design — the architecture is deliberately mapped to US Federal Rules of Evidence 902(13) and EU eIDAS Articles 25/26, with a live certification generator on the site. No competitor does this. **Third:** EU AI Act Article 72 evidence generator baked in — `air report article72 <trace.log>` produces a populated Markdown template for Article 72 post-market-monitoring filings. Substitutes: operators either write ad-hoc logs their lawyers can't use, or pay enterprise SIEM vendors to reconstruct evidence after an incident from incomplete data.

**What substitutes do people resort to because this doesn't exist yet?**
> JSON logs thrown into Splunk or Datadog (no cryptographic integrity, so not admissible). Hand-written incident reports reconstructed from partial prompts and tool outputs (incomplete, subjective). "Trust us" guardrail screenshots (not evidence). Custom compliance consultants building bespoke evidence packages per incident at $500–$1500/hour.

**Who are your competitors, and who might become competitors? Who do you fear most?**
> **Current:** Lakera (acquired, enterprise-only), Guardrails AI (prevention, not forensic), NeMo Guardrails (toolkit), Galileo (observability), Miggo Security (AI-BOM runtime observability). **Potential:** Datadog, Splunk, or a cloud provider shipping an "AI observability" offering with signed logs. **Feared most:** OpenAI or Anthropic baking cryptographically signed output into their SDKs natively. Counter: our positioning is model-agnostic OSS with regulatory alignment, which is a harder wedge for a model provider to bolt on than the reverse.

**What do you understand about your business that other companies in it just don't get?**
> Admissibility is decided by the court, regulator, or insurance carrier — not the product vendor. Competitors benchmark detection accuracy because it's measurable. We benchmark evidentiary integrity because that's what matters when an incident reaches a claim form or a subpoena. Nobody else is building the category's default evidentiary layer. We already shipped it.

## Monetization

**How or will you make money? How much could you make?**

Three tiers:
- **OSS Free (MIT license):** acquisition funnel. Every `pip install projectair` is a hook.
- **Team ($1,499/mo):** AIR Cloud hosted dashboard, SIEM integrations, up to 25 agents. Target: security and platform teams with agents in production. 2% conversion from weekly installs = ~20 paying teams at 90-day milestone; ~200 teams at 12-month milestone at $1,499/mo = ~$300K–$3.6M ARR.
- **Enterprise ($50K–$250K ACV):** regulator-ready compliance evidence packaging, SSO/SAML, on-prem / VPC. Target: regulated industries (fintech, healthtech, govtech, insurance). 5–10 enterprise logos at 18-month milestone = $500K–$2.5M ARR alone.

Total realistic 24-month ARR target: $3M–$6M. Larger upside if EU AI Act enforcement drives forced procurement.

## Progress

**How far along are you?**

> **Version 0.3.0 shipped to PyPI April 22, 2026.** Live public product. All 10 OWASP Top 10 for Agentic Applications detectors implemented. 200 tests passing. Framework integrations: LangChain, OpenAI SDK, Anthropic SDK. Admissibility architecture deployed at vindicara.io/admissibility with live chain-explorer. Hacker News launch scheduled for May 4, 2026. First warm design-partner conversations underway.

**How many users?**
> Pre-launch. PyPI install telemetry is private; actual adoption starts with HN launch May 4. By time you read this: early adopters only.

**How much revenue?**
> Zero paying customers as of application. Target first paying Team-tier customer 60 days post-launch (end of June 2026).

**How long have you been working on it?**
> Full-time: ~4 weeks of concentrated shipping. Project AIR as a pivot from earlier Vindicara positioning (five-pillar runtime security platform) crystalized in mid-April 2026 after OWASP v12.6 landed and my feasibility review confirmed the forensic-IR gap was real.

**How many lines of code?**
> `projectair` package: ~4,000 lines production code, ~2,500 lines tests. Public on GitHub at https://github.com/vindicara-inc/projectair.

## Impressive achievements

**Tell us in one or two sentences about the most impressive thing other than this startup that you have built or achieved.**

**[YOUR INPUT NEEDED]** — see template in Shared Content section above.

**Please tell us about the time you most successfully hacked some (non-computer) system to your advantage.**

**[YOUR INPUT NEEDED]** — see template in Shared Content section above.

## Anything else

**Anything else you want us to know?**

> By the time you read this, everything in this application is verifiable in 30 seconds: `pip install projectair && air demo`. Admissibility architecture: https://vindicara.io/admissibility/. Source: https://github.com/vindicara-inc/projectair. I'm a solo founder by design until traction justifies adding a technical co-founder. EU AI Act enforcement hits August 2, 2026; I'm building the evidence layer that makes compliance possible. I'd like to be in your summer batch.

---

# Techstars Application

Techstars application varies by program (AI, Security, FinTech, etc.). Questions below are the common set. Adapt to the specific program you apply to.

## Company basics

**Company name:** Vindicara, Inc.

**Website:** https://vindicara.io

**Industry:** Cybersecurity / AI Infrastructure / Developer Tools

**Stage:** Pre-seed (OSS launched; pre-paying customers)

**Location:** Los Angeles, California, United States

**Incorporation:** California corporation (Delaware re-domicile in progress)

**Year founded:** 2026

**Employees:** 1 (Kevin Minn, founder)

**Funding raised to date:** $0 institutional. [YOUR INPUT: any angel / friends & family?]

## Team

**Founder name:** Kevin Minn

**LinkedIn:** [YOUR LINKEDIN URL]

**Founder bio:** **[YOUR INPUT NEEDED]** — see template in Shared Content section

**Why you:** I've spent the last several years building in this space and saw the agent-forensics gap firsthand. I ship fast — Project AIR went from concept to complete OWASP v12.6 reference implementation in under four weeks, with 200 passing tests and a production-grade cryptographic chain. The category didn't exist six months ago. Somebody has to build it before the EU AI Act enforcement deadline in August.

## Product

**What does your company do?**
> Vindicara builds Project AIR, the open-source forensic and incident-response layer for AI agents. When an autonomous agent causes harm — sends the wrong wire, leaks the wrong file, approves the wrong thing — Project AIR produces a cryptographically signed forensic record that a court, regulator, or insurance carrier can accept as evidence. Shipped as MIT-licensed `projectair` on PyPI; commercial tiers add hosted ingestion, compliance evidence packaging, and SSO.

**What problem are you solving?**
> AI agents are moving from demo to production at machine speed. When they cause harm (and they will), prevention tools can only tell you what you tried to stop. They can't tell you what happened. Companies deploying agents have no forensic trail that a court, regulator, or insurer will accept. We ship that forensic trail by default — cryptographically signed, tamper-evident, mapped to US Federal Rules of Evidence and EU eIDAS Articles 25/26.

**Target customer:** Security engineers, platform teams, and compliance officers at companies deploying AI agents in production. First paying customers likely at mid-market regulated-industry companies (fintech, healthtech, govtech, insurance) where the EU AI Act and existing audit obligations create forced demand.

**Market size (TAM/SAM/SOM):**
> - **TAM:** AI Security is projected to exceed $30B by 2030 (Gartner). Incident response + compliance sub-segment ~30% = $9B.
> - **SAM:** Organizations deploying AI agents in production requiring auditable forensic records. Gartner forecasts 40% of enterprise applications embed agents by 2026. Rough US/EU bound: 50K–100K enterprise and mid-market companies.
> - **SOM (3-year):** 1–2K paying customers across Team and Enterprise tiers = $50M–$150M ARR at current pricing.

## Business model

**Revenue model:**
> SaaS subscription. **Team tier:** $1,499/month. **Enterprise tier:** $50K–$250K ACV. OSS tier is free forever (MIT) and serves as the acquisition funnel.

**Current revenue:** $0 (pre-launch).

**Burn rate:** [YOUR INPUT: approximate monthly burn — infrastructure + tools + Kevin's opportunity cost]

**Runway:** [YOUR INPUT: approximate months]

## Traction

**Key metrics:**
- PyPI release 0.3.0 live (April 22, 2026) with 10/10 OWASP Top 10 for Agentic Applications coverage
- 200 tests passing, mypy --strict clean
- LangChain + OpenAI + Anthropic framework integrations shipped
- Public admissibility architecture at vindicara.io/admissibility with live chain-explorer and FRE 902(13) certification generator
- 4 published legal documents (ToS, Privacy, AUP, Security Disclosure) — professional procurement-ready posture
- HN launch scheduled May 4, 2026
- 3 warm design-partner conversations in progress

**Projections (conservative):**
- 90 days: 500 GitHub stars, 100 weekly installs, 3 active design-partner conversations → first paid customer
- 6 months: 10 paying Team-tier teams, first Enterprise LOI signed → ~$15K–$20K MRR
- 12 months: 50 paying teams, SOC 2 Type I in progress, Series seed-ready → ~$75K MRR / $900K ARR run rate
- 24 months: Category-defining position; 500K+ ARR; 3–5 Enterprise logos signed

## Why Techstars

> Techstars has the operator network this product needs. Runtime security for AI agents is not a solo-sell; it requires conversations with security leadership at mid-market and enterprise targets who are unlikely to take a cold outreach from a pre-seed founder. Techstars gives me those conversations. I've shipped the product. I need the reps. The accelerator's emphasis on customer discovery, founder-led sales, and operator mentorship is the exact leverage I need over the next 3–6 months.

## Funding sought

> Pre-seed round in progress. Target: $500K SAFE at $5M post-money cap. Use of funds: 12-month runway for founder, AWS infrastructure, first hire (developer advocate / community), security audit of SDK ahead of Enterprise push, SOC 2 Type I preparation.

---

# Final Submission Checklist

Before you hit submit on either application:

1. **Video uploaded** (YC: <200MB .mp4 uploaded direct; Techstars: YouTube unlisted)
2. **[YOUR INPUT NEEDED] sections filled** — 3 personal-story answers
3. **Phone number** filled in YC form
4. **LinkedIn URL** filled in Techstars form
5. **Verify all links resolve:**
   - https://vindicara.io/
   - https://vindicara.io/admissibility/
   - https://pypi.org/project/projectair/0.3.0/
   - https://github.com/vindicara-inc/projectair
6. **Spell-check Kevin Minn** (not Moore, not Mini). I've been burned once already.
7. **If a question has a character limit** — the answers above may need trimming. YC is strict; Techstars is lenient.
8. **Save a copy of your submitted answers** before hitting submit (YC doesn't let you see them again without re-application).
9. **Don't mention the other accelerator in either application.** Techstars doesn't want to know you applied to YC, and YC doesn't care about Techstars.

## Follow-through after submission

- **YC:** decision typically 10–14 days. Silence = rejection. Rejection is almost always final for that batch; reapply next cycle.
- **Techstars:** decision varies by program; typically 4–6 weeks.
- **Both:** if invited to an interview, schedule immediately. Clear everything else from your calendar.

---

## What I need from you to finalize

Three personal-story placeholders, ~100 words each:
1. **Your background** (previous roles, why you saw this problem)
2. **Most impressive thing built outside this startup**
3. **"Hacked a system" story**

If you give me those three in bullet points, I can polish them into final answers tonight. Without them, your application is 95% done; you finish the last 5% in your own words.

Everything else — product description, traction, why-now, competition, revenue model, market sizing, solo-founder rationale — is fully drafted and ready to paste.
