# Premium email response templates

Templates for responding to inquiries from `/contact?tier=team` and `/contact?tier=enterprise`. Replace `{{ }}` placeholders with the specifics from the inbound inquiry. Send within one business day, ideally within four hours.

Tone goals: substantive, specific to their stack, not boilerplate. Reads like a senior security engineer wrote it, not a sales template. Names exact deliverables and exact next steps so the recipient feels the response is worth more than $1,499/mo or $50K-$250K ACV.

## Email 1: Team tier response

Use when an inquiry comes in with `tier=team`. Hosted AIR Cloud, multi-agent dashboards, SIEM, alerting. Target buyer: Head of Platform, Head of Security, Staff Platform Engineer at a mid-market company running 10-500 agents.

Subject line:

```
Re: AIR Team for {{ company }} — quote, deployment plan, and call slot
```

Body:

```
Hi {{ first_name }},

Thanks for reaching out about AIR Team. Based on what you shared ({{ agent_scale }} agents, {{ use_case_summary }}), here is the shape we would propose, what you would have on day 30, and what the engagement looks like end-to-end.

What you get on day 30
- A hosted AIR Cloud workspace for {{ company }}, scoped to your team, with our managed ingestion endpoint accepting Signed Intent Capsules from every instrumented agent in your stack.
- Every prompt, tool call, and inter-agent message captured as a BLAKE3-hashed, Ed25519-signed record, chained forward by UUIDv7 step ID. Tamper with any byte and verification breaks at the exact step.
- A multi-agent dashboard showing live trace volume per agent, OWASP-aligned findings (10 ASIs + 3 LLM categories + 1 chain-integrity check), and historical replay of any session.
- SIEM integrations live for whichever of Datadog, Splunk, Sumo Logic, or Microsoft Sentinel you use. Findings flow into your existing SOC, no new on-call.
- Incident workflows: when a finding clears severity threshold, AIR fires Slack, PagerDuty, or webhook, with the full signed evidence package attached.
- Article 72 evidence templates pre-wired so your compliance lead can produce post-market monitoring reports without a copy-paste workflow.

Pricing
- {{ proposed_price_range }} per month, depending on agent volume and SIEM integration count. For your scale ({{ agent_scale }}) the typical landing is {{ proposed_price }}/mo on annual billing.
- Annual prepay gets {{ discount }}% off. Net-30 invoice or Square card. No setup fees.

What we will do this week
1. 30-minute working call: Tuesday or Thursday this week, your pick. We walk your stack, agent inventory, and the specific events you need evidence for. I prepare a one-page deployment plan during the call.
2. Day 2: I send you the deployment plan with named integrations and a workspace provisioning checklist.
3. Day 7-10: Workspace stood up, your first agent instrumented end-to-end. You verify the chain.
4. Day 30: All agents in scope are reporting. Findings flowing into your SIEM. Your team is using the dashboard daily.

Two things I need from you
- A quick reply with two 30-minute slots that work this week.
- Any specific compliance frameworks or carriers you need evidence to land in (EU AI Act Article 72, NIST AI RMF, SOC 2 AI, your insurance carrier's incident attestation form). We pre-stage those exports so day 30 demo includes the artifacts your stakeholders will actually consume.

Quick context if you want to pre-evaluate before the call
- 10-second sanity check: pip install projectair && air demo
- Architecture: vindicara.io/admissibility (FRE 902(13) + eIDAS + Article 72 mapping)
- Source: github.com/vindicara-inc/projectair

Looking forward to the call.

Kevin Minn
Founder, Vindicara, Inc.
Kevin.Minn@vindicara.io
vindicara.io
```

Notes for filling in:
- `{{ proposed_price_range }}` — usually `$1,499 to $4,999` depending on scale.
- `{{ proposed_price }}` — pick the specific number for their agent count.
- `{{ discount }}` — start at 15% for annual; flex down to 10% if needed.
- `{{ use_case_summary }}` — one short clause referencing what they wrote in the form so they know you read it.

## Email 2: Enterprise tier response

Use when an inquiry comes in with `tier=enterprise`. SSO/SAML/RBAC, on-prem, branded compliance evidence, SLA, BAA. Target buyer: CISO, VP Engineering, Head of Compliance at a regulated company (fintech, healthtech, govtech, insurance carrier).

Subject line:

```
Re: AIR Enterprise for {{ company }} — proposal, security packet, and a working session
```

Body:

```
Hi {{ first_name }},

Thanks for reaching out about AIR Enterprise. The shape of an Enterprise engagement at {{ company }} based on what you shared ({{ industry }}, {{ agent_scale }} agents, {{ compliance_frameworks }}):

What Enterprise unlocks that Team does not
- On-prem, VPC, or air-gapped deployment. AIR Cloud and the engine substrate run inside your network. No agent trace data leaves your perimeter.
- SSO, SAML, RBAC tied to your existing identity provider (Okta, Azure AD, Auth0, Ping). Audit-grade access controls on every dashboard view and every export.
- Branded, compliance-grade evidence packaging. Article 72 post-market monitoring reports, NIST AI RMF control attestation, SOC 2 AI evidence collection, California SB 53 incident summaries. PDFs ship with your logo and counsel-reviewed attestation blocks.
- Insurance carrier integrations. Your AI-incident insurance policy needs structured evidence; we map AIR findings to your carrier's required-artifact format directly.
- 24/7 SLA, dedicated incident response contact, BAA, signed mutual NDA. Our standard MSA, BAA, and DPA are ready to send to your legal team today.

What you get on day 30
- AIR deployed in your VPC or on-prem environment, integrated with your IdP, talking to your SIEM (Datadog, Splunk, Sentinel, QRadar, Sumo, ArcSight).
- Every agent in scope reporting Signed Intent Capsules through your private ingestion endpoint. BLAKE3 + Ed25519 + UUIDv7 chain, tamper-evident at the byte level.
- Compliance evidence dashboard configured for {{ compliance_frameworks }}. Your compliance lead can pull a regulator-ready PDF in two clicks.
- Insurance carrier export configured for {{ carrier_if_known }} (or a generic structured-incident export if no carrier is named yet).
- Your SOC seeing OWASP-aligned findings (10 ASIs + 3 LLM categories + 1 chain-integrity check) in their existing tooling.

What I need from you to send a real proposal
1. Estimated agent count in scope and which frameworks you must produce evidence for.
2. Deployment preference: hosted AIR Cloud in our environment, hosted in your AWS account, on-prem Kubernetes, or air-gapped.
3. Identity provider, SIEM, and (if applicable) AI-incident insurance carrier.
4. Whether your security team needs a SOC 2 report from us, a SIG questionnaire response, or both.

I will respond within one business day with:
- A formal scoped proposal (deliverables, milestones, ACV).
- Our security packet (SOC 2 status, penetration test summary, sub-processor list, BAA template).
- A 60-minute architecture working session with me and your security/platform leads.

Pricing context
- Enterprise ACV typically lands $50K-$250K depending on agent volume, deployment model, framework count, and whether insurance integrations and on-prem are in scope.
- Procurement-friendly: net-60 invoicing, mutually agreed SLA penalties, mid-term renegotiation if scope expands.

If a working call is faster than email, here is my Calendly: {{ calendly_link }}. Otherwise, replying with the four data points above gets a proposal in your inbox tomorrow.

Quick context if your team wants to pre-evaluate before the call
- vindicara.io/admissibility — admissibility-by-design architecture, FRE 902(13), eIDAS Articles 25-26, EU AI Act Article 72, GDPR Article 30
- github.com/vindicara-inc/projectair — full open-source reference implementation of the OWASP Top 10 for Agentic Applications
- pip install projectair && air demo — 10-second sanity check that verifies the cryptographic chain end-to-end

Looking forward to the working session.

Kevin Minn
Founder & CEO, Vindicara, Inc.
Kevin.Minn@vindicara.io
vindicara.io | github.com/vindicara-inc/projectair

Vindicara, Inc. — 696 S New Hampshire Ave, Los Angeles, CA 90005
```

Notes for filling in:
- `{{ industry }}` — fintech / healthtech / govtech / insurance / SaaS, etc.
- `{{ compliance_frameworks }}` — explicit list pulled from their inquiry: e.g. "EU AI Act Article 72 plus SOC 2 AI plus your carrier's incident form."
- `{{ carrier_if_known }}` — name the insurance carrier if they mentioned it; otherwise drop the parenthetical.
- `{{ calendly_link }}` — set up if you have one; otherwise drop the line and let them propose times.

## Email 3: Auto-acknowledgement (if Web3Forms is wired with auto-reply)

Optional. Web3Forms supports auto-replies. If you turn it on, this is the body:

```
Hi {{ first_name }},

Thanks for reaching out to Vindicara. Your inquiry just landed in my inbox and I will respond personally within one business day with a tailored proposal and a deployment plan.

If you want to start exploring before then:
- 10-second sanity check: pip install projectair && air demo
- Architecture deep-dive: vindicara.io/admissibility
- Source: github.com/vindicara-inc/projectair

Talk soon.

Kevin Minn
Founder, Vindicara, Inc.
```

## Sequencing reminders

- Send response within one business day of the inquiry. Speed signals competence to the buyer.
- Personalize the first paragraph specifically to their use_case field. Generic openers signal templated outreach.
- Always end with a concrete two-action ask (slots + frameworks for Team; four data points + working session for Enterprise). Vague closes lead to dead threads.
- Cc no one on the first response. The buyer chose to email you; do not surface other people they did not ask about.
- Bcc kevin@sltrdigital.com on every Enterprise response so there is a personal-account copy for follow-up tracking outside vindicara.io.
