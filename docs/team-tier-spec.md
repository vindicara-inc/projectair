# Team AIR — canonical tier spec (LOCKED 2026-06-23)

Single source of truth for the Team tier. `issuer.py`, the pricing page, Stripe,
and FlightDeck gating mirror this. Do not change tier contents without updating
this file first. (Pro: see `pro-tier-spec.md`.)

## Identity

Team is the first real revenue tier and the only one carrying the **complete
APPM loop**. Pro is half of APPM (Audit + Prove): it records and proves what an
agent did. Team is all four (Audit, Prove, Monitor, Protect): it also watches
the fleet and stops it. Buyer = a security/platform team running agents in
production with a real incident process, not a solo operator.

Defining boundary: **Pro proves. Team proves, watches, and intervenes.** That
is why the Pro -> Team jump justifies ~6x: it is the other half of the framework
plus the entire collaboration and integration layer.

## Capabilities (`issuer.py`) — everything in Pro, plus

- `monitor` — continuous fleet-wide watch + anomaly detection (APPM Monitor, L2)
- `protect` — real-time containment, fail-closed, revoke/quarantine/renew; every
  containment action itself sealed as evidence (APPM Protect, L3)
- `dual-control` — FlightDeck dual-control gating on the Engage cascade
- `cohort-scope`, `fleet-scope` — cohort and full-fleet views, not single-agent
- `siem` — all five: Datadog, Splunk, Sumo Logic, Microsoft Sentinel, Slack
- `multi-seat` — shared workspace, multiple operators, roles
- `alerting` — routed alerts and notifications
- `admissibility` — certified, legal-hold-ready evidence packs (chain of custody,
  FRE 902(13)/(14) methodology docs, certifiable export). Refinement: at Team the
  customer's own records custodian signs the 902 certification; Vindicara puts
  its own name on the attestation only at Enterprise.
- `report-fleet-posture` — operational fleet-posture / incident report
  (non-attestation, no liability tail, distinct from SOC 2-AI)
- carried from Pro: air-cloud-client, premium-detectors, full anchor stack,
  evidence packs, report-nist-ai-rmf, hosted FlightDeck

## Quotas and limits (pricing card)

- Retention: **1 year hosted, queryable** (the primary lever from Pro's 30 days;
  the single biggest non-feature reason a team upgrades)
- Seats: **5 included**, then **$99/seat/mo** (seats 6–15), **hard ceiling 15**.
  A seat-16 request triggers the Enterprise conversation (do not raise the cap).
- Action allotment: **250,000 actions/mo included (PROVISIONAL** — confirm
  against per-1k COGS; decision rule: an active 5-seat team lands inside it most
  months, a heavy team crosses into overage). Overage **$1.50 / 1k, locked,
  standardized across tiers**.
- Standard plus expanded storage to support the 1-year window
- Watermark off (inherited from Pro)

## Pricing structure — platform fee + expansion, not pure flat (LOCKED)

- **$599/mo base**, includes 5 seats and the 250k-action allotment
- **$99/seat/mo** for seats 6–15 (a 6th seat = one Pro; self-explaining)
- action overage **$1.50 / 1k** beyond the included allotment
- 1-year retention as a tier attribute
- Fully-loaded 15-seat Team = $599 + 10×$99 = **$1,589/mo (~$19K/yr)** — lands
  just under the Enterprise floor, so the ceiling is automatic Enterprise lead-gen
- Checkout: **self-serve** ("Start on Team", Stripe Payment Link
  buy.stripe.com/4gMdR8dDI9QEgA88Hl1RC02 → price_1TUfSD… → tier "team") with a
  secondary "talk to sales" escape hatch for larger/annual/12-seat-start buyers

Pressure-test note: pure-flat $599 underprices Team as now scoped (it absorbed
full Protect, continuous Monitor, certified admissibility, and a year of
retention since $599 was set). Keep $599 as the visible floor that converts
cheaply from Pro; seats + overage carry a real SOC to an effective ~$1.5K-$3K/mo,
i.e. ~$18K-$36K ACV, sitting just under the Enterprise contract band with no dead
zone.

## Deliberately NOT in Team (the moat — mostly contractual, not technical)

- `report-soc2-ai` -> Enterprise (attestation liability)
- BAA / HIPAA contractual coverage -> Enterprise (a signed contract, not a flag;
  a hospital legally cannot run regulated PHI on Team without a BAA)
- ML-DSA-65 post-quantum signing -> Enterprise + Air-Gapped
- Agent IAM / cross-agent identity (full L4) -> Enterprise
- Named, Vindicara-backed expert attestation + litigation-hold / custodian-of-
  record -> Enterprise
- Dedicated single-tenant stack, on-prem, dedicated IR -> Enterprise
- Offline operation -> Air-Gapped
- Multi-year configurable retention -> Enterprise

## Resolved

- Overage rate: **$1.50 / 1k actions, standardized across tiers** — LOCKED.
- Per-seat: **$99/seat/mo**, 5 included, hard ceiling 15, seat-16 → Enterprise — LOCKED.
- Checkout: **self-serve** + "talk to sales" hatch — LOCKED.

## Still open

- Included allotment: **250k/mo is PROVISIONAL** until confirmed against per-1k COGS.
- Additional-seat Stripe Price ID — to be supplied, then mapped.
- Stripe metered-billing status for seats + overage: full auto-metered self-serve
  requires it wired; until then self-serve the $599 base and gate seat/overage
  expansion behind sales.
