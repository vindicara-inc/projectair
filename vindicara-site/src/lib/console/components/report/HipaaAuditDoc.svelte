<script lang="ts">
  import type { BuiltScenario } from '$lib/console/forensics/types';
  import { reportStats, type ReportAnchor } from '$lib/console/forensics/report';
  import { operator } from '$lib/console/stores/operator';

  let {
    incidents,
    anchor,
    reportId,
    fromIso,
    toIso,
    generatedAt
  }: {
    incidents: BuiltScenario[];
    anchor: ReportAnchor;
    reportId: string;
    fromIso: string;
    toIso: string;
    generatedAt: string;
  } = $props();

  let stats = $derived(reportStats(incidents));
  let agents = $derived(new Set(incidents.map((i) => i.agentLabel)).size);
  let scopeViolations = $derived(stats.critical + stats.high); // out-of-scope / high-risk halted

  let authority = $derived(
    $operator.signedInAt
      ? { name: $operator.name, org: $operator.organization, role: $operator.role, method: $operator.authMethod }
      : { name: 'Dr. Sarah Chen', org: 'Demo Health System', role: 'Privacy & Security Officer', method: 'passkey' as const }
  );

  const fmt = (iso: string) => new Date(iso).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' });
  const fmtDay = (iso: string) => new Date(iso).toLocaleDateString('en-US', { dateStyle: 'medium' });

  let controls = $derived([
    {
      cite: '45 CFR §164.312(b)',
      name: 'Audit controls',
      req: 'Record and examine activity in systems that contain or use ePHI.',
      how: 'Project AIR records every agent action as a signed, timestamped capsule (an AI Decision Record). Nothing an agent does touches ePHI without being captured.',
      evidence: `${stats.records} signed, timestamped records across ${agents} agents in this period.`,
      status: 'Satisfied'
    },
    {
      cite: '45 CFR §164.312(c)(1)',
      name: 'Integrity',
      req: 'Protect ePHI from improper alteration or destruction.',
      how: 'Each record is content-hashed with BLAKE3 and signed with Ed25519, linked into a tamper-evident chain. Any alteration is provably detected at the exact record.',
      evidence: `${stats.chainsIntact} of ${stats.total} chains re-verified intact; tampering is detectable, not just discouraged.`,
      status: 'Satisfied'
    },
    {
      cite: '45 CFR §164.312(d)',
      name: 'Person or entity authentication',
      req: 'Verify that a person or entity seeking access is who they claim to be.',
      how: 'High-risk actions halt and require a human; the decision is bound to an Auth0 / passkey-verified identity and recorded on-chain — proving who authorized what.',
      evidence: `${stats.halted} actions halted for step-up human approval, each tied to a named, verified authorizer.`,
      status: 'Satisfied'
    },
    {
      cite: '45 CFR §164.502(b)',
      name: 'Minimum necessary',
      req: 'Limit ePHI access to the minimum necessary for the purpose.',
      how: 'Project AIR detects and halts access beyond an agent’s declared scope — e.g. an agent reaching for records of patients it was never asked about.',
      evidence: `${scopeViolations} out-of-scope / high-risk PHI actions flagged or halted before they took effect.`,
      status: 'Enforced'
    },
    {
      cite: '45 CFR §164.308(a)(1)(ii)(D)',
      name: 'Information system activity review',
      req: 'Regularly review records of information-system activity.',
      how: 'This tamper-evident report is that review — a complete, verifiable account of AI agent activity for the period, exportable for auditors.',
      evidence: `Report ${reportId} covering ${fmtDay(fromIso)} – ${fmtDay(toIso)}.`,
      status: 'Satisfied'
    },
    {
      cite: '45 CFR §164.312(a)(1)',
      name: 'Access control · unique identification',
      req: 'Assign a unique identifier for tracking user/entity activity.',
      how: 'Every agent carries a unique registered identifier and Ed25519 signing key, so every action is attributable to a specific agent.',
      evidence: `${agents} uniquely identified agents, each with its own signing key.`,
      status: 'Satisfied'
    }
  ]);
</script>

<article class="report-doc">
  <!-- PAGE 1 — HIPAA AUDIT ATTESTATION + CONTROL MAPPING -->
  <section class="page">
    <div class="wordmark"><span class="dot"></span>Project <span class="air">AIR</span></div>
    <div class="tagline">Monitor · Protect · Prove</div>

    <h1>HIPAA Security Rule — Audit Attestation</h1>
    <div class="subtitle">AI agent activity mapped to the HIPAA Security Rule, with verifiable evidence</div>

    <dl class="meta">
      <div><dt>Audit ID</dt><dd class="mono">{reportId}-HIPAA</dd></div>
      <div><dt>Covered entity</dt><dd>{authority.org}</dd></div>
      <div><dt>Reporting period</dt><dd>{fmtDay(fromIso)} → {fmtDay(toIso)}</dd></div>
      <div><dt>Generated</dt><dd>{fmt(generatedAt)}</dd></div>
      <div><dt>Scope</dt><dd>{stats.total} AI agent incidents · {stats.records} signed records · {agents} agents</dd></div>
    </dl>

    <div class="authbox">
      <div class="authlabel">Attested by</div>
      <div class="authname">{authority.name}</div>
      <div class="authrole">{authority.role} · {authority.org}</div>
      <div class="authmethod">Verified human identity · {authority.method === 'auth0' ? 'Auth0 / OIDC' : 'Passkey · FIDO2 / WebAuthn'}</div>
    </div>

    <p class="attest">
      The HIPAA Security Rule requires covered entities to audit system activity, protect the
      integrity of ePHI, authenticate who acts, and enforce minimum-necessary access. As autonomous
      AI agents begin to touch ePHI, those obligations extend to the agents. The table below maps
      each applicable control to the evidence Project AIR produces — evidence that is cryptographically
      verifiable, not asserted.
    </p>

    <table class="hipaa">
      <thead>
        <tr><th>Control</th><th>Requirement</th><th>How Project AIR satisfies it</th><th>Status</th></tr>
      </thead>
      <tbody>
        {#each controls as c}
          <tr>
            <td><div class="cite mono">{c.cite}</div><div class="cname">{c.name}</div></td>
            <td>{c.req}</td>
            <td>{c.how}<div class="evid">Evidence: {c.evidence}</div></td>
            <td class="st">✓ {c.status}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </section>

  <!-- PAGE 2 — BREACH ASSESSMENT + INTEGRITY ANCHOR + SIGN-OFF -->
  <section class="page">
    <h2>Breach risk assessment</h2>
    <p>
      Under the Breach Notification Rule (45 CFR §164.402), an impermissible use or disclosure of
      ePHI is a breach unless a low probability of compromise is demonstrated. For this period:
    </p>
    <table class="breach">
      <thead><tr><th>Event</th><th>What happened</th><th>Disposition</th></tr></thead>
      <tbody>
        {#each incidents.filter((i) => i.severity === 'critical' || i.severity === 'high') as inc}
          <tr>
            <td class="mono">{inc.agentLabel}</td>
            <td>{inc.title}</td>
            <td class="ok">{inc.status === 'contained' ? 'Halted before effect — no disclosure' : 'Blocked before ePHI left the environment'}</td>
          </tr>
        {/each}
      </tbody>
    </table>
    <p class="finding"><b>Finding:</b> every high-risk action was halted or blocked before ePHI left the environment. No confirmed breach occurred in this period — and each disposition is provable from the signed chain.</p>

    <h2 class="mt">Integrity anchor</h2>
    <p>The complete activity chain for this period is anchored for independent verification:</p>
    <dl class="anchor mono">
      <div><dt>Chain root (BLAKE3)</dt><dd>{anchor.chainRoot}</dd></div>
      <div><dt>Signer key (Ed25519)</dt><dd>{anchor.signerKey}</dd></div>
      <div><dt>Sigstore Rekor log index</dt><dd>{anchor.rekorLogIndex}</dd></div>
      <div><dt>RFC 3161 timestamp</dt><dd>{fmt(anchor.tsaTimestamp)} · {anchor.tsaUrl}</dd></div>
    </dl>
    <p class="closing">
      This attestation and its underlying evidence can be re-verified offline by recomputing the
      hashes, checking the Ed25519 signatures, and confirming the Rekor inclusion proof — with no
      trust placed in Vindicara, the covered entity, or the AI vendor.
    </p>

    <div class="sigline">
      <div><div class="sl"></div>Signature — {authority.name}, {authority.role}</div>
      <div><div class="sl"></div>Date</div>
    </div>
    <div class="classification">Demonstrates Project AIR’s mapping to the HIPAA Security Rule. Demo Mode — figures are illustrative (synthetic data).</div>
  </section>
</article>

<style>
  .report-doc { display: flex; flex-direction: column; align-items: center; gap: 22px; padding: 6px 0 30px; }
  .page { background: #fff; color: #16181d; width: 100%; max-width: 820px; padding: 54px 60px; box-shadow: 0 18px 50px rgba(0,0,0,.5); font-family: 'Hanken Grotesk', system-ui, sans-serif; font-size: 13.5px; line-height: 1.6; }
  .page :global(.mono) { font-family: 'IBM Plex Mono', monospace; }
  h1 { font-family: 'Fraunces', Georgia, serif; font-size: 31px; font-weight: 700; line-height: 1.1; margin: 26px 0 8px; }
  h2 { font-family: 'Fraunces', Georgia, serif; font-size: 21px; font-weight: 600; margin: 0 0 12px; border-bottom: 2px solid #16181d; padding-bottom: 7px; }
  h2.mt { margin-top: 26px; }
  p { margin: 0 0 12px; }
  b { font-weight: 700; }
  .wordmark { font-family: 'Fraunces', serif; font-size: 19px; font-weight: 600; display: flex; align-items: center; gap: 8px; }
  .wordmark .air { color: #E63946; font-weight: 700; }
  .wordmark .dot { width: 11px; height: 11px; border-radius: 2px; background: #E63946; }
  .tagline { font-family: 'IBM Plex Mono', monospace; font-size: 10px; letter-spacing: .28em; text-transform: uppercase; color: #6b7280; margin-top: 4px; }
  .subtitle { color: #4b5563; font-size: 15px; margin-bottom: 24px; }
  .meta { display: grid; gap: 7px; margin: 0 0 22px; }
  .meta > div { display: grid; grid-template-columns: 170px 1fr; gap: 12px; border-bottom: 1px solid #e5e7eb; padding-bottom: 6px; }
  .meta dt { color: #6b7280; font-size: 12px; }
  .meta dd { font-weight: 600; }
  .authbox { border: 2px solid #E63946; padding: 14px 18px; margin: 6px 0 20px; background: #fff5f5; }
  .authlabel { font-family: 'IBM Plex Mono', monospace; font-size: 10px; letter-spacing: .16em; text-transform: uppercase; color: #b91c1c; }
  .authname { font-family: 'Fraunces', serif; font-size: 21px; font-weight: 700; margin-top: 3px; }
  .authrole { font-size: 13px; color: #374151; }
  .authmethod { font-size: 11.5px; color: #6b7280; margin-top: 5px; }
  .attest { font-size: 12.5px; color: #374151; border-left: 3px solid #cbd5e1; padding-left: 14px; }
  table { width: 100%; border-collapse: collapse; font-size: 11.5px; margin: 8px 0; }
  th { text-align: left; border-bottom: 1.5px solid #16181d; padding: 7px 8px; font-size: 10px; letter-spacing: .04em; text-transform: uppercase; color: #6b7280; }
  td { border-bottom: 1px solid #e5e7eb; padding: 8px 8px; vertical-align: top; }
  .hipaa td:first-child { white-space: nowrap; }
  .cite { font-size: 10.5px; color: #b91c1c; }
  .cname { font-weight: 700; font-size: 12px; margin-top: 2px; }
  .evid { margin-top: 5px; font-size: 10.5px; color: #6b7280; }
  .st { color: #047857; font-weight: 700; white-space: nowrap; }
  .ok { color: #047857; font-weight: 600; }
  .breach td:first-child { white-space: nowrap; }
  .finding { background: #f0fdf4; border: 1px solid #bbf7d0; padding: 11px 14px; font-size: 12.5px; }
  .anchor { display: grid; gap: 5px; font-size: 10.5px; margin-bottom: 14px; }
  .anchor > div { display: grid; grid-template-columns: 200px 1fr; gap: 10px; }
  .anchor dt { color: #6b7280; font-family: 'Hanken Grotesk', sans-serif; }
  .anchor dd { word-break: break-all; }
  .closing { font-size: 12.5px; font-weight: 600; }
  .sigline { display: grid; grid-template-columns: 1fr 1fr; gap: 40px; margin-top: 36px; }
  .sigline .sl { border-top: 1px solid #16181d; margin-bottom: 5px; }
  .sigline > div { font-size: 11px; color: #6b7280; }
  .classification { margin-top: 18px; font-family: 'IBM Plex Mono', monospace; font-size: 10px; letter-spacing: .08em; text-transform: uppercase; color: #9ca3af; }
  @media (max-width: 900px) { .page { padding: 34px 26px; } .meta > div, .anchor > div { grid-template-columns: 1fr; gap: 2px; } }
</style>
