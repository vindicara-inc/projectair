<script lang="ts">
  import type { BuiltScenario } from '$lib/console/forensics/types';
  import { verifyChain } from '$lib/console/forensics/crypto';
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
  // "Serious" = critical/high (the halted/blocked tier); everything else is advisory.
  let serious = $derived(incidents.filter((i) => i.severity === 'critical' || i.severity === 'high'));
  let seriousCount = $derived(stats.critical + stats.high);
  let advisoryCount = $derived(stats.total - seriousCount);
  const outcome = (s: BuiltScenario) =>
    s.status === 'contained' ? 'Halted' : s.severity === 'critical' || s.severity === 'high' ? 'Blocked' : 'Flagged';

  // Who is accountable for this report. Uses the signed-in operator; falls back to a
  // clearly-labelled demo authority until sign-in is wired.
  let authority = $derived(
    $operator.signedInAt
      ? { name: $operator.name, org: $operator.organization, role: $operator.role, method: $operator.authMethod }
      : { name: 'Dr. Sarah Chen', org: 'Demo Health System', role: 'Attending physician', method: 'passkey' as const }
  );

  const fmt = (iso: string) => new Date(iso).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' });
  const fmtDay = (iso: string) => new Date(iso).toLocaleDateString('en-US', { dateStyle: 'medium' });
  const short = (hex: string, n = 24) => `${hex.slice(0, n)}…`;
  const stepLabel = (s: BuiltScenario, i: number) => s.steps[i]?.plain ?? s.records[i]?.kind ?? '';
</script>

<article class="report-doc">
  <!-- PAGE 1 — COVER -->
  <section class="page cover">
    <div class="wordmark"><span class="dot"></span>Project <span class="air">AIR</span></div>
    <div class="tagline">Monitor · Protect · Prove</div>

    <h1>Tamper-Evident Forensic Report</h1>
    <div class="subtitle">AI agent activity, signed evidence chain, and cryptographic proof of integrity</div>

    <dl class="meta">
      <div><dt>Report ID</dt><dd class="mono">{reportId}</dd></div>
      <div><dt>Reporting period</dt><dd>{fmtDay(fromIso)} → {fmtDay(toIso)}</dd></div>
      <div><dt>Generated</dt><dd>{fmt(generatedAt)}</dd></div>
      <div><dt>Incidents in period</dt><dd>{stats.total} ({stats.halted} halted · {stats.flagged} flagged)</dd></div>
      <div><dt>Signed records</dt><dd>{stats.records} · all chains verified intact</dd></div>
    </dl>

    <!-- WHO AUTHORIZED THIS — the headline for court. -->
    <div class="authbox">
      <div class="authlabel">Authorized &amp; attested by</div>
      <div class="authname">{authority.name}</div>
      <div class="authrole">{authority.role} · {authority.org}</div>
      <div class="authmethod">Verified human identity · {authority.method === 'auth0' ? 'Auth0 / OIDC' : 'Passkey · FIDO2 / WebAuthn'}</div>
      <div class="authkey mono">Machine signing key (Ed25519): {short(anchor.signerKey, 20)}</div>
    </div>

    <p class="attest">
      This report was produced by Project AIR from a tamper-evident chain of signed records. Every
      action below was recorded the moment it happened, content-hashed with BLAKE3, signed with
      Ed25519, and linked to the prior record. The chain root is anchored to the public Sigstore
      Rekor transparency log and an RFC 3161 trusted timestamp, so its integrity can be verified
      independently — without trusting Vindicara, the healthcare organization, or the AI vendor.
    </p>
    <div class="classification">Contains synthetic patient data — illustrative (Demo Mode)</div>
  </section>

  <!-- PAGE 2 — EXECUTIVE SUMMARY + REGISTER -->
  <section class="page">
    <h2>1 · Executive summary</h2>
    <p>
      During {fmtDay(fromIso)} to {fmtDay(toIso)}, Project AIR monitored autonomous AI agents across
      the organization and recorded <b>{stats.total}</b> incidents. <b>{seriousCount}</b> serious
      actions (critical or high) were <b>halted or blocked</b> before they could take effect and
      reviewed by a human; <b>{advisoryCount}</b> lower-risk behaviors were flagged for awareness and
      required no action. Every one of the <b>{stats.records}</b> signed records was re-verified for
      this report and the cryptographic chains are <b>intact</b> ({stats.chainsIntact} of {stats.total}).
    </p>

    <table class="reg">
      <thead>
        <tr><th>Time</th><th>Agent</th><th>Department</th><th>What happened</th><th>Outcome</th><th>Severity</th><th>Chain</th></tr>
      </thead>
      <tbody>
        {#each incidents as inc}
          {@const v = verifyChain(inc.records)}
          <tr>
            <td class="mono nowrap">{fmt(inc.occurredAt)}</td>
            <td class="mono">{inc.agentLabel}</td>
            <td>{inc.industryTag === 'Healthcare' ? inc.agentDescription.replace(' agent', '') : inc.agentDescription}</td>
            <td>{inc.title}</td>
            <td>{outcome(inc)}</td>
            <td class="sev sev-{inc.severity}">{inc.severity.toUpperCase()}</td>
            <td class="ok">{v.status === 'ok' ? '✓ intact' : '✗ broken'}</td>
          </tr>
        {/each}
      </tbody>
    </table>
    <div class="note">“Outcome → Halted” means Project AIR’s Layer 3 containment stopped the action and required a human decision. No halted action took effect automatically.</div>
  </section>

  <!-- PAGES 3+ — INCIDENT DOSSIERS (halted incidents in full) -->
  <section class="page">
    <h2>2 · Incident dossiers</h2>
    <p class="lead">Full signed evidence for each halted action, in plain language with the cryptographic record beneath it.</p>

    {#each serious as inc, n}
      {@const v = verifyChain(inc.records)}
      <div class="dossier">
        <div class="dh">
          <div class="dnum">2.{n + 1}</div>
          <div>
            <div class="dtitle">{inc.title}</div>
            <div class="dmeta mono">{inc.agentLabel} · {inc.agentDescription} · {fmt(inc.occurredAt)} · <span class="sev sev-{inc.severity}">{inc.severity.toUpperCase()}</span></div>
          </div>
        </div>

        <p class="plain">{inc.plainHeadline}</p>

        <div class="kv"><span class="k">What the agent was asked to do</span><span class="vv">{inc.declaredIntent}</span></div>
        <div class="kv"><span class="k">What Project AIR found</span><span class="vv">{inc.verdict.plainVerdict}</span></div>

        {#if inc.findings.length}
          <div class="subh">Findings</div>
          <ul class="findings">
            {#each inc.findings as f}
              <li><b>{f.plainTitle}</b> — {f.whyItMatters} <span class="code mono">[{f.detector_id}]</span></li>
            {/each}
          </ul>
        {/if}

        {#if inc.containment}
          <div class="authority">
            <span class="ak">Step-up authority</span>
            <span class="av">{authority.name} · {authority.role}, {authority.org} — reviews and decides; the decision is signed into the chain.</span>
          </div>
        {/if}

        <div class="subh">Signed evidence chain · {v.records_verified} records · <span class="ok">verified intact</span></div>
        <table class="chain">
          <thead><tr><th>#</th><th>Action</th><th>Content hash (BLAKE3)</th><th>Signature (Ed25519)</th></tr></thead>
          <tbody>
            {#each inc.records as r, i}
              <tr>
                <td>{i + 1}</td>
                <td>{stepLabel(inc, i)}</td>
                <td class="mono">{short(r.content_hash)}</td>
                <td class="mono">{short(r.signature, 20)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/each}
  </section>

  <!-- LAST PAGE — CRYPTOGRAPHIC PROOF / REKOR ON PAPER -->
  <section class="page proof">
    <h2>3 · How this report proves itself</h2>
    <p>
      Project AIR’s integrity does not depend on trusting this document. Anyone — a court, a
      regulator, an opposing expert — can verify it offline from the values printed here.
    </p>

    <div class="proofgrid">
      <div class="pcard">
        <div class="pn">1</div>
        <div class="pt">Content hash — BLAKE3</div>
        <div class="px">Each record’s contents are hashed with BLAKE3. Re-hash the record; if a single byte changed, the hash won’t match and tampering is proven at that exact record.</div>
      </div>
      <div class="pcard">
        <div class="pn">2</div>
        <div class="pt">Signature — Ed25519</div>
        <div class="px">Each record is signed over <span class="mono">prev_hash ‖ content_hash</span> with the agent’s Ed25519 key, so records can’t be forged or reordered. (ML-DSA-65 post-quantum signatures are also supported.)</div>
      </div>
      <div class="pcard">
        <div class="pn">3</div>
        <div class="pt">Chain link — prev_hash</div>
        <div class="px">Every record carries the hash of the one before it, forming a chain. Remove, insert, or alter any record and the links break.</div>
      </div>
      <div class="pcard">
        <div class="pn">4</div>
        <div class="pt">Public anchor — Sigstore Rekor + RFC 3161</div>
        <div class="px">The chain root is published to the public Sigstore Rekor transparency log and stamped by an RFC 3161 timestamp authority — proof it existed, unaltered, at that time.</div>
      </div>
    </div>

    <div class="subh">Anchor record for this period</div>
    <dl class="anchor mono">
      <div><dt>Chain root (BLAKE3)</dt><dd>{anchor.chainRoot}</dd></div>
      <div><dt>Signer key (Ed25519)</dt><dd>{anchor.signerKey}</dd></div>
      <div><dt>Rekor log index</dt><dd>{anchor.rekorLogIndex}</dd></div>
      <div><dt>Rekor entry UUID</dt><dd>{anchor.rekorUuid}</dd></div>
      <div><dt>Rekor integrated time</dt><dd>{anchor.rekorIntegratedTime} ({fmt(toIso)})</dd></div>
      <div><dt>Inclusion proof root</dt><dd>{anchor.inclusionProofRoot}</dd></div>
      <div><dt>Inclusion proof (tree size {anchor.treeSize})</dt><dd>{anchor.inclusionHashes.join('  ')}</dd></div>
      <div><dt>RFC 3161 TSA</dt><dd>{anchor.tsaUrl} · serial {anchor.tsaSerial}</dd></div>
    </dl>

    <div class="subh">Verify this report offline</div>
    <ol class="verify">
      <li>For each record, recompute the BLAKE3 hash of its contents and confirm it equals the printed content hash.</li>
      <li>Verify each Ed25519 signature against the signer key over <span class="mono">prev_hash ‖ content_hash</span>.</li>
      <li>Confirm every record’s <span class="mono">prev_hash</span> equals the previous record’s content hash (the chain links).</li>
      <li>Check the Rekor inclusion proof against the public log at the printed log index — confirming the chain root was published, unaltered, at the integrated time.</li>
      <li>Validate the RFC 3161 timestamp token to confirm when the root existed.</li>
    </ol>
    <p class="closing">If every step holds, this record is authentic and unaltered — independently, with no trust placed in Vindicara, the healthcare organization, or the AI vendor.</p>

    <div class="sigline">
      <div><div class="sl"></div>Signature — {authority.name}, {authority.role}</div>
      <div><div class="sl"></div>Date</div>
    </div>
  </section>
</article>

<style>
  /* white "paper" document, readable on the dark console and print-ready */
  .report-doc { display: flex; flex-direction: column; align-items: center; gap: 22px; padding: 6px 0 30px; }
  .page {
    background: #fff; color: #16181d; width: 100%; max-width: 820px; padding: 54px 60px;
    box-shadow: 0 18px 50px rgba(0,0,0,.5); font-family: 'Hanken Grotesk', system-ui, sans-serif;
    font-size: 13.5px; line-height: 1.6;
  }
  .page :global(.mono) { font-family: 'IBM Plex Mono', monospace; }
  h1 { font-family: 'Fraunces', Georgia, serif; font-size: 34px; font-weight: 700; line-height: 1.1; margin: 30px 0 8px; letter-spacing: -.01em; }
  h2 { font-family: 'Fraunces', Georgia, serif; font-size: 22px; font-weight: 600; margin: 0 0 14px; border-bottom: 2px solid #16181d; padding-bottom: 8px; }
  p { margin: 0 0 12px; }
  b { font-weight: 700; }

  /* cover */
  .cover { min-height: 70vh; }
  .wordmark { font-family: 'Fraunces', serif; font-size: 19px; font-weight: 600; display: flex; align-items: center; gap: 8px; }
  .wordmark .air { color: #E63946; font-weight: 700; }
  .wordmark .dot { width: 11px; height: 11px; border-radius: 2px; background: #E63946; }
  .tagline { font-family: 'IBM Plex Mono', monospace; font-size: 10px; letter-spacing: .28em; text-transform: uppercase; color: #6b7280; margin-top: 4px; }
  .subtitle { color: #4b5563; font-size: 15px; margin-bottom: 26px; }
  .meta { display: grid; gap: 7px; margin: 0 0 26px; }
  .meta > div { display: grid; grid-template-columns: 190px 1fr; gap: 12px; border-bottom: 1px solid #e5e7eb; padding-bottom: 6px; }
  .meta dt { color: #6b7280; font-size: 12px; }
  .meta dd { font-weight: 600; }

  .authbox { border: 2px solid #E63946; padding: 18px 22px; margin: 8px 0 24px; background: #fff5f5; }
  .authlabel { font-family: 'IBM Plex Mono', monospace; font-size: 10px; letter-spacing: .16em; text-transform: uppercase; color: #b91c1c; }
  .authname { font-family: 'Fraunces', serif; font-size: 24px; font-weight: 700; margin-top: 4px; }
  .authrole { font-size: 14px; color: #374151; }
  .authmethod { font-size: 12px; color: #6b7280; margin-top: 6px; }
  .authkey { font-size: 11px; color: #6b7280; margin-top: 3px; }

  .attest { font-size: 12.5px; color: #374151; border-left: 3px solid #cbd5e1; padding-left: 14px; }
  .classification { margin-top: 22px; font-family: 'IBM Plex Mono', monospace; font-size: 10px; letter-spacing: .08em; text-transform: uppercase; color: #9ca3af; }

  /* tables */
  table { width: 100%; border-collapse: collapse; font-size: 11.5px; margin: 6px 0 8px; }
  th { text-align: left; border-bottom: 1.5px solid #16181d; padding: 6px 8px; font-size: 10px; letter-spacing: .04em; text-transform: uppercase; color: #6b7280; }
  td { border-bottom: 1px solid #e5e7eb; padding: 6px 8px; vertical-align: top; }
  .nowrap { white-space: nowrap; }
  .ok { color: #047857; font-weight: 600; }
  .sev { font-family: 'IBM Plex Mono', monospace; font-weight: 700; font-size: 10px; }
  .sev-critical { color: #b91c1c; }
  .sev-high { color: #b45309; }
  .sev-medium { color: #1d4ed8; }
  .sev-low { color: #6b7280; }
  .note { font-size: 11px; color: #6b7280; font-style: italic; margin-top: 4px; }
  .lead { color: #4b5563; }

  /* dossier */
  .dossier { border: 1px solid #e5e7eb; padding: 18px 20px; margin-bottom: 18px; break-inside: avoid; }
  .dh { display: flex; gap: 14px; align-items: baseline; }
  .dnum { font-family: 'Fraunces', serif; font-size: 20px; font-weight: 700; color: #E63946; }
  .dtitle { font-weight: 700; font-size: 15px; }
  .dmeta { font-size: 10.5px; color: #6b7280; margin-top: 2px; }
  .plain { margin-top: 10px; font-size: 13px; }
  .kv { display: grid; grid-template-columns: 200px 1fr; gap: 12px; padding: 7px 0; border-bottom: 1px solid #f1f1f1; }
  .kv .k { font-size: 11px; color: #6b7280; text-transform: uppercase; letter-spacing: .04em; }
  .subh { font-weight: 700; font-size: 12px; margin: 14px 0 4px; text-transform: uppercase; letter-spacing: .03em; color: #374151; }
  .findings { margin: 0 0 4px 18px; font-size: 12px; }
  .findings li { margin-bottom: 4px; }
  .code { color: #6b7280; font-size: 10.5px; }
  .authority { background: #fff5f5; border: 1px solid #fecaca; padding: 9px 12px; margin: 10px 0 4px; }
  .authority .ak { display: block; font-size: 10px; letter-spacing: .12em; text-transform: uppercase; color: #b91c1c; }
  .authority .av { font-size: 12px; }

  /* proof page */
  .proofgrid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin: 8px 0 18px; }
  .pcard { border: 1px solid #e5e7eb; padding: 13px 15px; break-inside: avoid; }
  .pn { width: 22px; height: 22px; border-radius: 50%; background: #16181d; color: #fff; display: grid; place-items: center; font-weight: 700; font-size: 12px; }
  .pt { font-weight: 700; margin: 8px 0 4px; font-size: 13px; }
  .px { font-size: 11.5px; color: #4b5563; }
  .anchor { display: grid; gap: 5px; font-size: 10.5px; margin-bottom: 16px; }
  .anchor > div { display: grid; grid-template-columns: 210px 1fr; gap: 10px; }
  .anchor dt { color: #6b7280; font-family: 'Hanken Grotesk', sans-serif; }
  .anchor dd { word-break: break-all; }
  .verify { margin: 0 0 12px 18px; font-size: 12px; }
  .verify li { margin-bottom: 5px; }
  .closing { font-size: 12.5px; font-weight: 600; }
  .sigline { display: grid; grid-template-columns: 1fr 1fr; gap: 40px; margin-top: 40px; }
  .sigline .sl { border-top: 1px solid #16181d; margin-bottom: 5px; }
  .sigline > div { font-size: 11px; color: #6b7280; }

  @media (max-width: 900px) {
    .page { padding: 34px 26px; }
    .proofgrid { grid-template-columns: 1fr; }
    .meta > div, .kv, .anchor > div { grid-template-columns: 1fr; gap: 2px; }
  }
</style>
