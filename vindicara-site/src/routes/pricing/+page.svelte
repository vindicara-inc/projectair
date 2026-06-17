<script>
  import { goto } from '$app/navigation';
  import AppShell from '$components/AppShell.svelte';
</script>
<svelte:head><title>Project AIR · Pricing</title></svelte:head>

<AppShell active="pricing" title="pricing" scroll>
  <div class="shead">
    <div><div class="eyebrow">Pricing</div><h2>Free shows the shape. Paid makes it provable.</h2></div>
    <span class="sp"></span>
    <p class="lead">The free tier lets you watch what your agents do. Everything that makes the record trustworthy, durable, and audit-ready lives behind the gate.</p>
  </div>

  <div class="tiers">

    <div class="tier">
      <div class="tn">Free</div><div class="tl">Community · evaluate</div>
      <ul>
        <li>100 raw captures</li>
        <li>Local CLI, view-only</li>
      </ul>
      <div class="nl">Not included</div>
      <ul class="excl">
        <li>16 detectors</li>
        <li>Signed chain</li>
        <li>Public anchoring</li>
        <li>Retention</li>
      </ul>
      <button class="pb" onclick={() => goto('/get-started')}>pip install projectair</button>
    </div>

    <div class="tier">
      <div class="tn">Team</div><div class="tl">prove it</div>
      <ul>
        <li>Unlimited Agent Audit Trail</li>
        <li>Signed chain + public anchoring</li>
        <li>16 detectors</li>
        <li>FlightDeck console</li>
        <li>Retention to your regulatory floor</li>
      </ul>
      <button class="pb" onclick={() => goto('/contact')}>Talk to us</button>
    </div>

    <div class="tier feat">
      <div class="tn">Enterprise</div><div class="tl">most teams here</div>
      <div class="plus2">Everything in Team, plus</div>
      <ul>
        <li>Containment (Protect)</li>
        <li>Causal graph, query, replay</li>
        <li>SIEM: Splunk · Datadog · Sentinel · Sumo</li>
        <li>Extended retention + PQ re-anchoring</li>
        <li>SSO / OIDC, SLA</li>
        <li>SOC 2 · HIPAA · ISO 42001 · EU AI Act · NIST</li>
      </ul>
      <button class="pb" onclick={() => goto('/contact')}>Book an agent audit</button>
    </div>

    <div class="tier">
      <div class="tn">Air-gapped</div><div class="tl">regulated · sovereign</div>
      <div class="plus2">Everything in Enterprise, plus</div>
      <ul>
        <li>Air-gapped license, no phone-home</li>
        <li>BAA</li>
        <li>HL7v2 / FHIR R4 interop</li>
        <li>On-prem / offline anchoring</li>
        <li>Admissibility Pack (FRE 902 + expert support)</li>
      </ul>
      <button class="pb" onclick={() => goto('/contact')}>Talk to us</button>
    </div>

  </div>

  <div class="payline">Retention is the lever: you don't pay us to store records, you pay us to keep them provable, signed, tamper-evident, and re-anchored, for as long as the law and a courtroom require.</div>

  <div class="why">
    <div class="lt"><b>We produce the record. You take it into your audit.</b> Project AIR is the agent-level evidence SOC 2, HIPAA, and ISO 42001 reviews now ask for and that generic GRC tools don't produce. We are not the auditor, and never the verdict.</div>
  </div>
</AppShell>

<style>
  .tiers{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
  .tier{background:var(--panel);border:1px solid var(--line);box-shadow:var(--shadow);padding:18px;display:flex;flex-direction:column}
  .tier.feat{border-color:var(--air);box-shadow:0 18px 46px -22px rgba(230,57,70,.5)}
  .tn{font-family:var(--display);font-size:20px;font-weight:600}
  .tl{font-family:var(--mono);font-size:9px;letter-spacing:.1em;text-transform:uppercase;color:var(--faint);margin-top:3px;margin-bottom:14px}
  .plus2{font-family:var(--mono);font-size:9px;letter-spacing:.08em;text-transform:uppercase;color:var(--faint);margin-bottom:4px}
  ul{list-style:none;margin:0 0 4px;display:flex;flex-direction:column;gap:9px}
  .tier > ul:first-of-type{flex:1}
  li{font-size:12px;color:var(--soft);display:flex;gap:8px;line-height:1.4}
  li::before{content:'›';color:var(--air2);font-weight:700}
  .nl{font-family:var(--mono);font-size:9px;letter-spacing:.08em;text-transform:uppercase;color:var(--faint);margin:10px 0 6px;border-top:1px solid var(--line2);padding-top:10px}
  .excl{flex:1}
  .excl li{color:var(--faint)}
  .excl li::before{content:'\2715';color:var(--air2);font-weight:700}
  .pb{text-align:center;padding:11px;border:1px solid var(--line);font-weight:600;font-size:12px;cursor:pointer;background:none;color:var(--white);margin-top:14px}
  .tier.feat .pb{background:var(--air);color:#fff;border-color:var(--air)}
  .payline{font-family:var(--mono);font-size:10.5px;color:var(--faint);margin-top:18px;text-align:center;line-height:1.6;max-width:80ch;margin-left:auto;margin-right:auto}
  .why{display:flex;gap:18px;align-items:center;background:var(--airbg);border:1px solid rgba(230,57,70,.28);padding:18px 22px;margin-top:20px}
  .why .lt{font-size:13px;color:var(--soft);line-height:1.55} .why .lt b{color:var(--white);font-weight:600}
  @media (max-width:1080px){ .tiers{grid-template-columns:1fr 1fr} }
  @media (max-width:620px){ .tiers{grid-template-columns:1fr} }
</style>
