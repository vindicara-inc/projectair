<script>
  import { goto } from '$app/navigation';
  import AppShell from '$components/AppShell.svelte';
</script>
<svelte:head><title>Project AIR · Enterprise &amp; Air-gapped</title></svelte:head>

<AppShell active="pricing" title="pricing" scroll>
  <div class="shead">
    <div>
      <div class="eyebrow"><a class="back" href="/pricing">← Pricing</a> · Enterprise &amp; Air-gapped</div>
      <h2>Regulated, audit-grade, sovereign.</h2>
    </div>
    <span class="sp"></span>
    <p class="lead">Where the record is a legal obligation: six-year retention floors, retention-locked storage, your own infrastructure with no phone-home. Both tiers build on everything in Team.</p>
  </div>

  <div class="tiers">

    <div class="tier feat">
      <div class="tn">Enterprise</div><div class="tl">regulated · audit-grade</div>
      <div class="price talk">Talk to us</div>
      <ul>
        <li class="plus">Everything in Team, plus</li>
        <li>Custom volume · 6-year retention</li>
        <li>Tamper-evident, retention-locked storage</li>
        <li>SOC 2-AI + compliance reports</li>
        <li>BAA / HIPAA contractual coverage</li>
        <li>Vindicara-named FRE 902 attestation · litigation-hold</li>
        <li>SSO / OIDC · SLA</li>
        <li>ML-DSA-65 post-quantum re-anchoring</li>
        <li>Agent IAM (full L4) · cross-agent identity</li>
        <li>Dedicated single-tenant / on-prem · dedicated IR</li>
      </ul>
      <button class="pb buy" onclick={() => goto('/contact')}>Book an agent audit</button>
    </div>

    <div class="tier">
      <div class="tn">Air-gapped</div><div class="tl">sovereign</div>
      <div class="price talk">License</div>
      <ul>
        <li class="plus">Everything in Enterprise, plus</li>
        <li>Your infrastructure, unbounded</li>
        <li>Fully offline operation · no phone-home</li>
        <li>Unlimited retention · your WORM</li>
        <li>Air-gapped license</li>
        <li>BAA · Admissibility Pack (FRE 902)</li>
      </ul>
      <button class="pb" onclick={() => goto('/contact')}>Talk to us</button>
    </div>

  </div>

  <div class="how">
    <h3>How long do you need to prove what your agents did?</h3>
    <div class="hgrid">
      <div><b>30 days</b><span>Pro · operational &amp; incident window</span></div>
      <div><b>1 year</b><span>Team · your full SOC 2 audit period</span></div>
      <div><b>6 years</b><span>Enterprise · HIPAA (45 CFR 164.316) and FINRA / SEC 17a-4 floor</span></div>
      <div><b>Forever</b><span>Air-gapped · sovereign, on your own iron</span></div>
    </div>
  </div>

  <div class="ladder">
    <div class="lh">The ladder</div>
    <ul>
      <li><b>Pro → Team</b> · keep it a year, for your whole team. Your SOC 2 window.</li>
      <li><b>Team → Enterprise</b> · keep it six years, retention-locked, to your regulatory floor.</li>
      <li><b>Enterprise → Air-gapped</b> · hold it forever, on your own infrastructure, under license.</li>
    </ul>
  </div>

  <div class="why">
    <div class="lt"><b>We produce the record. You take it into your audit.</b> Project AIR is the agent-level evidence SOC 2, HIPAA, and ISO 42001 reviews now ask for and that generic GRC tools don't produce. We are not the auditor, and never the verdict.</div>
  </div>
</AppShell>

<style>
  .back{color:var(--air2);text-decoration:none}
  .back:hover{text-decoration:underline}
  .tiers{display:grid;grid-template-columns:repeat(2,1fr);gap:14px;max-width:760px;margin:0 auto}
  .tier{background:var(--panel);border:1px solid var(--line);box-shadow:var(--shadow);padding:18px;display:flex;flex-direction:column}
  .tier.feat{border-color:var(--air);box-shadow:0 18px 46px -22px rgba(230,57,70,.5)}
  .tn{font-family:var(--display);font-size:20px;font-weight:600}
  .tl{font-family:var(--mono);font-size:9px;letter-spacing:.1em;text-transform:uppercase;color:var(--faint);margin-top:3px;margin-bottom:12px}
  .price{font-family:var(--display);font-size:26px;font-weight:600;margin-bottom:12px}
  .price.talk{font-size:15px;color:var(--soft);font-weight:500}
  ul{list-style:none;margin:0 0 4px;padding:0;display:flex;flex-direction:column;gap:9px;flex:1}
  li{font-size:12px;color:var(--soft);display:flex;gap:8px;line-height:1.4}
  li::before{content:'›';color:var(--air2);font-weight:700}
  li.plus{color:var(--white);font-weight:600}
  li.plus::before{content:'+';color:var(--air2)}
  .pb{display:block;text-align:center;text-decoration:none;padding:11px;border:1px solid var(--line);font-weight:600;font-size:12px;cursor:pointer;background:none;color:var(--white);margin-top:14px}
  .pb.buy{background:var(--air);color:#fff;border-color:var(--air)}
  .pb.buy:hover{filter:brightness(1.08)}
  .how{margin-top:26px;border-top:1px solid var(--line2);padding-top:22px}
  .how h3{font-family:var(--display);font-size:17px;font-weight:600;margin:0 0 14px}
  .hgrid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
  .hgrid > div{background:var(--panel);border:1px solid var(--line);padding:14px}
  .hgrid b{font-family:var(--display);font-size:18px;color:var(--air2);display:block;margin-bottom:5px}
  .hgrid span{font-size:11.5px;color:var(--soft);line-height:1.45}
  .ladder{margin-top:22px}
  .lh{font-family:var(--mono);font-size:9px;letter-spacing:.1em;text-transform:uppercase;color:var(--faint);margin-bottom:10px}
  .ladder ul{gap:8px}
  .ladder li{font-size:13px;color:var(--soft)} .ladder li b{color:var(--white);font-weight:600}
  .why{display:flex;gap:18px;align-items:center;background:var(--airbg);border:1px solid rgba(230,57,70,.28);padding:18px 22px;margin-top:22px}
  .why .lt{font-size:13px;color:var(--soft);line-height:1.55} .why .lt b{color:var(--white);font-weight:600}
  @media (max-width:760px){ .tiers{grid-template-columns:1fr} .hgrid{grid-template-columns:1fr 1fr} }
  @media (max-width:620px){ .hgrid{grid-template-columns:1fr} }
</style>
