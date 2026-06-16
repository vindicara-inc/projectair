<script>
  import { goto } from '$app/navigation';
  import AppShell from '$components/AppShell.svelte';
</script>
<svelte:head><title>Project AIR · Pricing</title></svelte:head>

<AppShell active="pricing" title="pricing">
  <div class="shead">
    <div><div class="eyebrow">Pricing</div><h2>Free to start. Priced for the buyer on the hook.</h2></div>
    <span class="sp"></span>
    <p class="lead">The CLI and SDK are open source and free forever. FlightDeck is where enforcement, identity binding, and evidence packs live.</p>
  </div>

  <div class="tiers">
    <div class="tier">
      <div class="tn">OSS</div><div class="tl">MIT · self-serve</div>
      <div class="pr">Free</div>
      <ul><li>air CLI and airsdk</li><li>All 16 detectors</li><li>Structural Verification floor</li><li>Sign and anchor to Rekor</li><li>Community support</li></ul>
      <button class="pb" onclick={() => goto('/contact')}>pip install projectair</button>
    </div>
    <div class="tier feat">
      <div class="tn">Team</div><div class="tl">most popular</div>
      <div class="pr">$599<small>/mo</small></div>
      <ul><li>Everything in OSS</li><li>FlightDeck console</li><li>Live enforcement floor</li><li>Human-identity binding</li><li>SIEM export, all five</li><li>Evidence packs</li></ul>
      <button class="pb" onclick={() => goto('/contact')}>Start with Team</button>
    </div>
    <div class="tier">
      <div class="tn">Enterprise</div><div class="tl">custom</div>
      <div class="pr">Custom</div>
      <ul><li>SSO and agent registry</li><li>Insurance API</li><li>Customer-VPC storage</li><li>Post-quantum signing</li><li>BAA and dedicated support</li></ul>
      <button class="pb" onclick={() => goto('/contact')}>Talk to us</button>
    </div>
  </div>
  <div class="payline">SIEM export covers Datadog, Splunk, Sumo Logic, Microsoft Sentinel, and Slack · payments processed by Stripe</div>

  <div class="why">
    <div class="seal"><span class="sk" style="font-size:11px">VS<br>SIEM</span></div>
    <div class="lt"><b>Why FlightDeck, when the CLI is free?</b> Splunk holds the text. Project AIR holds the mathematical proof. FlightDeck is the cryptographic verification and human-identity binding layer: it binds every agent to the named person who authorized it and proves the chain was never altered, which a log index alone cannot do.</div>
  </div>
</AppShell>

<style>
  .tiers{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
  .tier{background:var(--panel);border:1px solid var(--line);box-shadow:var(--shadow);padding:22px;display:flex;flex-direction:column}
  .tier.feat{border-color:var(--air);box-shadow:0 18px 46px -22px rgba(230,57,70,.5)}
  .tn{font-family:var(--display);font-size:20px;font-weight:600} .tl{font-family:var(--mono);font-size:9px;letter-spacing:.1em;text-transform:uppercase;color:var(--faint);margin-top:3px}
  .pr{font-family:var(--display);font-size:32px;font-weight:600;margin:16px 0 2px} .pr small{font-size:13px;color:var(--faint);font-family:var(--ui);font-weight:400}
  ul{list-style:none;margin:14px 0;display:flex;flex-direction:column;gap:9px;flex:1}
  li{font-size:12.5px;color:var(--soft);display:flex;gap:9px;line-height:1.4} li::before{content:'›';color:var(--air2);font-weight:700}
  .pb{text-align:center;padding:11px;border:1px solid var(--line);font-weight:600;font-size:12.5px;cursor:pointer;background:none;color:var(--white)}
  .tier.feat .pb{background:var(--air);color:#fff;border-color:var(--air)}
  .payline{font-family:var(--mono);font-size:10px;color:var(--faint);margin-top:16px;text-align:center}
  .why{display:flex;gap:18px;align-items:center;background:var(--airbg);border:1px solid rgba(230,57,70,.28);padding:18px 22px;margin-top:20px}
  .why .lt{font-size:13px;color:var(--soft);line-height:1.55} .why .lt b{color:var(--white);font-weight:600}
  @media (max-width:1080px){ .tiers{grid-template-columns:1fr} }
</style>
