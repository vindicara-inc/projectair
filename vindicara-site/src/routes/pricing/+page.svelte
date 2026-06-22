<script>
  import { goto } from '$app/navigation';
  import AppShell from '$components/AppShell.svelte';

  // Stripe Payment Link for Pro (Individual monthly). Payment Links are public;
  // this one fires checkout.session.completed, which the deployed license webhook
  // turns into a signed Pro license token + fulfillment email.
  const PRO_CHECKOUT = 'https://buy.stripe.com/dRm4gy7fk7IwbfO1eT1RC06';
</script>
<svelte:head><title>Project AIR · Pricing</title></svelte:head>

<AppShell active="pricing" title="pricing" scroll>
  <div class="shead">
    <div><div class="eyebrow">Pricing</div><h2>Evidence for what your agents did.</h2></div>
    <span class="sp"></span>
    <p class="lead">Retention-metered: how long you keep the record is the only lever that moves price. Free shows the shape. Paid keeps it provable, signed, and retained to your regulatory floor.</p>
  </div>

  <div class="tiers">

    <div class="tier">
      <div class="tn">Free</div><div class="tl">community · evaluate</div>
      <div class="price">$0</div>
      <ul>
        <li>10K hosted + unlimited local</li>
        <li>7-day retention · read-only viewer</li>
        <li>Standard storage</li>
      </ul>
      <button class="pb" onclick={() => goto('/get-started')}>pip install projectair</button>
    </div>

    <div class="tier">
      <div class="tn">Pro</div><div class="tl">individual · self-serve</div>
      <div class="price">$45<span>/mo</span></div>
      <ul>
        <li>1M records / mo</li>
        <li>90-day retention</li>
        <li>Hosted FlightDeck console</li>
        <li>Standard storage</li>
      </ul>
      <a class="pb buy" href={PRO_CHECKOUT}>Get Pro →</a>
    </div>

    <div class="tier">
      <div class="tn">Team</div><div class="tl">prove it</div>
      <div class="price talk">Talk to us</div>
      <ul>
        <li>5M / mo pooled · generous seats</li>
        <li>1-year retention</li>
        <li>Standard storage</li>
      </ul>
      <button class="pb" onclick={() => goto('/contact')}>Talk to us</button>
    </div>

    <div class="tier feat">
      <div class="tn">Enterprise</div><div class="tl">regulated · audit-grade</div>
      <div class="price talk">Talk to us</div>
      <ul>
        <li>Custom volume</li>
        <li>6-year retention</li>
        <li>Tamper-evident, retention-locked storage</li>
        <li>SSO · SLA · compliance reports</li>
      </ul>
      <button class="pb" onclick={() => goto('/contact')}>Book an agent audit</button>
    </div>

    <div class="tier">
      <div class="tn">Air-gapped</div><div class="tl">sovereign</div>
      <div class="price talk">License</div>
      <ul>
        <li>Your infra, unbounded</li>
        <li>Unlimited retention</li>
        <li>Your WORM, no phone-home</li>
        <li>BAA · Admissibility Pack</li>
      </ul>
      <button class="pb" onclick={() => goto('/contact')}>Talk to us</button>
    </div>

  </div>

  <p class="note">A record is one signed step: a tool call, an LLM call, a decision. A typical agent task is dozens of records. Volume limits are generous guardrails, not a meter; the upgrade trigger is always "keep it longer, for compliance, for my team."</p>

  <div class="how">
    <h3>How long do you need to prove what your agents did?</h3>
    <div class="hgrid">
      <div><b>90 days</b><span>operational & incident window</span></div>
      <div><b>1 year</b><span>your full SOC 2 audit period</span></div>
      <div><b>6 years</b><span>HIPAA (45 CFR 164.316) and FINRA / SEC 17a-4 books-and-records floor</span></div>
      <div><b>Forever</b><span>sovereign, air-gapped, on your own iron</span></div>
    </div>
  </div>

  <div class="ladder">
    <div class="lh">The ladder</div>
    <ul>
      <li><b>Free → Pro</b> · get it off your laptop, hosted and kept 90 days.</li>
      <li><b>Pro → Team</b> · keep it a year, for your whole team. Your SOC 2 window.</li>
      <li><b>Team → Enterprise</b> · keep it 6 years, retention-locked, to your regulatory floor.</li>
      <li><b>Enterprise → Air-gapped</b> · hold it forever, on your own infrastructure, under license.</li>
    </ul>
  </div>

  <div class="why">
    <div class="lt"><b>We produce the record. You take it into your audit.</b> Project AIR is the agent-level evidence SOC 2, HIPAA, and ISO 42001 reviews now ask for and that generic GRC tools don't produce. We are not the auditor, and never the verdict.</div>
  </div>
</AppShell>

<style>
  .tiers{display:grid;grid-template-columns:repeat(5,1fr);gap:14px}
  .tier{background:var(--panel);border:1px solid var(--line);box-shadow:var(--shadow);padding:18px;display:flex;flex-direction:column}
  .tier.feat{border-color:var(--air);box-shadow:0 18px 46px -22px rgba(230,57,70,.5)}
  .tn{font-family:var(--display);font-size:20px;font-weight:600}
  .tl{font-family:var(--mono);font-size:9px;letter-spacing:.1em;text-transform:uppercase;color:var(--faint);margin-top:3px;margin-bottom:12px}
  .price{font-family:var(--display);font-size:26px;font-weight:600;margin-bottom:12px}
  .price span{font-family:var(--mono);font-size:11px;color:var(--faint);font-weight:400}
  .price.talk{font-size:15px;color:var(--soft);font-weight:500}
  ul{list-style:none;margin:0 0 4px;display:flex;flex-direction:column;gap:9px;flex:1}
  li{font-size:12px;color:var(--soft);display:flex;gap:8px;line-height:1.4}
  li::before{content:'›';color:var(--air2);font-weight:700}
  .pb{display:block;text-align:center;text-decoration:none;padding:11px;border:1px solid var(--line);font-weight:600;font-size:12px;cursor:pointer;background:none;color:var(--white);margin-top:14px}
  .tier.feat .pb{background:var(--air);color:#fff;border-color:var(--air)}
  .pb.buy{background:var(--air);color:#fff;border-color:var(--air)}
  .pb.buy:hover{filter:brightness(1.08)}
  .note{font-family:var(--mono);font-size:10.5px;color:var(--faint);margin-top:18px;text-align:center;line-height:1.6;max-width:84ch;margin-left:auto;margin-right:auto}
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
  @media (max-width:1080px){ .tiers{grid-template-columns:repeat(3,1fr)} .hgrid{grid-template-columns:1fr 1fr} }
  @media (max-width:620px){ .tiers{grid-template-columns:1fr} .hgrid{grid-template-columns:1fr} }
</style>
