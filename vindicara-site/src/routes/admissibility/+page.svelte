<script>
  import AppShell from '$components/AppShell.svelte';
</script>
<svelte:head><title>Project AIR · Admissibility</title></svelte:head>

<AppShell active="admissibility" title="admissibility" scroll={true}>
  <div class="adm">
    <header class="ahead">
      <div class="eyebrow">Admissibility</div>
      <h1>Built for the people who have to prove it.</h1>
      <p class="lead">Chain-of-custody designed for a skeptical reviewer. This page is written to survive the questions a security lead, a general counsel, or an insurer will actually ask. We are explicit about what Project AIR gives you and what stays your responsibility.</p>
    </header>

    <section class="bars">
      <div class="bar"><div class="bn">Signed at the source</div><p>Records are signed in-process by the same code that handles the action, at the moment it happens. Not tailed from logs. Not reconstructed by a batch job.</p></div>
      <div class="bar"><div class="bn">Tamper-evident</div><p>Forward-chained BLAKE3 content hashing with Ed25519 signatures and opt-in ML-DSA-65 post-quantum signing. Any altered or missing hop fails verification.</p></div>
      <div class="bar"><div class="bn">Publicly anchored</div><p>Chain roots are anchored to Sigstore Rekor. Anyone can verify a record against the public transparency log with zero Vindicara infrastructure in the path.</p></div>
      <div class="bar"><div class="bn">Court-supportable</div><p>FRE 902(13) self-authentication templates and an eIDAS mapping, with an honest disclosures section so nothing is overstated to a reviewer.</p></div>
    </section>

    <section class="split">
      <div class="prov a">
        <h3>Project AIR provides</h3>
        <ul>
          <li><span class="mk">✓</span>Records signed in-process at the moment of action, not reconstructed from logs.</li>
          <li><span class="mk">✓</span>FRE 902(13) self-authentication templates and an eIDAS mapping for EU proceedings.</li>
          <li><span class="mk">✓</span>Forward-chained BLAKE3 integrity with opt-in ML-DSA-65 post-quantum signing.</li>
          <li><span class="mk">✓</span>Public anchoring to Sigstore Rekor, independently verifiable.</li>
          <li><span class="mk">✓</span>Default-deny redaction so sensitive payloads are hashed, not stored in the clear.</li>
        </ul>
      </div>
      <div class="prov b">
        <h3>You provide</h3>
        <ul>
          <li><span class="mk">›</span>An operator-declared agent registry for the identity and scope detectors.</li>
          <li><span class="mk">›</span>A qualified person to attest the records under FRE 902(13).</li>
          <li><span class="mk">›</span>Your retention policy and your own legal review of any filing.</li>
          <li><span class="mk">›</span>The decision on whether host-clock timestamps meet your evidentiary bar.</li>
        </ul>
      </div>
    </section>

    <section class="law">
      <div class="seal"><span class="sk">AB<br>316</span></div>
      <div class="lt">California <b>AB 316</b> removes the defense that an AI system acted on its own. When "the agent did it autonomously" is off the table, the question becomes <b>who authorized the agent, and can you prove what it did</b>. That is the record Project AIR produces, and it is why delegated authority, not raw logging, is the thing worth proving.</div>
    </section>

    <section class="frameworks">
      <h2>The frameworks your auditor already speaks</h2>
      <div class="fw">
        <div class="fwi"><div class="fk">EU AI Act</div><div class="fv">Articles 12 and 72. Audit-trail retention and post-market monitoring evidence, exportable as conformity artifacts.</div></div>
        <div class="fwi"><div class="fk">HIPAA</div><div class="fv">HIPAA audit trail requirements (45 CFR 164.312(b)), with named clinician identity bound into the chain.</div></div>
        <div class="fwi"><div class="fk">NIST AI RMF</div><div class="fv">Map, Measure, Manage, and Govern functions backed by runtime evidence rather than policy documents.</div></div>
        <div class="fwi"><div class="fk">AgDR</div><div class="fv">AI Decision Records: BLAKE3 hashing, Ed25519 and opt-in ML-DSA-65, UUIDv7 ordering, forward-chained integrity.</div></div>
      </div>
    </section>

    <section class="disclose">
      <h2>Honest disclosures</h2>
      <p>Project AIR is technical documentation, not legal advice. It produces evidence inputs for the frameworks above. It is not a certification, and it does not judge an agent's intent. What it proves is narrow and defensible: that an agent's authority was bounded, that the boundary was enforced, and that the record of what happened was signed and anchored.</p>
      <p>Self-authentication under FRE 902(13) is a template and a workflow; admissibility in a specific matter is decided by a court, on your evidence, with your qualified witness. Host-clock timestamps are advanced, not court-qualified by default. Identity and scope detectors depend on an operator-declared agent registry that you maintain.</p>
      <p class="muted">We would rather you read this section and trust the rest than overclaim and lose you at the first hard question.</p>
    </section>
  </div>
</AppShell>

<style>
  .adm{max-width:920px;margin:0 auto;padding-bottom:30px}
  .ahead h1{font-size:40px;margin:14px 0 0;max-width:18ch}
  .ahead .lead{font-size:15px;margin-top:16px;max-width:64ch}
  .bars{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:30px 0}
  .bar{border-top:2px solid var(--air);padding-top:12px}
  .bar .bn{font-family:var(--display);font-size:15px;font-weight:600}
  .bar p{font-size:11.5px;color:var(--soft);margin-top:6px;line-height:1.5}
  .split{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:26px}
  .prov{background:var(--panel);border:1px solid var(--line);box-shadow:var(--shadow);padding:22px}
  .prov h3{font-family:var(--mono);font-size:10px;letter-spacing:.14em;text-transform:uppercase;margin-bottom:14px;font-weight:600}
  .prov.a h3{color:var(--good)} .prov.b h3{color:var(--air2)}
  .prov ul{list-style:none;display:flex;flex-direction:column;gap:11px}
  .prov li{display:flex;gap:11px;font-size:12.5px;color:var(--soft);line-height:1.45}
  .prov li .mk{flex:0 0 16px;color:var(--good);font-weight:700} .prov.b li .mk{color:var(--air2)}
  .law{display:flex;gap:18px;align-items:center;background:var(--airbg);border:1px solid rgba(230,57,70,.28);padding:20px 24px;margin-bottom:30px}
  .law .lt{font-size:13.5px;color:var(--soft);line-height:1.6} .law .lt b{color:var(--white);font-weight:600}
  .frameworks h2{font-size:22px;margin-bottom:16px}
  .fw{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:30px}
  .fwi{border:1px solid var(--line);background:var(--navy1);padding:16px}
  .fwi .fk{font-family:var(--display);font-size:15px;font-weight:600;color:var(--white)}
  .fwi .fv{font-size:12px;color:var(--soft);margin-top:6px;line-height:1.5}
  .disclose h2{font-size:22px;margin-bottom:12px}
  .disclose p{font-size:13.5px;color:var(--soft);line-height:1.7;margin-bottom:12px}
  .disclose .muted{font-family:var(--mono);font-size:11px;color:var(--faint)}
  @media (max-width:1080px){ .bars,.split,.fw{grid-template-columns:1fr} }
</style>
