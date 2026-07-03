<script>
  import AppShell from '$components/AppShell.svelte';
  const record = [
    { k: 'record', v: 'signed capsule' },
    { k: 'model', v: 'axiisium-fusion' },
    { k: 'inputs', v: 'blake3:9f3a…c1d7' },
    { k: 'decided-by', v: 'named clinician' },
    { k: 'signature', v: 'valid' },
    { k: 'anchored', v: 'public log' }
  ];
</script>

<svelte:head>
  <title>Axiisium · Two products | Vindicara</title>
  <meta name="description" content="Axiisium Enrich ranks who to sequence for pharma trials. Axiisium Decide gives hematologists a signed, evolving multimodal assessment. One engine, two standards of reliability." />
</svelte:head>

<AppShell active="axiisium" title="axiisium products" scroll={true}>
  <div class="prose">
    <div class="eyebrow"><a class="crumb" href="/axiisium">Axiisium</a> · Products</div>
    <h1>Two products, one engine</h1>
    <p class="big">The same fusion engine, packaged for two buyers and held to two different standards of reliability. One is reliable by architecture. One is reliable by accountability.</p>

    <!-- ENRICH -->
    <div class="prod">
      <div class="phead">
        <div>
          <div class="pk">For pharma</div>
          <h2>Axiisium Enrich</h2>
        </div>
        <span class="badge live">Research-use today</span>
      </div>
      <p class="plead">Rank which trial candidates to sequence first for a molecular profile, so a sponsor fills an NPM1-defined cohort with fewer assays and a signed record of every selection.</p>
      <div class="grid3">
        <div class="g"><div class="gh">In</div><div class="gd">Morphology, flow, and clinical data already collected on candidates.</div></div>
        <div class="g"><div class="gh">Out</div><div class="gd">A calibrated, ranked sequence-first list with a signed selection record per patient.</div></div>
        <div class="g"><div class="gh">Why it is safe</div><div class="gd">It ranks, it never decides. Sequencing always confirms enrollment, so the output cannot fail in a way that reaches a patient.</div></div>
      </div>
      <div class="note">Reliable by architecture: a tunable recall floor bounds what it can miss, and confirmatory sequencing sits upstream of every decision. No diagnosis, no replacement for sequencing.</div>
    </div>

    <!-- DECIDE -->
    <div class="prod">
      <div class="phead">
        <div>
          <div class="pk">For the clinic</div>
          <h2>Axiisium Decide</h2>
        </div>
        <span class="badge dev">On a De Novo device pathway</span>
      </div>
      <p class="plead">A single signed assessment that evolves from day zero to final molecular: a provisional read while sequencing runs, an ELN-2022 risk class once genetics land, and a therapy-eligibility map, every claim tied to the signal that triggered it.</p>

      <div class="splitc">
        <div class="left">
          <div class="g"><div class="gh">Day zero</div><div class="gd">Automated differential, blast percentage, NPM1 and core-binding-factor flags while molecular pends.</div></div>
          <div class="g"><div class="gh">When genetics land</div><div class="gd">ELN-2022 risk class with measurable residual disease as a co-input and a confidence band.</div></div>
          <div class="g"><div class="gh">Therapy map</div><div class="gd">On-label vs investigational flags, each bound to its triggering signal. FLT3 and the hard calls are deferred to molecular and the clinician.</div></div>
        </div>
        <div class="rcard">
          <div class="rc-h"><span class="dot"></span> Signed decision record</div>
          <div class="rc-pwr">Powered by Project <span class="air">AIR</span></div>
          {#each record as kv}
            <div class="kv"><span class="k">{kv.k}</span><span class="v">{kv.v}</span></div>
          {/each}
          <div class="seal"><span class="ck">✓</span> Tamper-evident, attributable, independently verifiable.</div>
        </div>
      </div>
      <div class="note">Reliable by accountability: every output shows its evidence and confidence, defers what it cannot prove, and never diagnoses autonomously. A hematopathologist retains the read.</div>
    </div>

    <div class="card callout">
      <h3>Run AML trials, or treat AML patients?</h3>
      <p>Enrich is ready for pharma design partners now. Decide is in active development with clinical partners. If either is your world, we want to build it with you.</p>
      <div class="ctas">
        <a class="btn" href="/design-partner">Become a design partner</a>
        <a class="btn ghost" href="/axiisium/science">How it works</a>
      </div>
    </div>
  </div>
</AppShell>

<style>
  .prose h1{font-size:40px;margin:10px 0 0}
  .big{font-size:18px;color:var(--white);line-height:1.6;margin:14px 0 18px;font-family:var(--display)}
  .prose a{color:var(--ax2)}
  .crumb{font-weight:600}
  .prod{border:1px solid var(--line);background:var(--navy1);padding:20px 22px;margin:14px 0}
  .phead{display:flex;align-items:flex-start;justify-content:space-between;gap:14px;flex-wrap:wrap}
  .phead h2{font-size:26px;margin:4px 0 0}
  .pk{font-family:var(--mono);font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--ax2)}
  .badge{font-family:var(--mono);font-size:9.5px;letter-spacing:.08em;text-transform:uppercase;padding:6px 11px;border:1px solid var(--line);white-space:nowrap}
  .badge.live{color:var(--good);border-color:rgba(63,217,155,.4);background:var(--goodbg)}
  .badge.dev{color:var(--ax2);border-color:rgba(244,123,32,.4);background:var(--axbg)}
  .plead{font-size:14.5px;color:var(--soft);line-height:1.6;margin:12px 0 14px}
  .grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px}
  .g{border:1px solid var(--line);background:#0a1326;padding:12px 13px}
  .gh{font-family:var(--mono);font-size:9.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--ax2);margin-bottom:6px}
  .gd{font-size:12px;color:var(--soft);line-height:1.5}
  .note{font-size:12.5px;color:var(--soft);line-height:1.55;margin-top:12px;padding-top:12px;border-top:1px solid var(--line)}
  .splitc{display:grid;grid-template-columns:1fr .82fr;gap:14px;align-items:start}
  .left{display:flex;flex-direction:column;gap:10px}
  .rcard{border:1px solid rgba(244,123,32,.3);background:linear-gradient(180deg,var(--axbg),#0a1326);padding:14px 15px}
  .rc-h{font-family:var(--mono);font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--white);display:flex;align-items:center;gap:8px}
  .rc-h .dot{width:6px;height:6px;border-radius:50%;background:var(--ax);box-shadow:0 0 8px var(--ax)}
  .rc-pwr{font-family:var(--mono);font-size:10px;color:var(--faint);margin:4px 0 10px}
  .kv{display:flex;justify-content:space-between;gap:10px;padding:6px 0;border-bottom:1px solid var(--line2);font-size:11.5px}
  .kv:last-of-type{border-bottom:0}
  .kv .k{font-family:var(--mono);font-size:10px;color:var(--faint);letter-spacing:.04em}
  .kv .v{font-family:var(--mono);font-size:10.5px;color:var(--soft)}
  .seal{display:flex;align-items:center;gap:8px;margin-top:11px;padding:9px 10px;background:var(--goodbg);border:1px solid rgba(63,217,155,.32);font-size:11px;color:var(--good);line-height:1.4}
  .seal .ck{width:18px;height:18px;border-radius:50%;background:var(--good);color:#06210f;display:grid;place-items:center;font-size:11px;font-weight:800;flex:none}
  .callout{padding:18px 20px;margin:24px 0}
  .callout h3{margin-top:0}
  .callout p{font-size:13px;color:var(--soft);line-height:1.55}
  .ctas{display:flex;flex-wrap:wrap;gap:10px;margin-top:14px}
  @media (max-width:1080px){ .grid3{grid-template-columns:1fr} .splitc{grid-template-columns:1fr} }
</style>
