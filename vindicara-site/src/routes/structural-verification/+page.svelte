<script>
  import AppShell from '$components/AppShell.svelte';
</script>
<svelte:head><title>Vindicara · Structural Verification</title></svelte:head>

<AppShell active="structural-verification" title="structural verification" scroll={true}>
  <div class="wrap">
    <div class="head">
      <div class="eyebrow">Structural Verification</div>
      <h1>They check messages. <span class="grad">We check missions.</span></h1>
      <p class="lede">Intent Capsules are the signed promise. Structural Verification is the proof the promise was kept. A deterministic symbolic floor that cannot be prompt-injected.</p>
    </div>

    <div class="grid">
      <div class="left">
        <div class="panel">
          <div class="ph">The problem</div>
          <p>Per-call guardrails check individual messages. Content classifiers check individual outputs. But nobody checks whether the <i>trajectory</i> of an entire agent session served its declared intent. Reading <code>~/.ssh/id_rsa</code> is not inherently malicious. Posting to an external URL is not inherently malicious. Doing both in a "refactor the auth module" session is exfiltration.</p>
        </div>
        <div class="panel">
          <div class="ph">The solution</div>
          <p>Five deterministic checks over the causal graph: <b>SV-SECRET</b> (undeclared secret access), <b>SV-NET</b> (undeclared network egress), <b>SV-SCOPE</b> (filesystem scope violations), <b>SV-ENTITY</b> (unauthorized entity access), <b>SV-EXFIL</b> (causal exfiltration path). The symbolic floor is the guarantee. No LLM in the verification path.</p>
        </div>
      </div>

      <div class="term">
        <div class="bar"><span class="d r"></span><span class="d y"></span><span class="d g"></span><span class="tt">AIR VERIFY-INTENT</span></div>
        <div class="body">
          <div class="cmd">$ air verify-intent chain.jsonl</div>
          <div class="ln">Intent: "Refactor the auth module"</div>
          <div class="ln">Source: INTENT_DECLARATION</div>
          <div class="ln dim">Checking 14 steps...</div>
          <div class="ln f">SV-SECRET step 5: ~/.ssh/id_rsa</div>
          <div class="ln f sub">secret_access not declared</div>
          <div class="ln f">SV-NET step 7: POST attacker.com</div>
          <div class="ln f sub">not in allowed_network</div>
          <div class="ln f">SV-EXFIL #5 → #7: causal path</div>
          <div class="ln f sub">secret read → network egress</div>
          <div class="ln fail">FAILED BY AIR (2 critical, 1 high)</div>
        </div>
      </div>
    </div>

  </div>
</AppShell>

<style>
  .head{text-align:center;max-width:760px;margin:8px auto 0}
  .head h1{font-size:34px;margin:12px 0 0}
  .grad{color:var(--air2)}
  .lede{font-size:15px;color:var(--soft);line-height:1.6;margin:14px auto 0;max-width:60ch}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin:26px 0 0;align-items:stretch}
  .left{display:grid;gap:16px}
  .panel{border:1px solid var(--line);border-left:2px solid var(--air);background:var(--panel);box-shadow:var(--shadow);padding:16px 18px}
  .ph{font-family:var(--mono);font-size:10px;letter-spacing:.16em;text-transform:uppercase;color:var(--air2);margin-bottom:8px}
  .panel p{font-size:13px;color:#CBD5E8;line-height:1.6}
  .panel code{font-family:var(--mono);font-size:12px;color:var(--white);background:rgba(255,255,255,.06);padding:1px 5px}
  .panel b{color:var(--white)}
  .term{border:1px solid var(--line);background:#0a0e16;font-family:var(--mono);font-size:12.5px;display:flex;flex-direction:column}
  .bar{display:flex;align-items:center;gap:7px;padding:9px 12px;border-bottom:1px solid var(--line);background:#10141f}
  .d{width:10px;height:10px;border-radius:50%} .d.r{background:#ff5f57} .d.y{background:#febc2e} .d.g{background:#28c840}
  .tt{margin-left:8px;font-size:10px;letter-spacing:.14em;color:var(--faint)}
  .body{padding:14px 16px;display:grid;gap:5px;flex:1}
  .cmd{color:var(--white)} .ln{color:var(--soft)} .ln.dim{color:var(--faint)}
  .ln.f{color:var(--air2)} .ln.sub{padding-left:14px;color:#ff8f97} .ln.fail{color:#ff5763;font-weight:700;margin-top:6px}
  @media (max-width:1080px){ .grid{grid-template-columns:1fr} }
</style>
