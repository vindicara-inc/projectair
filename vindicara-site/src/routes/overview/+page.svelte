<script>
  import { goto } from '$app/navigation';
  import AppShell from '$components/AppShell.svelte';
</script>
<svelte:head><title>Project AIR · Overview</title></svelte:head>

<AppShell active="overview" title="overview">
  <div class="grid">
    <div class="reveal">
      <div class="eyebrow">There are no autonomous agents. Only delegated liability.</div>
      <h1>The immutable record of delegated authority.</h1>
      <p class="lead">Every action an agent takes is bound to the human who authorized it, signed in-process, and anchored to a public log. Agents act. Humans answer. Project AIR proves who.</p>
      <div class="mep"><b>Monitor.</b> <i>·</i> <b>Enforce.</b> <i>·</i> <b>Prove.</b></div>
      <div class="cta">
        <button class="btn" onclick={() => goto('/contact')}>Become a design partner</button>
        <button class="btn ghost" onclick={() => goto('/platform')}>See how it works</button>
      </div>
      <div class="proofs">
        <div><div class="k">DETECTION</div><div class="v">16 detectors · OWASP Agentic</div></div>
        <div><div class="k">SIGNATURE</div><div class="v">Ed25519 + ML-DSA-65</div></div>
        <div><div class="k">ANCHOR</div><div class="v">Public Sigstore Rekor</div></div>
      </div>
    </div>
    <div class="chain reveal" style="animation-delay:.08s">
      <div class="ct"><span>signed chain</span><span>agdr v0.6</span></div>
      <div style="margin-top:14px">
        <div class="node k"><div class="rod"><div class="bd"></div><div class="ln"></div></div><div><div class="nt">Delegation</div><div class="nv2">dr.okafor authorized claims-bot</div><div class="nh">passkey · FIDO2 · scope: hipaa-claims-v3</div></div></div>
        <div class="node"><div class="rod"><div class="bd"></div><div class="ln"></div></div><div><div class="nt">Action</div><div class="nv2">claims.adjudicate · ehr.read</div><div class="nh">within declared scope</div></div></div>
        <div class="node"><div class="rod"><div class="bd"></div><div class="ln"></div></div><div><div class="nt">Signed</div><div class="nv2">BLAKE3 + Ed25519 in-process</div><div class="nh">b3:9f4c…a7 · ml-dsa-65</div></div></div>
        <div class="node"><div class="rod"><div class="bd"></div></div><div><div class="nt">Anchored</div><div class="nv2">Sigstore Rekor</div><div class="nh">log index 1466351923</div></div></div>
      </div>
      <div class="sealrow">
        <div class="seal"><span class="sk">FRE<br>902</span></div>
        <div class="st"><b>Self-authenticating.</b><br>Court-supportable under FRE 902(13). Verify the chain yourself on search.sigstore.dev with zero Vindicara infrastructure in the path.</div>
      </div>
    </div>
  </div>
</AppShell>

<style>
  .grid{display:grid;grid-template-columns:1.18fr .82fr;gap:46px;height:100%;align-items:center}
  h1{font-size:48px;max-width:12ch;margin:16px 0 0}
  .lead{font-size:16px;max-width:46ch;margin-top:20px}
  .mep{display:flex;gap:10px;margin-top:22px;align-items:center;font-family:var(--display);font-style:italic;font-size:18px}
  .mep b{font-style:normal;font-weight:600;color:var(--air2)} .mep i{color:var(--line);font-style:normal}
  .cta{display:flex;gap:12px;margin-top:26px;flex-wrap:wrap}
  .proofs{display:flex;margin-top:34px;border-top:1px solid var(--line)}
  .proofs div{flex:1;padding:16px 18px 0;border-right:1px solid var(--line2)} .proofs div:last-child{border-right:0}
  .proofs .k{font-family:var(--mono);font-size:10px;color:var(--faint)} .proofs .v{font-size:13px;font-weight:600;margin-top:5px;color:var(--soft)}
  .chain{background:var(--panel);border:1px solid var(--line);box-shadow:var(--shadow);padding:24px;position:relative;overflow:hidden}
  .chain::after{content:'';position:absolute;inset:0;background-image:linear-gradient(var(--line2) 1px,transparent 1px),linear-gradient(90deg,var(--line2) 1px,transparent 1px);background-size:26px 26px;opacity:.5;pointer-events:none}
  .ct{font-family:var(--mono);font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--faint);display:flex;justify-content:space-between;position:relative;z-index:1}
  .node{position:relative;z-index:1;display:flex;gap:13px;align-items:flex-start;padding:12px 0}
  .node .rod{display:flex;flex-direction:column;align-items:center}
  .node .bd{width:13px;height:13px;border:2px solid var(--soft);border-radius:50%;background:var(--panel)}
  .node.k .bd{border-color:var(--air);background:var(--air);box-shadow:0 0 10px var(--air)}
  .node .ln{width:2px;flex:1;background:var(--line);min-height:13px} .node:last-child .ln{display:none}
  .node .nt{font-family:var(--mono);font-size:9.5px;letter-spacing:.1em;color:var(--faint);text-transform:uppercase}
  .node .nv2{font-size:13px;font-weight:600;margin-top:2px} .node .nh{font-family:var(--mono);font-size:10px;color:var(--air2);margin-top:2px;word-break:break-all}
  .sealrow{position:relative;z-index:1;display:flex;align-items:center;gap:14px;margin-top:6px;padding-top:16px;border-top:1px solid var(--line)}
  .sealrow .st{font-family:var(--mono);font-size:10px;color:var(--soft);line-height:1.6} .sealrow .st b{color:var(--air2)}
  @media (max-width:1080px){ .grid{grid-template-columns:1fr;gap:24px} }
</style>
