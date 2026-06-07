<script>
  import AppShell from '$components/AppShell.svelte';

  // Deployed contact endpoint (Lambda Function URL). See CONTACT_FORM.md to set it up.
  // While empty, the form falls back to a prefilled mailto so it is never a dead end.
  const CONTACT_ENDPOINT = '';

  let name = $state('');
  let email = $state('');
  let company = $state('');
  let team = $state('Security / DevSecOps');
  let prove = $state('');
  let designPartner = $state(false);
  let website = $state(''); // honeypot: hidden from users, bots fill it

  let status = $state('idle'); // idle | sending | sent | error
  let errorMsg = $state('');

  /** @param {SubmitEvent} e */
  async function submit(e) {
    e.preventDefault();
    if (!name.trim() || !email.includes('@')) {
      errorMsg = 'Please enter your name and a valid work email.';
      status = 'error';
      return;
    }

    const payload = { name, email, company, team, prove, designPartner, website };

    if (!CONTACT_ENDPOINT) {
      const body = `Name: ${name}\nEmail: ${email}\nCompany: ${company}\nTeam: ${team}\nDesign partner: ${designPartner ? 'yes' : 'no'}\n\n${prove}`;
      window.location.href = `mailto:support@vindicara.io?subject=${encodeURIComponent('Project AIR inquiry from ' + name)}&body=${encodeURIComponent(body)}`;
      status = 'sent';
      return;
    }

    status = 'sending';
    errorMsg = '';
    try {
      const res = await fetch(CONTACT_ENDPOINT, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (!res.ok) throw new Error(`Server responded ${res.status}`);
      status = 'sent';
    } catch {
      errorMsg = 'Something went wrong. Please email support@vindicara.io directly.';
      status = 'error';
    }
  }
</script>
<svelte:head><title>Vindicara · Contact</title></svelte:head>

<AppShell active="contact" title="contact" scroll={true}>
  <div class="clay">
    <div>
      <div class="eyebrow">Contact</div>
      <h2>Let's talk.</h2>
      <form class="form" onsubmit={submit}>
        <input class="hp" type="text" tabindex="-1" autocomplete="off" aria-hidden="true" bind:value={website} name="website" placeholder="Leave this field empty">

        <div class="fld"><label for="c-name">Name</label><input id="c-name" type="text" bind:value={name} placeholder="Your name"></div>
        <div class="fld"><label for="c-email">Work email</label><input id="c-email" type="email" bind:value={email} placeholder="you@company.com"></div>
        <div class="fld"><label for="c-company">Company</label><input id="c-company" type="text" bind:value={company} placeholder="Company"></div>
        <div class="fld"><label for="c-team">Your team</label><select id="c-team" bind:value={team}><option>Security / DevSecOps</option><option>Compliance / Risk</option><option>Legal / Insurance</option><option>Engineering</option><option>Founder / Exec</option></select></div>
        <div class="fld full"><label for="c-prove">What are you trying to prove?</label><textarea id="c-prove" bind:value={prove} placeholder="Tell us about your agents and what you need to show an auditor, insurer, or court."></textarea></div>
        <label class="check full"><input type="checkbox" bind:checked={designPartner}><span>We want to be a design partner. We will instrument a real agent workload during the program.</span></label>
        {#if status === 'sent'}<div class="ok full">Thank you. We will reply from support@vindicara.io.</div>{/if}
        {#if status === 'error'}<div class="err full">{errorMsg}</div>{/if}
        <div class="formfoot full">
          <button class="btn" type="submit" disabled={status === 'sending'}>{status === 'sending' ? 'Sending...' : 'Send message'}</button>
          <span class="mono note">or email <a href="mailto:support@vindicara.io">support@vindicara.io</a></span>
        </div>
      </form>
    </div>
    <div class="cside">
      <div class="partner">
        <div class="pt">Become a design partner</div>
        <p>We are taking a small number of design partners ahead of general availability. You get direct access to the founder, white-glove instrumentation, and influence over the roadmap. We get a real workload to prove against.</p>
      </div>
      <div class="cways">
        <div class="cway"><span class="cl">General</span><a href="mailto:support@vindicara.io">support@vindicara.io</a></div>
        <div class="cway"><span class="cl">Press</span><a href="mailto:press@vindicara.io">press@vindicara.io</a></div>
        <div class="cway"><span class="cl">Source</span><a href="https://github.com/vindicara-inc/projectair" target="_blank" rel="noopener">github.com/vindicara-inc/projectair</a></div>
        <div class="cway"><span class="cl">Install</span><a href="https://pypi.org/project/projectair/" target="_blank" rel="noopener">pip install projectair · Python 3.12+</a></div>
      </div>
    </div>
  </div>
</AppShell>

<style>
  .clay{display:grid;grid-template-columns:1fr 1fr;gap:40px;align-items:start;max-width:1000px}
  h2{font-size:30px;margin-bottom:16px}
  .form{display:grid;grid-template-columns:1fr 1fr;gap:14px}
  .fld{display:flex;flex-direction:column;gap:6px} .fld.full,.full{grid-column:1/-1}
  .fld label{font-family:var(--mono);font-size:9.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--faint)}
  .fld input,.fld select,.fld textarea{font-family:var(--ui);font-size:13.5px;padding:10px 12px;border:1px solid var(--line);background:var(--navy1);color:var(--white);outline:none}
  .fld input:focus,.fld select:focus,.fld textarea:focus{border-color:var(--air)}
  .fld textarea{resize:none;height:74px}
  .check{display:flex;gap:10px;align-items:flex-start;font-size:12px;color:var(--soft);line-height:1.4} .check input{margin-top:2px}
  .ok{background:var(--goodbg);border:1px solid rgba(63,217,155,.3);color:var(--good);padding:12px 14px;font-size:12.5px}
  .err{background:var(--airbg);border:1px solid rgba(230,57,70,.3);color:var(--air2);padding:12px 14px;font-size:12.5px}
  .btn:disabled{opacity:.6;cursor:default}
  .hp{position:absolute;left:-9999px;width:1px;height:1px;opacity:0;pointer-events:none}
  .formfoot{display:flex;align-items:center;gap:16px;margin-top:4px}
  .note{font-size:11px;color:var(--faint)} .note a{color:var(--air2);text-decoration:none}
  .partner{background:var(--airbg);border:1px solid rgba(230,57,70,.28);padding:18px 20px}
  .partner .pt{font-family:var(--display);font-size:17px;font-weight:600} .partner p{font-size:12.5px;color:var(--soft);margin-top:6px;line-height:1.5}
  .cways{margin-top:18px;border-top:1px solid var(--line)}
  .cway{display:flex;justify-content:space-between;align-items:center;padding:14px 0;border-bottom:1px solid var(--line2)}
  .cway .cl{font-family:var(--mono);font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--faint)}
  .cway a{color:var(--air2);text-decoration:none;font-size:13px;font-weight:600} .cway a:hover{text-decoration:underline}
  @media (max-width:1080px){ .clay{grid-template-columns:1fr;gap:24px} }
</style>
