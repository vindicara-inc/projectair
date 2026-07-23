<script>
  // @ts-nocheck
  import { goto } from '$app/navigation';
  // FlightDeck findings inbox — ported from design-mockups/air-flightdeck-inbox.html.
  // Only the main content area is reproduced here; the app layout supplies the
  // page shell, top nav, and left rail.

  const FINDINGS = [
    {
      ty: '⛓', nm: 'Prompt injection in tool result', tag: 'AIR-01',
      loc: 'session 7f3a · step 47', sev: 'c', blast: '3 steps', score: 91,
      lab: 'Critical', cat: '⛓ AIR-01 · Live capture',
      tldr: 'An untrusted tool result fed into the agent\'s next reasoning step contained an instruction-style payload ("ignore previous instructions and..."). The agent treated injected text as a directive. Left uncontained, this is the entry point for goal hijack and tool misuse.'
    },
    {
      ty: '◎', nm: 'Agent invoked tool outside declared scope', tag: 'ASI10',
      loc: 'billing-agent', sev: 'h', blast: '1 agent', score: 88,
      lab: 'High', cat: '◎ ASI10 · Rogue agent',
      tldr: 'billing-agent called a tool that is not in its declared BehavioralScope. This is Zero-Trust scope enforcement: the agent acted outside the authorization you declared for it.'
    },
    {
      ty: '⌖', nm: 'SSH key read after poisoned README', tag: 'ASI01',
      loc: 'session 7f3a · step 52', sev: 'c', blast: '4 steps', score: 94,
      lab: 'Critical', cat: '⌖ ASI01 · Goal hijack',
      tldr: 'A poisoned README instruction redirected the agent\'s goal toward reading a private SSH key. The causal graph links the poisoned input directly to the credential read.'
    },
    {
      ty: '❖', nm: 'Memory / context poisoning detected', tag: 'ASI06',
      loc: 'session a19c · step 12', sev: 'm', blast: '2 steps', score: 62,
      lab: 'Medium', cat: '❖ ASI06 · Memory poisoning',
      tldr: 'A context-memory entry was mutated between write and read. Downstream reasoning consumed the poisoned entry as trusted state.'
    },
    {
      ty: '⛁', nm: 'Sensitive data in model output', tag: 'AIR-02',
      loc: 'session 7f3a · step 49', sev: 'm', blast: '1 step', score: 58,
      lab: 'Medium', cat: '⛁ AIR-02 · Data disclosure',
      tldr: 'The model output contained a value matching a secret pattern. Disclosure risk if this output is logged, returned to a user, or passed to another agent.'
    },
    {
      ty: '⇄', nm: 'Unverified inter-agent message', tag: 'ASI07',
      loc: 'handoff A → B', sev: 'm', blast: '2 agents', score: 55,
      lab: 'Medium', cat: '⇄ ASI07 · Insecure handoff',
      tldr: 'Agent B accepted a delegated task from Agent A without an issuer-signed capability token. The cross-agent chain of custody cannot be cryptographically proven.'
    },
    {
      ty: '⚿', nm: 'Chain gap: missing tool_end record', tag: 'AIR-04',
      loc: 'session b204 · step 8', sev: 'l', blast: '1 step', score: 31,
      lab: 'Low', cat: '⚿ AIR-04 · Untraceable action',
      tldr: 'A tool_start has no matching tool_end. There is a silent interval in the forensic chain where an action completed without being recorded.'
    }
  ];

  // Extra rows shown only in "All findings" (the dupes the causal engine collapses).
  const NOISE = [
    {
      ty: '⛁', nm: 'Sensitive data in model output (dup)', tag: 'AIR-02',
      loc: 'session 7f3a · step 49', sev: 'l', blast: '—', score: 40,
      lab: 'Low', cat: '⛁ AIR-02',
      tldr: 'Duplicate of the step-49 disclosure; collapsed into its root cause under AIR refined.'
    }
  ];

  const TIERS = { free: 0, pro: 1, team: 2 };
  const SEV_VAR = { c: 'crit', h: 'high', m: 'med', l: 'low' };
  const SEV_LABEL = { c: 'Critical', h: 'High', m: 'Medium', l: 'Low' };

  let tier = $state('free');
  let refined = $state(false);
  let tipShown = $state(false);
  let slideOpen = $state(false);
  let current = $state(0);
  let activeTab = $state('overview');
  let typeFilter = $state('all');
  let typeOpen = $state(false);
  let actionsOpen = $state(false);
  let profileOpen = $state(false);

  // Modals
  let wallOpen = $state(false);
  let wallKind = $state('plan');
  let instrOpen = $state(false);

  // Gated action button states (keyed by intent).
  let gatedDone = $state({ pro: false, team: false });

  const rows = $derived(
    (refined ? FINDINGS : [...FINDINGS, ...NOISE]).filter((r) => typeFilter === 'all' || r.sev === typeFilter)
  );
  const tierLvl = $derived(TIERS[tier]);
  const finding = $derived(rows[current] ?? rows[0]);

  // Hosted-actions meter swaps with the preview tier.
  const meter = $derived(
    tier === 'pro'
      ? { used: '3.1k', cap: '25k', width: 12, fill: 'linear-gradient(90deg,var(--c-air),var(--c-air2))' }
      : tier === 'team'
        ? { used: '41k', cap: '250k', width: 16, fill: 'linear-gradient(90deg,var(--c-ok),var(--c-cyan))' }
        : { used: '94', cap: '100', width: 94, fill: 'linear-gradient(90deg,var(--c-high),var(--c-crit))' }
  );

  const gaugeDash = 195;
  const gaugeOffset = $derived(gaugeDash - (gaugeDash * finding.score) / 100);

  function setRefined(v) {
    refined = v;
  }

  function selType(v) {
    typeFilter = v;
    typeOpen = false;
  }

  function actMenu(need) {
    actionsOpen = false;
    if (tierLvl >= TIERS[need]) return;
    openWall('plan');
  }

  function nav(p) {
    profileOpen = false;
    goto(p);
  }

  function openRow(i) {
    current = i;
    slideOpen = true;
  }

  function closeSlide() {
    slideOpen = false;
  }

  function openWall(kind) {
    wallKind = kind;
    wallOpen = true;
  }

  const wallCopy = $derived(
    wallKind === 'pro'
      ? {
          title: 'Anchoring is a paid feature',
          body: 'Permanently anchor this finding to public Sigstore Rekor on Pro and above. Free is a 7-day, unanchored viewer.'
        }
      : wallKind === 'team'
        ? {
            title: 'Engage containment is a Team feature',
            body: 'Auto-apply containment with fail-closed enforcement and dual-control on Team. Free copies the rule for you to apply yourself.'
          }
        : {
            title: 'This feature is available on all paid plans',
            body: 'Upgrade now to keep anchoring, retaining, and containing findings beyond the Free viewer.'
          }
  );

  function gatedClick(need) {
    if (tierLvl >= TIERS[need]) {
      gatedDone = { ...gatedDone, [need]: true };
      return;
    }
    openWall(need);
  }

  function selectTier(t) {
    tier = t;
    gatedDone = { pro: false, team: false };
  }
</script>

<div class="inbox-screen">
<div class="inbox">
  <!-- TOPBAR -->
  <div class="topbar">
    <div class="hello">Hello, <b>get-sltr!</b></div>
    <div class="grow"></div>
    <div class="tierbox">
      <span class="cap">Preview tier</span>
      <div class="seg">
        <button class:on={tier === 'free'} onclick={() => selectTier('free')}>Free</button>
        <button class:on={tier === 'pro'} onclick={() => selectTier('pro')}>Pro</button>
        <button class:on={tier === 'team'} onclick={() => selectTier('team')}>Team</button>
      </div>
    </div>
    <div class="meter">
      <div class="lab"><span>Hosted actions</span><span><b>{meter.used}</b>/{meter.cap}</span></div>
      <div class="bar"><div class="fill" style="width:{meter.width}%;background:{meter.fill}"></div></div>
    </div>
    <button class="upg" onclick={() => openWall('plan')}>Upgrade</button>
    <div class="sel" style="position:relative">
      <button class="av" aria-label="Account menu" onclick={() => { profileOpen = !profileOpen; typeOpen = false; actionsOpen = false; }}>G</button>
      {#if profileOpen}
        <div class="menu profile-menu">
          <div class="pm-head"><b>Get-sltr!</b><span>get-sltr@example.com</span></div>
          <div class="pm-sep"></div>
          <button onclick={() => nav('/flightdeck/settings')}>Profile</button>
          <button onclick={() => nav('/flightdeck/settings')}>Account settings</button>
          <div class="pm-sep"></div>
          <div class="pm-lbl">Console</div>
          <button onclick={() => nav('/flightdeck')}>Overview</button>
          <button onclick={() => nav('/flightdeck/rules')}>Agents</button>
          <button onclick={() => nav('/flightdeck/incidents')}>Incidents</button>
          <button onclick={() => nav('/flightdeck/report')}>Forensics</button>
          <button onclick={() => nav('/flightdeck/readiness')}>Compliance</button>
          <div class="pm-sep"></div>
          <button onclick={() => nav('/flightdeck/auth/logout/')}>Sign out</button>
          <button class="danger" onclick={() => nav('/flightdeck/settings')}>Delete account</button>
        </div>
      {/if}
    </div>
  </div>

  <div class="content">
    <!-- HERO: stat tiles -->
    <div class="hero">
      <div class="stats">
        <div class="tile">
          <div class="sevbar">
            <i style="background:var(--c-crit);flex:1.2"></i>
            <i style="background:var(--c-high);flex:3"></i>
            <i style="background:var(--c-med);flex:2.4"></i>
            <i style="background:var(--c-low);flex:1.6"></i>
          </div>
          <div class="big">23</div>
          <div class="top" style="margin:6px 0 0">Open findings</div>
          <div class="legend" style="margin-top:8px">
            <span><i style="background:var(--c-crit)"></i>2 critical</span>
            <span><i style="background:var(--c-high)"></i>11 high</span>
          </div>
        </div>
        <div class="tile alt">
          <div class="top"><span class="dot" style="background:rgba(255,255,255,.08)">◎</span>Auto-filtered</div>
          <div class="big">9</div>
          <div class="sub"><b>causal engine</b> · noise removed</div>
        </div>
        <div class="tile">
          <div class="top"><span class="dot" style="background:rgba(155,140,255,.18);color:var(--c-violet)">＋</span>New</div>
          <div class="big">7</div>
          <div class="sub">in last 7 days</div>
        </div>
        <div class="tile">
          <div class="top"><span class="dot" style="background:rgba(93,202,165,.18);color:var(--c-low)">✓</span>Contained</div>
          <div class="big">1</div>
          <div class="sub">in last 7 days</div>
        </div>
      </div>
    </div>

    <!-- FILTER BAR -->
    <div class="fbar">
      <div class="search">🔍 Search findings</div>
      <div class="toggle" style="position:relative">
        <button class:on={!refined} onclick={() => setRefined(false)}>All findings</button>
        <button
          class:on={refined}
          onclick={() => setRefined(true)}
          onmouseenter={() => (tipShown = true)}
          onmouseleave={() => (tipShown = false)}
        >AIR refined</button>
        <div class="tip" class:show={tipShown}>
          <div class="row">
            <div><div class="h">All findings</div><div class="n">28 <small>100%</small></div></div>
            <div style="text-align:right"><div class="h">AIR refined</div><div class="n">23 <small>−18%</small></div></div>
          </div>
          <div class="viz"></div>
          <div class="captxt">AIR's causal engine collapsed 5 duplicate / non-load-bearing findings into their root cause.</div>
        </div>
      </div>
      <div class="sel">
        <button class="chip" onclick={() => { typeOpen = !typeOpen; actionsOpen = false; }}>{typeFilter === 'all' ? 'All types' : SEV_LABEL[typeFilter]} ▾</button>
        {#if typeOpen}
          <div class="menu">
            <button onclick={() => selType('all')}>All types</button>
            <button onclick={() => selType('c')}>Critical</button>
            <button onclick={() => selType('h')}>High</button>
            <button onclick={() => selType('m')}>Medium</button>
            <button onclick={() => selType('l')}>Low</button>
          </div>
        {/if}
      </div>
      <div class="chip act">⚑ Filtered to <b>recently discovered</b></div>
      <div class="sel" style="margin-left:auto">
        <button class="chip" onclick={() => { actionsOpen = !actionsOpen; typeOpen = false; }}>Actions ▾</button>
        {#if actionsOpen}
          <div class="menu" style="right:0;left:auto">
            <button onclick={() => actMenu('pro')}>{tierLvl >= TIERS.pro ? '' : '🔒 '}Export findings</button>
            <button onclick={() => actMenu('pro')}>{tierLvl >= TIERS.pro ? '' : '🔒 '}Anchor all findings</button>
            <button onclick={() => actMenu('team')}>{tierLvl >= TIERS.team ? '' : '🔒 '}Engage containment</button>
          </div>
        {/if}
      </div>
    </div>

    <!-- TABLE -->
    <table>
      <thead>
        <tr><th class="ty">Type</th><th>Name</th><th>Severity</th><th>Blast radius</th><th></th></tr>
      </thead>
      <tbody>
        {#each rows as f, i}
          <tr class:sel={slideOpen && current === i} onclick={() => openRow(i)}>
            <td class="ty"><div class="tyic">{f.ty}</div></td>
            <td>
              <div class="nm">{f.nm}<span class="tag">{f.tag}</span></div>
              <div class="loc">{f.loc}</div>
            </td>
            <td><span class="sev {f.sev}"><i></i>{f.lab}</span></td>
            <td class="blast">{f.blast}</td>
            <td></td>
          </tr>
        {/each}
      </tbody>
    </table>
    <div class="empty">No more findings to show</div>
  </div>
</div>

<!-- SLIDE-OVER -->
<div class="slide" class:open={slideOpen}>
  <div class="sl-top">
    <button class="iconbtn" onclick={closeSlide}>✕</button>
    <button class="iconbtn">⤢</button>
    <button class="actbtn" onclick={() => (instrOpen = true)}>Actions ▾</button>
  </div>
  <div class="sl-head">
    <div class="gauge">
      <svg width="74" height="74">
        <circle cx="37" cy="37" r="31" stroke="rgba(255,255,255,.08)" stroke-width="6" fill="none" />
        <circle
          cx="37" cy="37" r="31"
          stroke="var(--c-{SEV_VAR[finding.sev]})"
          stroke-width="6" fill="none" stroke-linecap="round"
          stroke-dasharray={gaugeDash} stroke-dashoffset={gaugeOffset}
        />
      </svg>
      <div class="val"><b>{finding.score}</b><small>{finding.lab}</small></div>
    </div>
    <div class="sl-title">
      <h3>{finding.nm}</h3>
      <div class="det">We found 1 issue · last detected 6 hours ago</div>
      <div><span class="badge new">● New</span><span class="badge cat">{finding.cat}</span></div>
    </div>
  </div>
  <div class="tabs">
    <button class:on={activeTab === 'overview'} onclick={() => (activeTab = 'overview')}>Overview</button>
    <button class:on={activeTab === 'activity'} onclick={() => (tierLvl >= TIERS.team ? (activeTab = 'activity') : openWall('plan'))}>Activity {#if tierLvl < 2}<span class="lk">🔒 Team</span>{/if}</button>
    <button class:on={activeTab === 'tasks'} onclick={() => (tierLvl >= TIERS.pro ? (activeTab = 'tasks') : openWall('plan'))}>Tasks {#if tierLvl < 1}<span class="lk">🔒 Pro</span>{/if}</button>
  </div>
  <div class="sl-body">
    <div class="sec">
      <h4>TL;DR</h4>
      <p>{finding.tldr}</p>
    </div>
    <div class="sec">
      <div class="hd"><h4>How do I contain it?</h4><button class="ghostbtn lk" onclick={() => (tierLvl >= TIERS.pro ? (instrOpen = true) : openWall('plan'))}>{#if tierLvl >= TIERS.pro}⧉ Agent instructions{:else}🔒 Agent instructions <span class="mono" style="font-size:9px">Pro</span>{/if}</button></div>
      <p style="margin-bottom:14px">Add a containment rule so this pattern is blocked (or stepped-up to a human) before it reaches a tool call. AIR generates the ready snippet for your stack.</p>
      <div class="gactions">
        <button class="ghostbtn lk" onclick={() => (tierLvl >= TIERS.pro ? (instrOpen = true) : openWall('plan'))}>{#if tierLvl >= TIERS.pro}⧉ Copy containment rule{:else}🔒 Copy containment rule <span class="mono" style="font-size:9px">Pro</span>{/if}</button>
        <button class="ghostbtn lk" class:done={gatedDone.pro} onclick={() => gatedClick('pro')}>
          {#if gatedDone.pro}✓ Anchored{:else}🔒 Anchor finding <span class="mono" style="font-size:9px">Pro</span>{/if}
        </button>
        <button class="ghostbtn lk" class:done={gatedDone.team} onclick={() => gatedClick('team')}>
          {#if gatedDone.team}✓ Containment engaged{:else}🔒 Engage containment <span class="mono" style="font-size:9px">Team</span>{/if}
        </button>
      </div>
    </div>
    <div class="sec">
      <h4>Affected steps <span class="mono" style="color:var(--c-faint)">· causal chain</span></h4>
      <div class="steps">
        <div class="sh">SESSION 7f3a · LOAD-BEARING RECORDS</div>
        <div class="it on">step 47 · tool_result <span class="mini">injection origin</span></div>
        <div class="it">step 48 · llm_call <span class="mini">absorbed</span></div>
        <div class="it">step 49 · tool_start(shell) <span class="mini">blast</span></div>
      </div>
    </div>
  </div>
</div>

<!-- UPGRADE WALL -->
{#if wallOpen}
  <div
    class="scrim show"
    role="presentation"
    onclick={(e) => { if (e.target === e.currentTarget) wallOpen = false; }}
  >
    <div class="modal">
      <div class="k">Upgrade to a paid plan</div>
      <h2>{wallCopy.title}</h2>
      <p>{wallCopy.body} View <a href="/pricing">pricing details</a>.</p>
      <div class="btns">
        <button class="btn-primary" onclick={() => { wallOpen = false; goto('/pricing'); }}>Upgrade Now</button>
        <button class="btn-ghost" onclick={() => (wallOpen = false)}>Talk To A Human</button>
      </div>
    </div>
  </div>
{/if}

<!-- AGENT INSTRUCTIONS -->
{#if instrOpen}
  <div
    class="scrim show"
    role="presentation"
    onclick={(e) => { if (e.target === e.currentTarget) instrOpen = false; }}
  >
    <div class="modal" style="width:560px">
      <div class="k">Agent instructions</div>
      <h2 style="font-size:18px;margin-bottom:14px">Contain: Prompt injection in tool result</h2>
      <div class="codebox"><span class="c"># AIR detected a prompt-injection in a tool result feeding session 7f3a (step 47).</span>
<span class="c"># Detector: AIR-01 · Severity: Critical · Blast radius: 3 steps</span>

<span class="kw">from</span> airsdk.containment <span class="kw">import</span> ContainmentPolicy

policy = ContainmentPolicy(
    deny_arg_patterns=[<span class="s">r"ignore (all )?previous instructions"</span>],
    block_on_findings=[<span class="s">"AIR-01"</span>],
    step_up_for_actions=[<span class="s">"shell"</span>, <span class="s">"http"</span>],
)
<span class="c"># Wire into your recorder: AIRRecorder(..., containment=policy)</span></div>
      <div class="btns">
        <button class="btn-primary" onclick={() => (instrOpen = false)}>⧉ Copy instructions</button>
        <button class="btn-ghost" onclick={() => (instrOpen = false)}>Close</button>
      </div>
      <div class="note" style="margin-top:14px">Free copies the rule. <span style="color:var(--c-warn)">Engage containment</span> (auto-apply + fail-closed) is Team.</div>
    </div>
  </div>
{/if}
</div>

<style>
  .inbox-screen {
    /* Palette lifted from the mockup so the olive/light-gray two-tone is faithful.
       Defined on the screen root (not just .inbox) so the fixed-position
       slide-over and modal overlays inherit the same vars. */
    --c-bg: #0b1020; --c-panel: #141c34; --c-panel2: #1a2440; --c-slide: #0b1020;
    --c-ink: #fff; --c-muted: rgba(255,255,255,.88); --c-faint: rgba(255,255,255,.72);
    --c-glass: rgba(255,255,255,.07); --c-glass2: rgba(255,255,255,.05); --c-glass-brd: rgba(255,255,255,.16);
    --c-air: #e63946; --c-air2: #ff5d68; --c-cyan: #67e8f9; --c-ok: #5dcaa5;
    --c-warn: #ffb454; --c-violet: #9b8cff;
    --c-hair: rgba(255,255,255,.08); --c-stroke: rgba(255,255,255,.14);
    --c-mono: ui-monospace, Menlo, Consolas, monospace;
    --c-sans: 'Inter', system-ui, sans-serif;
    --c-crit: #ff5d68; --c-high: #ffb454; --c-med: #6aa8ff; --c-low: #5dcaa5;
    color: var(--c-ink); font-family: var(--c-sans); font-size: 14px;
  }
  .inbox-screen * { box-sizing: border-box; }
  .inbox-screen button { font-family: inherit; cursor: pointer; }

  /* TOPBAR */
  .topbar { display: flex; align-items: center; gap: 16px; padding: 4px clamp(20px,4vw,44px); }
  .hello { font-size: 20px; font-weight: 600; }
  .hello b { color: #fff; }
  .grow { flex: 1; }
  .tierbox { display: flex; align-items: center; gap: 8px; }
  .tierbox .cap { font-family: var(--c-mono); font-size: 9px; letter-spacing: .12em; text-transform: uppercase; color: var(--c-faint); }
  .seg { display: flex; background: var(--c-panel2); border: 1px solid var(--c-hair); border-radius: 16px 8px 8px 16px; padding: 3px; }
  .seg button { background: transparent; border: 0; color: var(--c-muted); font-family: var(--c-mono); font-size: 10px; letter-spacing: .08em; text-transform: uppercase; padding: 6px 12px; border-radius: 6px; }
  .seg button.on { background: var(--c-air); color: #fff; box-shadow: 0 0 14px rgba(230,57,70,.5); }
  .meter { min-width: 210px; }
  .meter .lab { display: flex; justify-content: space-between; font-family: var(--c-mono); font-size: 9px; letter-spacing: .08em; text-transform: uppercase; color: var(--c-faint); margin-bottom: 5px; }
  .meter .lab b { color: var(--c-ink); }
  .meter .bar { height: 6px; border-radius: 8px 3px 3px 8px; background: rgba(255,255,255,.08); overflow: hidden; }
  .meter .fill { height: 100%; background: linear-gradient(90deg, var(--c-air), var(--c-air2)); }
  .upg { background: var(--c-air); color: #fff; border: 0; border-radius: 16px 8px 8px 16px; padding: 8px 14px; font-weight: 600; font-size: 12px; }
  .av { width: 32px; height: 32px; border: 0; border-radius: 50%; background: var(--c-air); color: #fff; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 13px; cursor: pointer; }

  /* CONTENT */
  .content { padding: 14px clamp(20px,4vw,44px) 24px; }
  .hero { display: flex; gap: 14px; align-items: stretch; margin: 8px 0 16px; }
  .stats { flex: 1; display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }

  /* stat tiles (light-gray two-tone) */
  .tile { background: linear-gradient(155deg, rgba(255,255,255,.07), rgba(255,255,255,.015)); backdrop-filter: blur(3px) saturate(180%) brightness(1.08); -webkit-backdrop-filter: blur(3px) saturate(180%) brightness(1.08); border: 1px solid rgba(255,255,255,.44); border-radius: 20px 7px 7px 20px; padding: 11px 14px; box-shadow: inset 0 1px 0 rgba(255,255,255,.95), inset 0 0 0 1px rgba(255,255,255,.16), 0 0 26px -5px rgba(255,255,255,.22), 0 14px 32px -18px rgba(0,0,0,.65); }
  .tile.alt { background: linear-gradient(155deg, rgba(255,255,255,.05), rgba(255,255,255,.01)); }
  .tile .top { display: flex; align-items: center; gap: 8px; color: var(--c-muted); font-size: 12px; font-weight: 500; margin-bottom: 6px; }
  .tile .dot { width: 18px; height: 18px; border-radius: 5px; display: flex; align-items: center; justify-content: center; font-size: 11px; }
  .tile .big { font-size: 26px; font-weight: 700; line-height: 1.1; color: #fff; }
  .tile .sub { font-size: 11px; color: var(--c-muted); margin-top: 3px; }
  .tile .sub b { color: var(--c-violet); }
  .sevbar { display: flex; gap: 3px; margin-bottom: 8px; }
  .sevbar i { height: 5px; border-radius: 3px; flex: 1; }
  .legend { display: flex; gap: 12px; font-family: var(--c-mono); font-size: 10px; color: #7c8270; }
  .legend i { display: inline-block; width: 7px; height: 7px; border-radius: 2px; margin-right: 4px; vertical-align: middle; }

  /* FILTER BAR */
  .fbar { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; flex-wrap: wrap; }
  .search { display: flex; align-items: center; gap: 8px; background: rgba(255,255,255,.05); backdrop-filter: blur(3px) saturate(180%) brightness(1.08); -webkit-backdrop-filter: blur(3px) saturate(180%) brightness(1.08); border: 1px solid rgba(255,255,255,.40); box-shadow: inset 0 1px 0 rgba(255,255,255,.85), 0 0 16px -5px rgba(255,255,255,.18); border-radius: 20px; padding: 8px 14px; color: var(--c-muted); font-size: 12px; min-width: 200px; }
  .toggle { display: flex; background: rgba(255,255,255,.05); backdrop-filter: blur(3px) saturate(180%) brightness(1.08); -webkit-backdrop-filter: blur(3px) saturate(180%) brightness(1.08); border: 1px solid rgba(255,255,255,.40); box-shadow: inset 0 1px 0 rgba(255,255,255,.85), 0 0 16px -5px rgba(255,255,255,.18); border-radius: 20px; padding: 3px; position: relative; }
  .toggle button { background: transparent; border: 0; color: var(--c-muted); font-size: 12px; padding: 6px 14px; border-radius: 16px; }
  .toggle button.on { background: rgba(255,255,255,.92); color: #0b1020; font-weight: 600; }
  .chip { background: rgba(255,255,255,.05); backdrop-filter: blur(3px) saturate(180%) brightness(1.08); -webkit-backdrop-filter: blur(3px) saturate(180%) brightness(1.08); border: 1px solid rgba(255,255,255,.40); box-shadow: inset 0 1px 0 rgba(255,255,255,.85), 0 0 16px -5px rgba(255,255,255,.18); border-radius: 20px; padding: 8px 14px; color: var(--c-muted); font-size: 12px; display: flex; align-items: center; gap: 7px; }
  .sel { position: relative; display: inline-flex; }
  .sel .chip { cursor: pointer; }
  .menu { position: absolute; top: calc(100% + 6px); left: 0; z-index: 45; min-width: 168px; display: flex; flex-direction: column; padding: 6px; border-radius: 14px; background: rgba(18,26,50,.98); backdrop-filter: blur(22px) saturate(160%); -webkit-backdrop-filter: blur(22px) saturate(160%); border: 1px solid rgba(255,255,255,.30); box-shadow: inset 0 1px 0 rgba(255,255,255,.6), 0 18px 38px -14px rgba(0,0,0,.6); }
  .menu button { background: transparent; border: 0; text-align: left; color: rgba(255,255,255,.9); font-size: 12px; padding: 8px 10px; border-radius: 8px; white-space: nowrap; }
  .menu button:hover { background: rgba(255,255,255,.1); color: #fff; }
  .profile-menu { right: 0; left: auto; min-width: 212px; }
  .pm-head { display: flex; flex-direction: column; gap: 2px; padding: 8px 10px; }
  .pm-head b { color: #fff; font-size: 13px; }
  .pm-head span { color: var(--c-muted); font-size: 11px; }
  .pm-lbl { padding: 6px 10px 3px; font-size: 9px; letter-spacing: .1em; text-transform: uppercase; color: var(--c-faint); }
  .pm-sep { height: 1px; background: rgba(255,255,255,.14); margin: 5px 6px; }
  .menu button.danger { color: #ff8a8a; }
  .menu button.danger:hover { background: rgba(230,57,70,.20); color: #ffb3b3; }
  .chip.act { color: #6b46c1; border-color: rgba(107,70,193,.4); }
  .chip.act b { color: #6b46c1; }

  /* refined tooltip */
  .tip { position: absolute; left: 0; top: 46px; background: #05050c; border: 1px solid var(--c-stroke); border-radius: 10px; padding: 14px 16px; width: 300px; z-index: 30; box-shadow: 0 18px 50px rgba(0,0,0,.6); display: none; }
  .tip.show { display: block; }
  .tip .row { display: flex; justify-content: space-between; margin-bottom: 8px; }
  .tip .row .h { font-family: var(--c-mono); font-size: 10px; text-transform: uppercase; letter-spacing: .08em; color: var(--c-faint); }
  .tip .row .n { font-size: 20px; font-weight: 700; }
  .tip .row .n small { font-size: 11px; color: var(--c-ok); margin-left: 5px; }
  .tip .viz { height: 34px; background: linear-gradient(90deg, var(--c-violet), rgba(155,140,255,.2)); border-radius: 6px; clip-path: polygon(0 0,100% 18%,100% 82%,0 100%); margin: 6px 0; }
  .tip .captxt { font-size: 11px; color: var(--c-muted); }

  /* TABLE */
  table { width: 100%; border-collapse: collapse; }
  thead th { text-align: left; font-family: var(--c-mono); font-size: 10px; letter-spacing: .08em; text-transform: uppercase; color: var(--c-faint); font-weight: 600; padding: 0 14px 10px; border-bottom: 1px solid var(--c-hair); }
  tbody tr { border-bottom: 1px solid var(--c-hair); }
  tbody tr:hover { background: rgba(255,255,255,.03); cursor: pointer; }
  tbody tr.sel { background: rgba(230,57,70,.07); box-shadow: inset 2px 0 0 var(--c-air); }
  td { padding: 9px 14px; vertical-align: top; }
  td.ty { width: 44px; }
  .tyic { width: 26px; height: 26px; border-radius: 6px; background: var(--c-panel2); border: 1px solid var(--c-hair); display: flex; align-items: center; justify-content: center; font-family: var(--c-mono); font-size: 9px; color: #fff; }
  .nm { font-size: 13.5px; font-weight: 500; }
  .loc { font-family: var(--c-mono); font-size: 11px; color: var(--c-faint); margin-top: 3px; }
  .tag { font-family: var(--c-mono); font-size: 9px; letter-spacing: .06em; color: var(--c-violet); background: rgba(155,140,255,.12); padding: 2px 6px; border-radius: 4px; margin-left: 7px; }
  .sev { display: inline-flex; align-items: center; gap: 6px; font-size: 11px; font-weight: 600; padding: 4px 9px; border-radius: 14px; }
  .sev i { width: 6px; height: 6px; border-radius: 50%; }
  .sev.c { color: var(--c-crit); background: rgba(255,93,104,.12); } .sev.c i { background: var(--c-crit); }
  .sev.h { color: var(--c-high); background: rgba(255,180,84,.12); } .sev.h i { background: var(--c-high); }
  .sev.m { color: var(--c-med); background: rgba(106,168,255,.12); } .sev.m i { background: var(--c-med); }
  .sev.l { color: var(--c-low); background: rgba(93,202,165,.12); } .sev.l i { background: var(--c-low); }
  .blast { font-family: var(--c-mono); font-size: 12px; color: var(--c-muted); }
  .empty { text-align: center; color: var(--c-faint); font-size: 12px; padding: 13px; border-top: 1px solid var(--c-hair); margin-top: 4px; }

  /* SLIDE-OVER */
  .slide { position: fixed; top: 0; right: 0; height: 100vh; width: 560px; background: #eef1f6; border-left: 1px solid rgba(0,0,0,.08); transform: translateX(100%); transition: transform .28s cubic-bezier(.4,0,.2,1); z-index: 50; display: flex; flex-direction: column; box-shadow: -30px 0 80px rgba(0,0,0,.5); }
  .slide.open { transform: translateX(0); }
  .sl-top { display: flex; align-items: center; gap: 12px; padding: 16px 16px 10px; }
  .iconbtn { width: 30px; height: 30px; border-radius: 7px; background: #fff; border: 1px solid rgba(0,0,0,.12); color: #1b2114; display: flex; align-items: center; justify-content: center; font-size: 14px; }
  .actbtn { margin-left: auto; background: #fff; border: 1px solid rgba(0,0,0,.12); border-radius: 8px; color: #1b2114; padding: 8px 13px; font-size: 12px; font-weight: 600; display: flex; align-items: center; gap: 6px; }
  .sl-head { margin: 14px 16px; padding: 18px 20px; display: flex; gap: 16px; border-radius: 18px; background: linear-gradient(155deg, rgba(22,36,68,.97), rgba(12,22,50,.97)); border: 1px solid rgba(255,255,255,.44); box-shadow: inset 0 1px 0 rgba(255,255,255,.9), inset 0 0 0 1px rgba(255,255,255,.12), 0 0 26px -6px rgba(255,255,255,.16), 0 16px 34px -18px rgba(0,0,0,.35); }
  .gauge { width: 74px; height: 74px; flex: 0 0 74px; position: relative; }
  .gauge svg { transform: rotate(-90deg); }
  .gauge .val { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; }
  .gauge .val b { font-size: 22px; font-weight: 700; line-height: 1; color: #fff; }
  .gauge .val small { font-family: var(--c-mono); font-size: 8px; letter-spacing: .06em; text-transform: uppercase; color: var(--c-muted); margin-top: 2px; }
  .sl-title h3 { margin: 0 0 4px; font-size: 16px; color: #fff; }
  .sl-title .det { font-size: 12px; color: var(--c-muted); margin-bottom: 8px; }
  .badge { display: inline-flex; align-items: center; gap: 5px; font-family: var(--c-mono); font-size: 9px; letter-spacing: .06em; text-transform: uppercase; padding: 4px 8px; border-radius: 5px; margin-right: 6px; }
  .badge.new { background: rgba(155,140,255,.16); color: var(--c-violet); }
  .badge.cat { background: rgba(255,255,255,.07); color: var(--c-muted); border: 1px solid var(--c-glass-brd); }
  .tabs { display: flex; gap: 22px; padding: 4px 20px 0; margin-bottom: 4px; border-bottom: 1px solid rgba(0,0,0,.08); }
  .tabs button { background: transparent; border: 0; border-bottom: 2px solid transparent; color: rgba(18,26,45,.55); padding: 13px 0; font-size: 13px; font-weight: 500; }
  .tabs button.on { color: #0b1020; border-bottom-color: var(--c-air); }
  .tabs button .lk { font-family: var(--c-mono); font-size: 8px; color: var(--c-warn); margin-left: 5px; }
  .sl-body { padding: 0 0 20px; overflow-y: auto; flex: 1; }
  .sl-body h4 { font-family: var(--c-mono); font-size: 11px; letter-spacing: .08em; text-transform: uppercase; color: var(--c-muted); margin: 0 0 8px; }
  .sl-body p { color: rgba(255,255,255,.86); line-height: 1.55; font-size: 13px; margin: 0 0 20px; }
  .sec { margin: 0 16px 14px; padding: 16px 18px; border-radius: 16px; background: linear-gradient(155deg, rgba(22,36,68,.97), rgba(12,22,50,.97)); border: 1px solid rgba(255,255,255,.42); box-shadow: inset 0 1px 0 rgba(255,255,255,.85), inset 0 0 0 1px rgba(255,255,255,.10), 0 14px 30px -18px rgba(0,0,0,.35); }
  .sec .hd { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }
  .ghostbtn { background: rgba(255,255,255,.08); border: 1px solid var(--c-glass-brd); border-radius: 7px; color: #fff; padding: 6px 11px; font-size: 11px; font-weight: 600; display: flex; align-items: center; gap: 6px; }
  .ghostbtn.lk { color: var(--c-warn); border-color: rgba(255,180,84,.35); }
  .ghostbtn.done { color: var(--c-ok); border-color: rgba(93,202,165,.4); }
  .steps { border: 1px solid var(--c-hair); border-radius: 8px; overflow: hidden; }
  .steps .sh { background: rgba(255,255,255,.06); font-family: var(--c-mono); font-size: 10px; letter-spacing: .06em; text-transform: uppercase; color: var(--c-muted); padding: 9px 12px; border-bottom: 1px solid var(--c-hair); }
  .steps .it { display: flex; align-items: center; gap: 10px; padding: 11px 12px; font-family: var(--c-mono); font-size: 12px; border-bottom: 1px solid var(--c-hair); color: rgba(255,255,255,.86); }
  .steps .it:last-child { border-bottom: 0; }
  .steps .it.on { background: rgba(230,57,70,.10); }
  .steps .it .mini { font-size: 9px; color: var(--c-air); background: rgba(230,57,70,.14); padding: 2px 6px; border-radius: 4px; margin-left: auto; }
  .gactions { display: flex; gap: 10px; margin-top: 6px; flex-wrap: wrap; }

  /* MODALS */
  .scrim { position: fixed; inset: 0; background: rgba(3,3,9,.66); backdrop-filter: blur(3px); z-index: 60; display: none; align-items: center; justify-content: center; }
  .scrim.show { display: flex; }
  .modal { background: rgba(18,26,50,.96); backdrop-filter: blur(30px) saturate(160%); -webkit-backdrop-filter: blur(30px) saturate(160%); border: 1px solid var(--c-glass-brd); border-radius: 14px; width: 460px; padding: 26px; box-shadow: 0 30px 90px rgba(0,0,0,.7); }
  .modal .k { font-family: var(--c-mono); font-size: 10px; letter-spacing: .1em; text-transform: uppercase; color: var(--c-muted); margin-bottom: 10px; }
  .modal h2 { margin: 0 0 10px; font-size: 22px; color: #fff; }
  .modal p { color: var(--c-muted); font-size: 13px; line-height: 1.55; margin: 0 0 20px; }
  .modal p a { color: var(--c-air2); }
  .modal .btns { display: flex; gap: 10px; }
  .modal .btns button { flex: 0 0 auto; padding: 11px 18px; border-radius: 8px; font-weight: 600; font-size: 13px; }
  .btn-primary { background: var(--c-air); color: #fff; border: 0; }
  .btn-ghost { background: transparent; color: #1b2114; border: 1px solid rgba(20,26,12,.18); }
  .codebox { background: #05050c; border: 1px solid var(--c-hair); border-radius: 8px; padding: 14px; font-family: var(--c-mono); font-size: 11.5px; line-height: 1.7; color: #cfd2e6; white-space: pre; overflow-x: auto; margin-bottom: 16px; }
  .codebox .c { color: var(--c-faint); } .codebox .kw { color: var(--c-air2); } .codebox .s { color: var(--c-ok); }
  .note { font-size: 11px; color: #8a9080; font-family: var(--c-mono); }
  .mono { font-family: var(--c-mono); }

  @media (max-width: 980px) {
    .stats { grid-template-columns: 1fr 1fr; }
    .slide { width: 100%; }
    .modal { width: calc(100% - 32px); }
  }
</style>
