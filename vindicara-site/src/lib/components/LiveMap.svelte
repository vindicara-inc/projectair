<script>
  // @ts-nocheck
  // Live world-map hero: dotted map + glowing active/new dots, LIVE indicator,
  // headline and legend. Sits at the top of the Get Started page.
  import DotMap from '$lib/components/DotMap.svelte';
</script>

<div class="livemap">
  <div class="lm-live"><span class="lm-live-dot" aria-hidden="true"></span>Live</div>
  <h1>Project <span class="air">AIR</span>, in use around the world right now.</h1>
  <div class="lm-map"><DotMap /></div>
  <p class="lm-cap"><b>Active users</b> light up in white, <b>new arrivals</b> in red, live as they happen.</p>
  <div class="lm-legend">
    <span><i class="lm-dot lm-active"></i>Active users</span>
    <span><i class="lm-dot lm-new"></i>New users</span>
  </div>
</div>

<style>
  .livemap { text-align: center; position: relative; }
  .livemap h1 { font-size: 38px; margin: 12px auto 0; max-width: 24ch; line-height: 1.1; }
  .livemap h1 .air { color: var(--air2); }
  .lm-live { position: absolute; top: 0; right: 0; font-family: var(--mono, 'JetBrains Mono', monospace); font-size: 14px; letter-spacing: 0.22em; text-transform: uppercase; color: var(--air2); font-weight: 600; display: inline-flex; align-items: center; }
  .lm-live-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #ff5763; box-shadow: 0 0 9px rgba(255, 87, 99, 0.95); margin-right: 9px; animation: lmblink 1.5s ease-in-out infinite; }
  @keyframes lmblink { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
  .lm-cap { font-size: 16px; color: var(--white); line-height: 1.6; margin: 12px auto 8px; font-family: var(--display, 'Spectral', serif); white-space: nowrap; }
  @media (max-width: 680px) { .lm-cap { white-space: normal; } }
  .lm-map { position: relative; left: 50%; width: 100vw; transform: translateX(-50%); margin-top: 8px; }
  .lm-legend { display: flex; gap: 24px; justify-content: center; margin: 4px 0 12px; font-family: var(--mono, 'JetBrains Mono', monospace); font-size: 12px; letter-spacing: 0.03em; color: #cdd8ec; }
  .lm-dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 8px; vertical-align: middle; }
  .lm-active { background: #fff; box-shadow: 0 0 9px rgba(255, 255, 255, 0.9); }
  .lm-new { background: #ff5763; box-shadow: 0 0 9px rgba(255, 87, 99, 0.9); }
  /* the map hero stands on the clean page background, no dotfield behind it */
  :global(body::after) { display: none !important; }
</style>
