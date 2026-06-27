<script lang="ts">
	import { authError, beginAuth0Login } from '$lib/console/stores/session';

	let pending = $state<'google' | 'github' | 'generic' | null>(null);

	$effect(() => {
		if ($authError) pending = null;
	});

	function startGoogle() {
		pending = 'google';
		void beginAuth0Login('google-oauth2');
	}

	function startGitHub() {
		pending = 'github';
		void beginAuth0Login('github');
	}

	function startGeneric() {
		pending = 'generic';
		void beginAuth0Login();
	}
</script>

<div class="wrap">
	<div class="rim-glow" aria-hidden="true"></div>
	<section class="left" aria-labelledby="sign-in-title">
		<a class="logo" href="/" aria-label="Project AIR home">
			<svg class="plane" viewBox="0 0 28 24" aria-hidden="true">
				<path d="M27 11 2 2l9 10Z" fill="#fff" />
				<path d="M27 11 11 12 2 21Z" fill="#e63946" />
				<path d="m11 12-9 9 5-8Z" fill="#c92d3a" />
			</svg>
			<span>V<span class="slash">/</span>P <b>AIR</b></span>
		</a>

		<div class="center">
			<p class="chip">Flightdeck access</p>
			<h1 id="sign-in-title">Sign in to Flightdeck.</h1>
			<p class="sub">Monitor agent evidence, investigate findings, and manage containment from one operator console.</p>

			<div class="button-row">
				<button class="button google" onclick={startGoogle} disabled={pending !== null}>
					<svg class="provider-icon" viewBox="0 0 24 24" aria-hidden="true">
						<path fill="#4285f4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.27-4.74 3.27-8.1Z" />
						<path fill="#34a853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.99.66-2.26 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84A11 11 0 0 0 12 23Z" />
						<path fill="#fbbc05" d="M5.84 14.1a6.6 6.6 0 0 1 0-4.2V7.06H2.18a11 11 0 0 0 0 9.88l3.66-2.84Z" />
						<path fill="#ea4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1A11 11 0 0 0 2.18 7.06l3.66 2.84C6.71 7.3 9.14 5.38 12 5.38Z" />
					</svg>
					{pending === 'google' ? 'Redirecting…' : 'Google'}
				</button>
				<button class="button github" onclick={startGitHub} disabled={pending !== null}>
					<svg class="provider-icon" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
						<path d="M12 1A11 11 0 0 0 8.52 22.43c.55.1.75-.24.75-.53v-1.85c-3.06.67-3.71-1.47-3.71-1.47-.5-1.28-1.22-1.62-1.22-1.62-1-.68.08-.67.08-.67 1.1.08 1.68 1.13 1.68 1.13.98 1.68 2.57 1.2 3.2.92.1-.71.38-1.2.69-1.47-2.44-.28-5.01-1.22-5.01-5.43 0-1.2.43-2.18 1.13-2.95-.11-.28-.49-1.4.11-2.92 0 0 .92-.3 3.02 1.13a10.5 10.5 0 0 1 5.5 0c2.1-1.42 3.02-1.13 3.02-1.13.6 1.52.22 2.64.11 2.92.7.77 1.13 1.75 1.13 2.95 0 4.22-2.58 5.15-5.03 5.42.4.34.75 1 .75 2.03v3.01c0 .29.2.64.76.53A11 11 0 0 0 12 1Z" />
					</svg>
					{pending === 'github' ? 'Redirecting…' : 'GitHub'}
				</button>
			</div>

			<button class="button sso" onclick={startGeneric} disabled={pending !== null}>
				<span class="sso-lock" aria-hidden="true">▣</span>
				<span>{pending === 'generic' ? 'Redirecting…' : 'Sign in with SSO'}</span>
				<span class="providers">Enterprise identity</span>
			</button>
			<button class="email" onclick={startGeneric} disabled={pending !== null}>
				Continue with email <span aria-hidden="true">›</span>
			</button>

			<div class="divider" aria-hidden="true">or</div>

			<button class="demo" disabled aria-disabled="true" title="Public demo access is not configured yet.">
				<span aria-hidden="true">▶</span> Test-drive a demo chain <small>coming soon</small>
			</button>
			<p class="fine">OAuth is handled by Auth0. Provider credentials never enter Flightdeck.</p>
			{#if $authError}
				<p class="error" role="status" aria-live="polite">{$authError}</p>
			{/if}
		</div>

		<nav class="footer" aria-label="Sign-in resources">
			<a href="/get-started/">Docs</a><a href="/pricing/">Pricing</a><a href="/security/">Security</a>
		</nav>
	</section>

	<aside class="right" aria-label="Project AIR trust details">
		<p class="right-label">What Flightdeck adds to your agent operations</p>

		<article class="card">
			<h2><span class="card-icon ok" aria-hidden="true">✓</span>Signed local evidence</h2>
			<p>AIR records signed Intent Capsules where your agents run, so your evidence chain stays under your control.</p>
		</article>

		<article class="card">
			<h2><span class="card-icon air" aria-hidden="true">↗</span>Findings you can inspect</h2>
			<p>Investigate <strong>10 OWASP Agentic, 3 OWASP LLM, and 3 AIR-native</strong> detector signals in one place.</p>
		</article>

		<div class="badges" aria-label="Flightdeck technical attributes">
			<span><i class="green"></i>BLAKE3 + signatures</span><span><i class="cyan"></i>Auth0 PKCE</span><span><i class="violet"></i>16 detectors</span>
		</div>
		<div class="sectors"><span>Developers</span><span>Security teams</span><span>Regulated systems</span></div>
	</aside>
</div>

<style>
	:global(html) { background: #070710; }
	:global(body) { margin: 0; background: #070710; }
	:global(button), :global(a) { font: inherit; }
	:global(button) { cursor: pointer; }
	:global(button:focus-visible), :global(a:focus-visible) { outline: 3px solid #67e8f9; outline-offset: 3px; }
	.rim-glow { position: fixed; inset: 0; z-index: 30; pointer-events: none; border: 1px solid transparent; background: linear-gradient(transparent, transparent) padding-box, linear-gradient(110deg, transparent 0 34%, rgba(255,255,255,.08) 42%, rgba(255,255,255,.9) 48%, rgba(255,255,255,.28) 54%, transparent 63%) border-box; background-size: 100% 100%, 300% 300%; background-position: center, 0% 50%; box-shadow: inset 0 0 14px rgba(255,255,255,.14); animation: rim-flow 12s linear infinite; }
	.wrap { --red: #e63946; --red-light: #ff5d68; --ink: #fff; --muted: rgba(255,255,255,.64); --faint: rgba(255,255,255,.44); --hair: rgba(255,255,255,.09); --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; min-height: 100vh; display: grid; grid-template-columns: 1.05fr .95fr; color: var(--ink); font-family: Inter, system-ui, sans-serif; }
	.left { min-height: 100vh; display: flex; flex-direction: column; padding: 34px 6vw; position: relative; overflow: hidden; background: linear-gradient(165deg, #16223f 0%, #101a30 55%, #0b1020 100%); }
	.left::after { content: ''; position: absolute; inset: auto -10% -32% 20%; height: 42rem; pointer-events: none; background: radial-gradient(ellipse, rgba(230,57,70,.14), transparent 63%); }
	.logo { z-index: 1; display: inline-flex; align-items: center; gap: 10px; width: max-content; color: #fff; text-decoration: none; font: 700 15px var(--mono); letter-spacing: .2em; }
	.logo b, .slash { color: var(--red); }
	.plane { width: 27px; height: 23px; filter: drop-shadow(0 0 9px rgba(230,57,70,.55)); }
	.center { z-index: 1; width: 100%; max-width: 400px; margin: auto; padding: 68px 0; }
	.chip { display: inline-flex; margin: 0 0 22px; padding: 7px 13px; border: 1px solid rgba(255,255,255,.28); border-radius: 999px; background: rgba(255,255,255,.12); color: #fff; font: 11px var(--mono); letter-spacing: .1em; text-transform: uppercase; }
	h1 { max-width: 360px; margin: 0 0 12px; font-size: clamp(2.1rem, 4vw, 2.7rem); line-height: 1.08; letter-spacing: -.035em; }
	.sub { margin: 0 0 28px; color: rgba(255,255,255,.75); font-size: 15px; line-height: 1.55; }
	.button-row { display: grid; grid-template-columns: 1fr 1fr; gap: 11px; margin-bottom: 11px; }
	.button, .demo { min-height: 48px; border-radius: 10px; font-weight: 700; font-size: 14px; transition: filter .15s ease, transform .15s ease, background .15s ease; }
	.button { display: inline-flex; align-items: center; justify-content: center; gap: 9px; width: 100%; border: 1px solid rgba(255,255,255,.15); }
	.button:hover:not(:disabled), .email:hover:not(:disabled) { filter: brightness(1.1); transform: translateY(-1px); }
	.button:disabled, .email:disabled { cursor: wait; opacity: .72; }
	.google { border: 0; background: #fff; color: #161616; }
	.github { background: #10101c; color: #fff; }
	.provider-icon { width: 18px; height: 18px; }
	.sso { justify-content: flex-start; padding: 0 13px; background: rgba(255,255,255,.06); color: #fff; border-color: rgba(255,255,255,.28); }
	.sso-lock { color: #d9d4ff; font-size: 16px; }
	.providers { margin-left: auto; color: rgba(255,255,255,.5); font: 9px var(--mono); letter-spacing: .08em; text-transform: uppercase; }
	.email { display: block; width: 100%; border: 0; background: transparent; color: rgba(255,255,255,.76); padding: 9px; font-size: 13px; }
	.divider { display: flex; align-items: center; gap: 14px; margin: 16px 0; color: rgba(255,255,255,.48); font: 10px var(--mono); letter-spacing: .16em; text-transform: uppercase; }
	.divider::before, .divider::after { content: ''; flex: 1; height: 1px; background: rgba(255,255,255,.16); }
	.demo { width: 100%; border: 1px solid rgba(230,57,70,.36); background: rgba(230,57,70,.1); color: rgba(255,255,255,.58); cursor: not-allowed; }
	.demo span { color: var(--red-light); }
	.demo small { font-size: 10px; color: var(--faint); }
	.fine { margin: 16px 0 0; text-align: center; color: rgba(255,255,255,.58); font-size: 12px; line-height: 1.45; }
	.error { margin: 14px 0 0; padding: 10px 12px; border: 1px solid rgba(255,180,84,.5); border-radius: 8px; background: rgba(255,180,84,.09); color: #ffd4a0; font-size: 12px; line-height: 1.45; }
	.footer { z-index: 1; display: flex; flex-wrap: wrap; gap: 18px; margin-top: auto; }
	.footer a { color: rgba(255,255,255,.62); font-size: 12px; text-decoration: none; }
	.footer a:hover { color: #fff; }
	.right { position: relative; display: flex; flex-direction: column; justify-content: center; gap: 16px; min-height: 100vh; overflow: hidden; padding: 48px 5vw; border-left: 1px solid var(--hair); background: radial-gradient(900px 500px at 80% 10%, rgba(230,57,70,.14), transparent 60%), radial-gradient(700px 500px at 30% 90%, rgba(103,232,249,.08), transparent 60%), #06060d; }
	.right::before { content: ''; position: absolute; inset: 0; opacity: .5; background-image: radial-gradient(rgba(255,255,255,.05) 1px, transparent 1px); background-size: 24px 24px; }
	.right > * { position: relative; }
	.right-label { margin: 0 0 2px; color: var(--faint); font: 10px var(--mono); letter-spacing: .14em; text-transform: uppercase; }
	.card { padding: 20px 22px; border: 1px solid var(--hair); border-radius: 14px; background: rgba(12,12,22,.7); backdrop-filter: blur(5px); }
	.card h2 { display: flex; align-items: center; gap: 11px; margin: 0 0 8px; font-size: 15px; }
	.card p { margin: 0; color: var(--muted); font-size: 13px; line-height: 1.55; }
	.card strong { color: #fff; font-weight: 600; }
	.card-icon { display: inline-grid; place-items: center; width: 30px; height: 30px; border-radius: 8px; font-size: 16px; }
	.ok { background: rgba(93,202,165,.16); color: #5dcaa5; }.air { background: rgba(230,57,70,.16); color: var(--red-light); }
	.badges, .sectors { display: flex; flex-wrap: wrap; gap: 8px; }.badges span, .sectors span { display: inline-flex; align-items: center; gap: 7px; padding: 7px 11px; border: 1px solid var(--hair); border-radius: 8px; background: rgba(255,255,255,.04); color: var(--muted); font: 11px var(--mono); letter-spacing: .04em; }.badges i { width: 8px; height: 8px; border-radius: 50%; }.green { background: #5dcaa5; }.cyan { background: #67e8f9; }.violet { background: #9b8cff; }.sectors span { border-radius: 999px; color: var(--faint); font-size: 10px; letter-spacing: .08em; text-transform: uppercase; }
	@keyframes rim-flow { to { background-position: center, 300% 50%; } }
	@media (prefers-reduced-motion: reduce) { *, *::before, *::after { scroll-behavior: auto !important; animation-duration: .01ms !important; animation-iteration-count: 1 !important; transition-duration: .01ms !important; }.rim-glow { animation: none; } }
	@media (max-width: 880px) { .wrap { grid-template-columns: 1fr; }.right { display: none; }.left { padding: 28px 7vw; }.center { margin: auto; }.footer { margin-top: 0; } }
	@media (max-width: 420px) { .button-row { grid-template-columns: 1fr; }.center { padding: 46px 0; }.providers { display: none; } }
</style>
