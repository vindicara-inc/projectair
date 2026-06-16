<script lang="ts">
	import { replayStore } from '$lib/stores/replay.svelte';
	import { verifierStore } from '$lib/stores/verifier.svelte';

	const isLive = $derived(replayStore.status === 'playing');
	const eventsPerMin = $derived(replayStore.emitted.length > 0 ? Math.round(replayStore.emitted.length * 6) : 0);
</script>

<div style="background:rgba(0,0,0,.3); border:1px solid rgba(255,255,255,.06); border-radius:8px; overflow:hidden;">
	<!-- Header -->
	<div class="flex items-center justify-between px-4 py-3" style="border-bottom:1px solid rgba(255,255,255,.06); background:rgba(0,0,0,.3);">
		<span class="text-[11px] font-bold tracking-[0.22em] uppercase" style="font-family:var(--font-display); color:var(--color-white);">Evidence Chain · Live</span>
		<div class="flex items-center gap-2.5 text-[9px] tracking-[0.18em] uppercase" style="color:var(--color-red);">
			{#if isLive}
				<span class="w-1.5 h-1.5 rounded-full" style="background:var(--color-red); box-shadow:0 0 8px var(--color-red); animation:blink 1.5s infinite;"></span>
				STREAMING
			{:else}
				<span class="w-1.5 h-1.5 rounded-full" style="background:var(--color-white-4);"></span>
				<span style="color:var(--color-white-4);">IDLE</span>
			{/if}
			<span style="color:var(--color-white-3); margin-left:8px; padding-left:10px; border-left:1px solid rgba(255,255,255,.1);">{eventsPerMin} EVENTS/MIN</span>
		</div>
	</div>

	<!-- SVG graph -->
	<svg viewBox="0 0 600 320" class="w-full h-auto block" xmlns="http://www.w3.org/2000/svg">
		<defs>
			<radialGradient id="ng-red" cx="50%" cy="50%" r="50%">
				<stop offset="0%" stop-color="#dc2626" stop-opacity="1"/>
				<stop offset="60%" stop-color="#dc2626" stop-opacity=".3"/>
				<stop offset="100%" stop-color="#dc2626" stop-opacity="0"/>
			</radialGradient>
			<radialGradient id="ng-green" cx="50%" cy="50%" r="50%">
				<stop offset="0%" stop-color="#6effb3" stop-opacity="1"/>
				<stop offset="60%" stop-color="#6effb3" stop-opacity=".3"/>
				<stop offset="100%" stop-color="#6effb3" stop-opacity="0"/>
			</radialGradient>
			<radialGradient id="ng-alert" cx="50%" cy="50%" r="50%">
				<stop offset="0%" stop-color="#ff5468" stop-opacity="1"/>
				<stop offset="60%" stop-color="#ff5468" stop-opacity=".3"/>
				<stop offset="100%" stop-color="#ff5468" stop-opacity="0"/>
			</radialGradient>
		</defs>

		<g stroke="rgba(220,38,38,.25)" stroke-width="1" fill="none">
			<path d="M 120,90 Q 200,140 300,160" id="p1"/>
			<path d="M 120,200 Q 200,180 300,160" id="p2"/>
			<path d="M 120,260 Q 200,220 300,160" id="p3"/>
			<path d="M 300,160 Q 400,140 480,90" id="p4"/>
			<path d="M 300,160 Q 400,160 480,200" id="p5"/>
			<path d="M 300,160 Q 400,220 480,270" id="p6"/>
			<path d="M 480,90 Q 540,140 540,200" stroke="rgba(110,255,179,.3)" id="p7"/>
		</g>

		{#if isLive}
			<g>
				{#each [{href:'#p1',fill:'#dc2626',dur:'2.5s',begin:'0s'},{href:'#p2',fill:'#dc2626',dur:'3s',begin:'.8s'},{href:'#p3',fill:'#ff5468',dur:'2.2s',begin:'1.4s'},{href:'#p4',fill:'#dc2626',dur:'2.8s',begin:'.4s'},{href:'#p5',fill:'#6effb3',dur:'2.4s',begin:'1s'},{href:'#p6',fill:'#dc2626',dur:'2.7s',begin:'1.7s'},{href:'#p7',fill:'#6effb3',dur:'3.2s',begin:'2s'}] as particle}
					<circle r="3" fill={particle.fill}>
						<animateMotion dur={particle.dur} repeatCount="indefinite" begin={particle.begin}><mpath href={particle.href}/></animateMotion>
						<animate attributeName="opacity" values="0;1;1;0" dur={particle.dur} repeatCount="indefinite" begin={particle.begin}/>
					</circle>
				{/each}
			</g>
		{/if}

		<g>
			<!-- Agents left -->
			<circle cx="120" cy="90" r="22" fill="url(#ng-red)" opacity=".5"/>
			<circle cx="120" cy="90" r="10" fill="rgba(5,5,7,.9)" stroke="#dc2626" stroke-width="1.5"/>
			<text x="120" y="93" text-anchor="middle" fill="#dc2626" font-family="JetBrains Mono" font-size="9" font-weight="700">A1</text>
			<text x="120" y="125" text-anchor="middle" fill="rgba(248,246,241,.6)" font-family="JetBrains Mono" font-size="8" letter-spacing="1">agent-7b3f</text>

			<circle cx="120" cy="200" r="22" fill="url(#ng-red)" opacity=".5"/>
			<circle cx="120" cy="200" r="10" fill="rgba(5,5,7,.9)" stroke="#dc2626" stroke-width="1.5"/>
			<text x="120" y="203" text-anchor="middle" fill="#dc2626" font-family="JetBrains Mono" font-size="9" font-weight="700">A2</text>
			<text x="120" y="235" text-anchor="middle" fill="rgba(248,246,241,.6)" font-family="JetBrains Mono" font-size="8" letter-spacing="1">agent-a91c</text>

			<circle cx="120" cy="260" r="20" fill="url(#ng-alert)" opacity=".55">
				<animate attributeName="opacity" values=".4;.7;.4" dur="1.5s" repeatCount="indefinite"/>
			</circle>
			<circle cx="120" cy="260" r="10" fill="rgba(5,5,7,.9)" stroke="#ff5468" stroke-width="1.5"/>
			<text x="120" y="263" text-anchor="middle" fill="#ff5468" font-family="JetBrains Mono" font-size="9" font-weight="700">A3</text>
			<text x="120" y="293" text-anchor="middle" fill="rgba(255,84,104,.7)" font-family="JetBrains Mono" font-size="8" letter-spacing="1">FLAG</text>

			<!-- Central hub -->
			<circle cx="300" cy="160" r="38" fill="url(#ng-red)" opacity=".4"/>
			<circle cx="300" cy="160" r="28" fill="rgba(5,5,7,.92)" stroke="#dc2626" stroke-width="2"/>
			<circle cx="300" cy="160" r="22" fill="none" stroke="rgba(220,38,38,.4)" stroke-width="1" stroke-dasharray="3 3">
				<animateTransform attributeName="transform" type="rotate" from="0 300 160" to="360 300 160" dur="12s" repeatCount="indefinite"/>
			</circle>
			<text x="300" y="158" text-anchor="middle" fill="#dc2626" font-family="Syncopate" font-size="9" font-weight="700">AIR</text>
			<text x="300" y="172" text-anchor="middle" fill="rgba(248,246,241,.6)" font-family="JetBrains Mono" font-size="7" letter-spacing="1">SDK</text>

			<!-- Destinations right -->
			<circle cx="480" cy="90" r="22" fill="url(#ng-green)" opacity=".5"/>
			<circle cx="480" cy="90" r="10" fill="rgba(5,5,7,.9)" stroke="#6effb3" stroke-width="1.5"/>
			<text x="480" y="93" text-anchor="middle" fill="#6effb3" font-family="JetBrains Mono" font-size="8" font-weight="700">REK</text>
			<text x="480" y="125" text-anchor="middle" fill="rgba(248,246,241,.6)" font-family="JetBrains Mono" font-size="8" letter-spacing="1">sigstore.rekor</text>

			<circle cx="480" cy="200" r="20" fill="url(#ng-red)" opacity=".5"/>
			<circle cx="480" cy="200" r="10" fill="rgba(5,5,7,.9)" stroke="#dc2626" stroke-width="1.5"/>
			<text x="480" y="203" text-anchor="middle" fill="#dc2626" font-family="JetBrains Mono" font-size="8" font-weight="700">TSA</text>
			<text x="480" y="235" text-anchor="middle" fill="rgba(248,246,241,.6)" font-family="JetBrains Mono" font-size="8" letter-spacing="1">RFC 3161</text>

			<circle cx="480" cy="270" r="20" fill="url(#ng-red)" opacity=".5"/>
			<circle cx="480" cy="270" r="10" fill="rgba(5,5,7,.9)" stroke="#dc2626" stroke-width="1.5"/>
			<text x="480" y="273" text-anchor="middle" fill="#dc2626" font-family="JetBrains Mono" font-size="8" font-weight="700">S3</text>
			<text x="480" y="305" text-anchor="middle" fill="rgba(248,246,241,.6)" font-family="JetBrains Mono" font-size="8" letter-spacing="1">cold storage</text>

			<circle cx="540" cy="155" r="14" fill="url(#ng-green)" opacity=".5"/>
			<circle cx="540" cy="155" r="7" fill="rgba(5,5,7,.9)" stroke="#6effb3" stroke-width="1.5"/>
			<text x="540" y="158" text-anchor="middle" fill="#6effb3" font-family="JetBrains Mono" font-size="7" font-weight="700">&#10003;</text>
		</g>

		<text x="20" y="20" fill="rgba(248,246,241,.3)" font-family="JetBrains Mono" font-size="9" letter-spacing="2">// AGENTS</text>
		<text x="265" y="20" fill="rgba(248,246,241,.3)" font-family="JetBrains Mono" font-size="9" letter-spacing="2">// HUB</text>
		<text x="450" y="20" fill="rgba(248,246,241,.3)" font-family="JetBrains Mono" font-size="9" letter-spacing="2">// CHAIN</text>
		<text x="20" y="310" fill="rgba(248,246,241,.4)" font-family="JetBrains Mono" font-size="8" letter-spacing="1.5">CHAIN_STATUS · {verifierStore.chainStatus.toUpperCase()}</text>
	</svg>

	<!-- Legend -->
	<div class="flex items-center gap-4 px-4 py-3" style="border-top:1px solid rgba(255,255,255,.06); background:rgba(0,0,0,.2);">
		<div class="flex items-center gap-1.5 text-[9px] tracking-[0.18em] uppercase" style="color:var(--color-white-3);">
			<span class="w-1.5 h-1.5 rounded-full" style="background:var(--color-red); box-shadow:0 0 6px var(--color-red);"></span>
			EVIDENCE
		</div>
		<div class="flex items-center gap-1.5 text-[9px] tracking-[0.18em] uppercase" style="color:var(--color-white-3);">
			<span class="w-1.5 h-1.5 rounded-full" style="background:var(--color-terminal-green); box-shadow:0 0 6px var(--color-terminal-green);"></span>
			VERIFIED
		</div>
		<div class="flex items-center gap-1.5 text-[9px] tracking-[0.18em] uppercase" style="color:var(--color-white-3);">
			<span class="w-1.5 h-1.5 rounded-full" style="background:var(--color-critical); box-shadow:0 0 6px var(--color-critical);"></span>
			ALERT
		</div>
		<div class="flex-1"></div>
		<span class="text-[9px] tracking-[0.18em] uppercase font-bold" style="color:var(--color-red);">
			{replayStore.emitted.length} CAPSULES · LIVE
		</span>
	</div>
</div>
