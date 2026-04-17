<script lang="ts">
	import '../app.css';
	import favicon from '$lib/assets/favicon.svg';

	let { children } = $props();
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
	<title>Vindicara AIR | AI Agent Incident Response</title>
	<meta name="description" content="The only tool that turns AI agent traces into evidence, so security can contain, legal can prove duty of care, and insurance can process claims. Forensic reconstruction, incident response, court-admissible evidence. One SDK." />
	<meta name="keywords" content="AI incident response, AI forensics, agent forensics, AgDR, OWASP ASI, AI Decision Records, EU AI Act Article 12, California SB 53, NIST AI RMF, LLM forensics, agent trace, AI audit trail" />

	<!-- Open Graph -->
	<meta property="og:type" content="website" />
	<meta property="og:url" content="https://vindicara.io" />
	<meta property="og:title" content="Vindicara AIR | AI Agent Incident Response" />
	<meta property="og:description" content="When your AI agent goes off-script, AIR tells you what happened, and proves it. Forensic reconstruction, incident response, court-admissible evidence. One SDK." />
	<meta property="og:site_name" content="Vindicara" />

	<!-- Twitter / X -->
	<meta name="twitter:card" content="summary_large_image" />
	<meta name="twitter:site" content="@vindicara" />
	<meta name="twitter:title" content="Vindicara AIR | AI Agent Incident Response" />
	<meta name="twitter:description" content="When your AI agent goes off-script, AIR tells you what happened, and proves it. Forensic reconstruction, incident response, court-admissible evidence." />

	<!-- Canonical -->
	<link rel="canonical" href="https://vindicara.io" />

	<!-- Theme -->
	<meta name="theme-color" content="#0a0a0f" />
</svelte:head>

{@render children()}
