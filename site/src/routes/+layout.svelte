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
	<meta property="og:image" content="https://vindicara.io/og-image.png" />
	<meta property="og:image:width" content="1200" />
	<meta property="og:image:height" content="630" />
	<meta property="og:image:alt" content="Vindicara AIR: When your agent goes off-script, AIR has the receipts." />

	<!-- Twitter / X -->
	<meta name="twitter:card" content="summary_large_image" />
	<meta name="twitter:site" content="@vindicara" />
	<meta name="twitter:title" content="Vindicara AIR | AI Agent Incident Response" />
	<meta name="twitter:description" content="When your AI agent goes off-script, AIR tells you what happened, and proves it. Forensic reconstruction, incident response, court-admissible evidence." />
	<meta name="twitter:image" content="https://vindicara.io/og-image.png" />

	<!-- Canonical -->
	<link rel="canonical" href="https://vindicara.io" />

	<!-- Theme -->
	<meta name="theme-color" content="#0a0a0f" />

	<!-- Structured Data -->
	{@html `<script type="application/ld+json">${JSON.stringify({
		'@context': 'https://schema.org',
		'@graph': [
			{
				'@type': 'Organization',
				'@id': 'https://vindicara.io/#organization',
				name: 'Vindicara',
				url: 'https://vindicara.io',
				logo: 'https://vindicara.io/og-image.png',
				sameAs: ['https://github.com/get-sltr/vindicara-ai', 'https://x.com/vindicara', 'https://linkedin.com/company/vindicara'],
			},
			{
				'@type': 'SoftwareApplication',
				'@id': 'https://vindicara.io/#air',
				name: 'Vindicara AIR',
				applicationCategory: 'SecurityApplication',
				operatingSystem: 'Cross-platform',
				description: 'Forensic reconstruction and incident response for AI agents. Court-admissible evidence from agent traces.',
				url: 'https://vindicara.io',
				publisher: { '@id': 'https://vindicara.io/#organization' },
				offers: [
					{ '@type': 'Offer', name: 'Open Source', price: '0', priceCurrency: 'USD' },
					{ '@type': 'Offer', name: 'Team', price: '1499', priceCurrency: 'USD', priceSpecification: { '@type': 'UnitPriceSpecification', price: '1499', priceCurrency: 'USD', billingIncrement: 1, unitText: 'MONTH' } },
					{ '@type': 'Offer', name: 'Enterprise', priceSpecification: { '@type': 'PriceSpecification', minPrice: '50000', maxPrice: '250000', priceCurrency: 'USD' } },
				],
			},
			{
				'@type': 'WebSite',
				'@id': 'https://vindicara.io/#website',
				url: 'https://vindicara.io',
				name: 'Vindicara',
				publisher: { '@id': 'https://vindicara.io/#organization' },
			},
		],
	})}<\/script>`}
</svelte:head>

{@render children()}
