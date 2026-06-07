<script>
  import AppShell from '$components/AppShell.svelte';
</script>
<svelte:head><title>Vindicara · Security</title></svelte:head>

<AppShell active="security" title="security" scroll={true}>
  <div class="prose">
    <div class="eyebrow">Security</div>
    <h1>Security and responsible disclosure.</h1>
    <p class="muted">Last updated: June 6, 2026</p>

    <p class="lede">Project AIR is built to be the evidence layer customers rely on, so the integrity and confidentiality of the Services matter to us as much as they do to you. This page describes how we secure the Services and how to report a vulnerability.</p>

    <h2>How we secure the Services</h2>
    <p><b>Infrastructure.</b> The Hosted Services run on Amazon Web Services (primary region US-West-2). Data is encrypted in transit (TLS) and at rest. Access to production is restricted by least-privilege, role-based controls, and secrets are held in a managed secrets store, not in code.</p>
    <p><b>Authentication.</b> Console access is authenticated through Auth0 using the OAuth 2.0 Authorization Code flow with PKCE. High-stakes actions can require step-up authentication bound to a named human.</p>
    <p><b>Integrity by construction.</b> Every recorded action is written as a signed, hash-chained record. Records are signed with keys held under the customer's sole control, content is hashed with BLAKE3, signatures use Ed25519 (with optional ML-DSA-65 post-quantum signing), and chain roots can be anchored to independent public transparency logs. Any alteration breaks verification deterministically.</p>
    <p><b>Data minimization.</b> Published evidence applies default-deny redaction: non-whitelisted payload fields are stored and published as hashes rather than cleartext. We do not access raw customer payloads outside the scope needed to provide the Services.</p>
    <p><b>Operational practices.</b> We use logging and monitoring, a secure development lifecycle, dependency hygiene, and an incident-response process. Subprocessors are listed in our Privacy Policy and DPA.</p>

    <h2>What you control</h2>
    <p>Because records are signed with your keys, the integrity of your evidence depends on your key management: generation, custody, rotation, and revocation. You are also responsible for your account access, redaction and retention configuration, and for executing a Business Associate Agreement before processing PHI.</p>

    <h2>Reporting a vulnerability</h2>
    <p>If you believe you have found a security vulnerability in the Services or this website, please report it to <a href="mailto:security@vindicara.io">security@vindicara.io</a>. A PGP key is available on request for sensitive reports. Please include enough detail to reproduce the issue (affected URL or component, steps, and impact).</p>
    <p>What to expect: we aim to acknowledge reports within 3 business days, provide an initial assessment within 10 business days, and keep you informed through remediation. With your permission, we are glad to credit researchers who report valid issues.</p>

    <h2>Disclosure guidelines and safe harbor</h2>
    <p>We support good-faith security research. When testing, please: only target assets you are authorized to test (the Services and vindicara.io); do not access, modify, or exfiltrate data that is not yours; do not run denial-of-service tests, send spam, or use social engineering or physical attacks; and give us reasonable time to remediate before public disclosure. If you make a good-faith effort to comply with these guidelines, we will not pursue or support legal action against you for your research, and we will work with you to understand and resolve the issue quickly. This safe harbor does not authorize actions that violate the privacy of, or cause harm to, our customers or third parties.</p>

    <h2>Compliance posture</h2>
    <p>We sign Business Associate Agreements for HIPAA-regulated workloads and offer a Data Processing Addendum with Standard Contractual Clauses for GDPR/UK transfers. The Services produce conformity and audit evidence mapped to frameworks such as the EU AI Act, NIST AI RMF, and HIPAA; these are evidence inputs, not certifications, and admissibility or sufficiency is determined by the relevant authority.</p>

    <div class="links">
      <a href="/privacy">Privacy Policy</a><a href="/dpa">DPA</a><a href="/terms">Terms</a><a href="mailto:security@vindicara.io">security@vindicara.io</a>
    </div>
  </div>
</AppShell>

<style>
  .prose h1{font-size:36px;margin:14px 0 0}
  .prose h2{font-size:18px;margin:26px 0 0}
  .lede{font-size:15px;color:var(--white);line-height:1.65;margin:16px 0 4px;font-family:var(--display)}
  .muted{color:var(--faint);font-family:var(--mono);font-size:12px;margin-top:8px}
  .prose p{font-size:13.5px;color:var(--soft);line-height:1.7;margin-top:8px}
  .prose a{color:var(--air2);text-decoration:none} .prose a:hover{text-decoration:underline}
  .links{display:flex;gap:18px;margin-top:28px;font-family:var(--mono);font-size:12px;flex-wrap:wrap}
</style>
