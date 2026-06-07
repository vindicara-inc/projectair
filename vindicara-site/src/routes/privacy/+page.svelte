<script>
  import AppShell from '$components/AppShell.svelte';
</script>
<svelte:head><title>Vindicara · Privacy Policy</title></svelte:head>

<AppShell active="privacy" title="privacy" scroll={true}>
  <div class="prose">
    <div class="eyebrow">Privacy</div>
    <h1>Privacy Policy.</h1>
    <p class="muted">Last updated: June 6, 2026</p>

    <p class="lede">This Privacy Policy explains how Vindicara, Inc. ("Vindicara," "we," "us") collects, uses, discloses, and protects personal information in connection with our websites, the open-source air CLI and airsdk, and the hosted FlightDeck and AIR Cloud services (the "Services"). It also explains the choices and rights you have. The open-source software runs locally on your own systems and does not transmit data to us unless you explicitly enable a feature that does so (such as cloud anchoring or AIR Cloud).</p>

    <h2>1. Who is responsible for your data (controller vs. processor)</h2>
    <p>For information about visitors to our websites and account holders of the Hosted Services, Vindicara acts as a <b>controller</b>. For Customer Data that you submit to or generate within the Hosted Services, including agent traces and Evidence Chains, Vindicara acts as a <b>processor</b> that handles that data on your behalf and under your instructions; you are the controller of that data and are responsible for its lawful collection and use. Where we act as a processor of personal data, our Data Processing Addendum (DPA) governs that processing and is available on request.</p>

    <h2>2. Information we collect</h2>
    <p><b>Account and identity information.</b> When you create an account, we (through our identity provider, Auth0) collect your name, email address, organization, role, authentication identifiers, and session metadata.</p>
    <p><b>Billing information.</b> If you purchase a paid plan, our payment processor (Stripe) collects and processes your payment details. We do not receive or store full payment card numbers; we receive limited billing metadata such as plan, status, and the last four digits or a token.</p>
    <p><b>Usage and device information.</b> We collect logs and telemetry about how the Services are used, including IP address, browser and device type, pages and API endpoints accessed, timestamps, and diagnostic information, to operate, secure, and improve the Services.</p>
    <p><b>Communications.</b> When you contact us (for example via the contact form or support and sales email), we collect the information you provide, such as your name, email, company, and message.</p>
    <p><b>Customer Data.</b> The Hosted Services process the agent traces, decision records, and Evidence Chains you submit or generate. This content is controlled by you and may contain personal data or, where you choose to process it, protected health information (PHI). By design, published Evidence Chains apply default-deny redaction so that non-whitelisted payload fields are stored and published as cryptographic hashes rather than cleartext.</p>
    <p><b>Cookies.</b> Our websites and console use strictly necessary cookies for authentication and session management, and may use limited, privacy-preserving analytics. We do not use advertising cookies or sell behavioral data.</p>

    <h2>3. How we use information</h2>
    <p>We use personal information to: provide, operate, secure, and support the Services; authenticate users and manage sessions; process payments and manage subscriptions; communicate with you about your account, support requests, security, and changes to the Services; monitor, prevent, and investigate fraud, abuse, and security incidents; comply with legal obligations and enforce our Terms; and improve the Services, including through aggregated and de-identified analysis. Where required, our legal bases for processing are performance of a contract, our legitimate interests in operating and securing the Services, your consent (which you may withdraw), and compliance with legal obligations.</p>

    <h2>4. Public transparency log (important)</h2>
    <p>If you enable cryptographic anchoring, the Services publish chain roots and hashed identifiers to <b>independent public transparency logs and timestamp authorities</b> (including Sigstore Rekor and an RFC 3161 timestamp authority). These public entries contain hashes, timestamps, and limited metadata, not cleartext personal data, but once published they are <b>immutable and cannot be deleted, modified, or recalled</b>, including in response to an erasure request. Anchoring is a feature you choose to enable; do not anchor records whose hashes or existence you are not permitted to disclose.</p>

    <h2>5. How we share information</h2>
    <p>We do not sell personal information. We share it only as follows: (a) with <b>subprocessors and service providers</b> who process data on our behalf under contract, including Amazon Web Services (hosting; primary region us-west-2), Auth0 (identity), Stripe (payments), and Sigstore Rekor and a timestamp authority (public anchoring of hashes, as described above); (b) to <b>comply with law</b>, legal process, or a lawful government request, or to protect the rights, safety, and security of Vindicara, our users, or the public; and (c) in connection with a <b>merger, acquisition, financing, or sale of assets</b>, subject to the commitments in this Policy. A current list of subprocessors is available on request.</p>

    <h2>6. Data retention</h2>
    <p>We retain account and billing information for as long as your account is active and as needed to comply with legal, tax, and accounting obligations. We retain Customer Data and Evidence Chains for the duration of your subscription and for the post-termination export window described in the Terms, after which we delete them in the ordinary course, except (i) hashes already published to public transparency logs, which are immutable, and (ii) records we are required to retain by law. Logs and telemetry are retained for a limited period consistent with security and operational needs.</p>

    <h2>7. Security</h2>
    <p>We use administrative, technical, and physical safeguards designed to protect personal information, including encryption in transit and at rest, least-privilege access controls, authenticated access via Auth0, default-deny redaction of published payloads, and tamper-evident, signed Evidence Chains. Because records are signed with keys held under your sole control, the integrity of your chains depends on your own key management. No method of transmission or storage is completely secure, and we cannot guarantee absolute security.</p>

    <h2>8. International data transfers</h2>
    <p>We are based in the United States and process data there. If you access the Services from outside the United States, your information may be transferred to and processed in the United States and other countries that may have different data-protection laws. Where required, we rely on appropriate safeguards for international transfers, such as the European Commission's Standard Contractual Clauses, available through our DPA.</p>

    <h2>9. Your rights and choices</h2>
    <p>Depending on where you live, you may have rights to access, correct, delete, port, or restrict the processing of your personal information, to object to certain processing, and to withdraw consent. Residents of the EEA/UK have rights under the GDPR/UK GDPR; residents of California have rights under the CCPA/CPRA, including the right to know, delete, correct, and opt out of "sale" or "sharing" (we do not sell or share personal information as those terms are defined). To exercise rights with respect to data for which we are the controller, contact privacy@vindicara.io. Where we process Customer Data as a processor, please direct data-subject requests to the relevant customer (controller); we will assist them as required by our DPA. We will not discriminate against you for exercising your rights, and you may have the right to appeal or lodge a complaint with a supervisory authority.</p>

    <h2>10. Health information (HIPAA)</h2>
    <p>The Services are not a substitute for your own HIPAA compliance program. Where you use the Services to process PHI, we will, upon execution of a Business Associate Agreement (BAA), act as a Business Associate with respect to that PHI and handle it in accordance with the BAA and applicable law. Absent a signed BAA, you must not submit PHI to the Hosted Services. A standard BAA is available to qualifying customers; contact legal@vindicara.io.</p>

    <h2>11. Children's privacy</h2>
    <p>The Services are intended for businesses and are not directed to children. We do not knowingly collect personal information from anyone under 18. If you believe a child has provided us personal information, contact privacy@vindicara.io and we will delete it.</p>

    <h2>12. Changes to this Policy</h2>
    <p>We may update this Policy from time to time. If we make a material change, we will provide reasonable notice, for example by posting the updated Policy with a new "Last updated" date or by notifying account holders. Your continued use of the Services after the effective date constitutes acceptance of the updated Policy.</p>

    <h2>13. Contact us</h2>
    <p>For privacy questions or to exercise your rights: <a href="mailto:privacy@vindicara.io">privacy@vindicara.io</a>. General support: <a href="mailto:support@vindicara.io">support@vindicara.io</a>. Postal and entity details are available on request. Vindicara, Inc. is a Delaware corporation.</p>

    <div class="links">
      <a href="/terms">Terms of Service</a><a href="/contact">Contact</a><a href="/admissibility">Admissibility</a>
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
  .links{display:flex;gap:18px;margin-top:28px;font-family:var(--mono);font-size:12px}
</style>
