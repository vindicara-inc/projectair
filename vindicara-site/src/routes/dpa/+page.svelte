<script>
  import AppShell from '$components/AppShell.svelte';
</script>
<svelte:head><title>Vindicara · Data Processing Addendum</title></svelte:head>

<AppShell active="dpa" title="dpa" scroll={true}>
  <div class="prose">
    <div class="eyebrow">Data protection</div>
    <h1>Data Processing Addendum.</h1>
    <p class="muted">Last updated: June 6, 2026</p>

    <p class="lede">This Data Processing Addendum ("DPA") forms part of the Terms of Service between Vindicara, Inc. ("Vindicara," "Processor") and the customer agreeing to those Terms ("Customer," "Controller") and applies to the Processing of Personal Data by Vindicara on Customer's behalf through the Hosted Services. Where Customer is itself a processor acting for a third-party controller, references to Controller apply to that third party and Customer is the intermediary. To execute a countersigned copy, contact legal@vindicara.io.</p>

    <h2>1. Definitions</h2>
    <p>"Applicable Data Protection Law" means all laws and regulations applicable to the Processing of Personal Data under this DPA, including the EU General Data Protection Regulation 2016/679 ("GDPR"), the UK GDPR and Data Protection Act 2018, and the California Consumer Privacy Act as amended by the CPRA ("CCPA"). "Personal Data," "Processing," "Controller," "Processor," "Data Subject," and "Personal Data Breach" have the meanings given in Applicable Data Protection Law. "Customer Personal Data" means Personal Data contained in Customer Data that Vindicara Processes on Customer's behalf. "Subprocessor" means a third party engaged by Vindicara to Process Customer Personal Data. "Standard Contractual Clauses" or "SCCs" means the clauses approved by the European Commission for transfers of Personal Data to third countries.</p>

    <h2>2. Roles and Scope of Processing</h2>
    <p>As between the parties, Customer is the Controller (or processor) of Customer Personal Data and Vindicara is the Processor. Vindicara will Process Customer Personal Data only (a) to provide, secure, and support the Services in accordance with the Terms, (b) on Customer's documented instructions (including via configuration and use of the Services), and (c) as required by law, in which case Vindicara will inform Customer unless legally prohibited. The subject matter, duration, nature, purpose, categories of Personal Data, and categories of Data Subjects are described in Annex 1. Vindicara will inform Customer if, in its opinion, an instruction infringes Applicable Data Protection Law.</p>

    <h2>3. Customer Responsibilities</h2>
    <p>Customer is responsible for the lawfulness of Customer Personal Data and of Customer's instructions, including having a valid legal basis, providing required notices to Data Subjects, and configuring redaction, retention, and anchoring appropriately. Customer must not submit special-category data or protected health information except as permitted by the Services and, for PHI, under a separate Business Associate Agreement.</p>

    <h2>4. Confidentiality</h2>
    <p>Vindicara will ensure that personnel authorized to Process Customer Personal Data are subject to binding confidentiality obligations and have received appropriate data-protection training.</p>

    <h2>5. Security Measures</h2>
    <p>Vindicara will implement and maintain appropriate technical and organizational measures designed to protect Customer Personal Data, taking into account the state of the art and the risks of Processing, as described in Annex 2 and on our Security page. These include encryption in transit and at rest, least-privilege access controls, authenticated access, default-deny redaction of published payloads, and tamper-evident signed records. Vindicara may update its measures provided that the level of protection is not materially decreased.</p>

    <h2>6. Subprocessors</h2>
    <p>Customer provides general authorization for Vindicara to engage Subprocessors to Process Customer Personal Data. Vindicara maintains a current list of Subprocessors (including Amazon Web Services, Auth0, Stripe, and Sigstore Rekor and a timestamp authority) available on request, imposes data-protection obligations on each Subprocessor no less protective than this DPA, and remains responsible for each Subprocessor's performance. Vindicara will give Customer notice of any intended addition or replacement of a Subprocessor, and Customer may object on reasonable data-protection grounds, in which case the parties will work in good faith to resolve the objection.</p>

    <h2>7. Data Subject Requests</h2>
    <p>Taking into account the nature of the Processing, Vindicara will assist Customer by appropriate technical and organizational measures, insofar as possible, to respond to requests from Data Subjects to exercise their rights. If Vindicara receives such a request directly, it will, where legally permitted, direct the Data Subject to Customer.</p>

    <h2>8. Personal Data Breach</h2>
    <p>Vindicara will notify Customer without undue delay after becoming aware of a Personal Data Breach affecting Customer Personal Data, and will provide information reasonably available to it to help Customer meet its breach-notification obligations, and will take reasonable steps to mitigate and remediate.</p>

    <h2>9. Data Protection Impact Assessments</h2>
    <p>Vindicara will provide reasonable assistance to Customer with data protection impact assessments and prior consultations with supervisory authorities, taking into account the nature of Processing and information available to Vindicara.</p>

    <h2>10. International Transfers</h2>
    <p>Vindicara Processes Customer Personal Data primarily in the United States. Where the transfer of Customer Personal Data from the EEA, UK, or Switzerland is subject to Applicable Data Protection Law, the SCCs (and the UK Addendum where applicable) are incorporated into this DPA by reference and apply to that transfer, with Customer as data exporter and Vindicara as data importer.</p>

    <h2>11. Return and Deletion</h2>
    <p>Upon termination of the Services and on Customer's request, Vindicara will delete or return Customer Personal Data within the period described in the Terms, except (a) hashes already published to public transparency logs, which are immutable, and (b) data Vindicara is required to retain by law, which it will continue to protect.</p>

    <h2>12. Audits</h2>
    <p>Vindicara will make available information reasonably necessary to demonstrate compliance with this DPA and will allow for and contribute to audits, including inspections, conducted by Customer or an auditor mandated by Customer, subject to reasonable confidentiality, scope, frequency, notice, and security conditions. Vindicara may satisfy audit requests by providing third-party reports or certifications where available.</p>

    <h2>13. California (CCPA)</h2>
    <p>For Personal Data subject to the CCPA, Vindicara acts as a "service provider." Vindicara will not sell or share such Personal Data, will not retain, use, or disclose it except for the limited business purpose of providing the Services or as permitted by the CCPA, and will not combine it with data from other sources except as permitted. Vindicara certifies that it understands and will comply with these restrictions.</p>

    <h2>14. Liability and Precedence</h2>
    <p>Each party's liability under this DPA is subject to the limitations and exclusions in the Terms. In the event of a conflict between this DPA and the Terms regarding the Processing of Personal Data, this DPA controls; the SCCs control over both with respect to transfers they govern.</p>

    <h2>Annex 1 — Description of Processing</h2>
    <p><b>Subject matter:</b> provision of the Hosted Services. <b>Duration:</b> the term of the Services plus the post-termination period in the Terms. <b>Nature and purpose:</b> hosting, recording, signing, anchoring, analyzing, and producing evidence from agent activity to provide accountability, detection, and compliance-evidence features. <b>Categories of Personal Data:</b> account and authentication identifiers; billing metadata; usage and device data; and any Personal Data contained in Customer-submitted agent traces and decision records (which Customer controls; published records are redacted to hashes by default). <b>Categories of Data Subjects:</b> Customer's authorized users and administrators, and individuals referenced in Customer Data.</p>

    <h2>Annex 2 — Technical and Organizational Measures</h2>
    <p>Encryption of data in transit (TLS) and at rest; least-privilege, role-based access control; authentication via Auth0; default-deny redaction of published payloads; tamper-evident, cryptographically signed and hash-chained records; logging and monitoring; secrets management; secure SDLC and dependency hygiene; and incident response. Further detail is on the Security page.</p>

    <h2>Annex 3 — Subprocessors</h2>
    <p>Amazon Web Services (cloud hosting; primary region US-West-2); Auth0 (authentication and identity); Stripe (payment processing); Sigstore Rekor and an RFC 3161 timestamp authority (public anchoring of hashes and timestamps). A current, detailed list is available on request.</p>

    <div class="links">
      <a href="/terms">Terms of Service</a><a href="/privacy">Privacy Policy</a><a href="/security">Security</a><a href="mailto:legal@vindicara.io?subject=DPA%20execution">Execute a DPA</a>
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
