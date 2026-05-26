"""HL7v2 clinical evidence sidecar (Pro).

Parses HL7v2 messages, maps them to FHIR R4 resources, captures signed
AIR intent capsules for each clinical event, and optionally pushes FHIR
resources to a customer-owned FHIR R4 server.

All clinical chains contain PHI-derived data. A BAA is required before
activating this module. Set ``RedactionPolicy(baa_acknowledged=True)``
and keep ``phi_mode=PHIMode.REDACTED`` unless your deployment has
explicit legal authorization to store raw PHI in the audit chain.
"""
from __future__ import annotations
