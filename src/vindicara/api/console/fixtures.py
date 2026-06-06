"""Static Flightdeck seed content (rules catalog, plugin inventory)."""

from __future__ import annotations

RULE_DOCS: dict[str, dict[str, str]] = {
    "company-floor": {
        "id": "company-floor",
        "name": "company-floor.md",
        "layerNote": "non-overridable · applies to every agent",
        "content": (
            "# company-floor   layer: floor   non-overridable\n"
            "require_delegation: true\nallowed_network:\n  - internal-only\n"
            "secret_access: none\nredaction: default-deny"
        ),
    },
    "hipaa-claims-v3": {
        "id": "hipaa-claims-v3",
        "name": "hipaa-claims-v3.md",
        "layerNote": "inherits company-floor · stricter only",
        "content": (
            "# hipaa-claims-v3   layer: department   inherits: company-floor\n"
            "goal: adjudicate inbound insurance claims\nrequire_delegation: true\n"
            "allowed_tools:\n  - claims.read\n  - claims.adjudicate"
        ),
    },
}


READINESS_QUESTIONS: list[dict[str, str]] = [
    {
        "id": "phi",
        "question": "Is PHI encrypted?",
        "status": "yes",
        "proof": "Default-deny redaction hashes non-whitelisted fields. <b>PHI never enters the evidence chain in the clear.</b>",
    },
    {
        "id": "logs",
        "question": "Can it produce logs?",
        "status": "yes",
        "proof": "Signed AgDR records anchor to Rekor. <b>Immutable audit trail for HIPAA 45 CFR 164.312(b).</b>",
    },
    {
        "id": "access",
        "question": "Does it have access controls?",
        "status": "yes",
        "proof": "Agents run under human delegations on the deterministic floor. <b>Identity via Auth0, Entra, Okta, or SPIFFE.</b>",
    },
    {
        "id": "baa",
        "question": "BAA with hosting?",
        "status": "yes",
        "proof": "Buyer executes BAA with their cloud provider. <b>The signed BAA travels with the audit trail.</b>",
    },
]


def plugin_catalog() -> dict[str, list[dict[str, object]]]:
    def icon(label: str, start: str, end: str) -> dict[str, str]:
        return {"label": label, "from": start, "to": end}

    return {
        "core": [
            {"id": "datadog", "name": "Datadog", "category": "SIEM", "description": "Stream signed records to your SOC.", "status": "available", "icon": icon("D", "#7b4dff", "#a98bff")},
            {"id": "splunk", "name": "Splunk", "category": "SIEM", "description": "Forward findings and chain roots to Splunk.", "status": "available", "icon": icon("S", "#19b27a", "#48e6a4")},
            {"id": "auth0", "name": "Auth0", "category": "Identity", "description": "Bind delegations to verified humans.", "status": "available", "icon": icon("A0", "#e8722a", "#ffb454")},
            {"id": "rekor", "name": "Sigstore Rekor", "category": "Anchoring", "description": "Publicly anchor chain roots.", "status": "available", "icon": icon("SG", "#13c08a", "#6db5ff")},
        ],
        "insurance": [
            {"id": "coalition", "name": "Coalition", "category": "Cyber / AI liability", "description": "Posture and evidence packs for underwriting.", "status": "available", "icon": icon("CO", "#0a6cff", "#5aa0ff")},
        ],
    }
