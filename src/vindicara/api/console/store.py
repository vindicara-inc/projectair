"""In-memory Flightdeck workspace state backed by live engine reads."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from vindicara.api.console.fixtures import READINESS_QUESTIONS, plugin_catalog
from vindicara.api.console.ops_proof import fetch_ops_manifest, proof_payload
from vindicara.compliance.frameworks import list_frameworks
from vindicara.sdk.exceptions import PolicyNotFoundError

if TYPE_CHECKING:
    from vindicara.api.console.auth import OperatorContext
    from vindicara.engine.policy import PolicyRegistry
    from vindicara.identity.models import AgentIdentity
    from vindicara.identity.registry import AgentRegistry


@dataclass
class FlightdeckStore:
    revoked_agents: set[str] = field(default_factory=set)
    resolved_findings: set[str] = field(default_factory=set)
    transport: dict[str, bool] = field(
        default_factory=lambda: {
            "Signed evidence pack": True,
            "Posture feed": True,
            "Incident reconstruction": True,
            "Raw PHI / payloads": False,
        }
    )
    consents: list[dict[str, str]] = field(default_factory=list)
    plugin_connected: set[str] = field(default_factory=set)

    def revoke_delegation(self, agent: str) -> None:
        self.revoked_agents.add(agent)

    def act_on_finding(self, finding_id: str) -> None:
        self.resolved_findings.add(finding_id)

    def set_transport(self, label: str, on: bool) -> None:
        if label == "Raw PHI / payloads" and on:
            msg = "Raw PHI transport cannot be enabled"
            raise ValueError(msg)
        if label not in self.transport:
            msg = f"Unknown transport channel: {label}"
            raise ValueError(msg)
        self.transport[label] = on

    def revoke_consent(self, carrier: str) -> None:
        for consent in self.consents:
            if consent["carrier"] == carrier:
                consent["status"] = "revoked"
                return
        msg = f"Unknown carrier consent: {carrier}"
        raise ValueError(msg)

    def connect_plugin(self, plugin_id: str) -> None:
        self.plugin_connected.add(plugin_id)

    def overview(self, registry: AgentRegistry, operator: OperatorContext) -> dict[str, object]:
        manifest, manifest_error = fetch_ops_manifest()
        agents = registry.list_agents()
        delegations = self._delegations(agents)
        findings = self._findings(agents)
        covered = sum(1 for d in delegations if d["status"] == "covered")
        proof = proof_payload(manifest, manifest_error)
        return {
            "stats": [
                {"label": "Active delegations", "value": str(covered), "meta": "live grants", "tone": "vio"},
                {
                    "label": "Chains anchored",
                    "value": (
                        f"{int(proof['records']):,}"
                        if int(proof["records"]) > 0
                        else "live"
                    ),
                    "meta": "0 tampered" if proof["chainIntact"] else "check manifest",
                    "tone": "teal",
                },
                {
                    "label": "Open findings",
                    "value": str(len(findings)),
                    "meta": self._finding_meta(findings),
                    "tone": "amber",
                },
                {"label": "Registered agents", "value": str(len(agents)), "meta": "identity registry", "tone": "blue"},
            ],
            "delegations": delegations,
            "enforcement": self._enforcement(agents),
            "findings": findings,
            "proof": proof,
            "operator": self._operator(operator, covered),
        }

    def readiness(self) -> dict[str, object]:
        questions = READINESS_QUESTIONS
        score_yes = sum(1 for q in questions if q.get("status") == "yes")
        score_total = len(questions)
        pct = round(100 * score_yes / score_total) if score_total else 0
        frameworks = list_frameworks()
        rings = [
            {
                "framework": fw.name,
                "detail": f"{fw.control_count} controls mapped",
                "pct": pct,
                "state": "good" if pct >= 90 else "progress",
            }
            for fw in frameworks[:4]
        ]
        return {"scoreYes": score_yes, "scoreTotal": score_total, "questions": questions, "compliance": rings}

    def rules(self, registry: PolicyRegistry) -> dict[str, object]:
        infos = registry.list_policies()
        rulesets = [{"id": info.policy_id, "name": f"{info.policy_id}.md", "layer": "policy"} for info in infos]
        if infos:
            selected = self.rule_doc(registry, infos[0].policy_id)
        else:
            selected = {
                "id": "none",
                "name": "no-policies.md",
                "layerNote": "no policies registered",
                "content": "# No policies registered\n# Register a policy through the engine to see it here.",
            }
        return {"rulesets": rulesets, "selected": selected}

    def rule_doc(self, registry: PolicyRegistry, rule_id: str) -> dict[str, str]:
        try:
            policy = registry.get(rule_id)
        except PolicyNotFoundError:
            return {
                "id": rule_id,
                "name": f"{rule_id}.md",
                "layerNote": "not found",
                "content": f"# {rule_id}\n# policy not found in the engine registry",
            }
        rule_lines = "\n".join(f"  - {rule.rule_id}" for rule in policy.rules)
        content = (
            f"# {policy.name}   id: {policy.policy_id}   v{policy.version}\n"
            f"# {policy.description}\n"
            f"enabled: {str(policy.enabled).lower()}\n"
            f"rules:\n{rule_lines}"
        )
        return {
            "id": policy.policy_id,
            "name": f"{policy.policy_id}.md",
            "layerNote": f"{len(policy.rules)} rules, {'enabled' if policy.enabled else 'disabled'}",
            "content": content,
        }

    def plugins(self) -> dict[str, list[dict[str, object]]]:
        catalog = plugin_catalog()
        for group in catalog.values():
            for plugin in group:
                pid = str(plugin["id"])
                plugin["status"] = "connected" if pid in self.plugin_connected else plugin["status"]
        return catalog

    def insurance(self) -> dict[str, object]:
        active = sum(1 for c in self.consents if c["status"] == "active")
        pending = sum(1 for c in self.consents if c["status"] == "pending")
        transport = [
            {"label": label, "detail": detail, "on": self.transport[label], "locked": locked}
            for label, detail, locked in (
                ("Signed evidence pack", "FRE 902(13) self-authenticating, hash-only", False),
                ("Posture feed", "delegation coverage, findings, anchoring health", False),
                ("Incident reconstruction", "causal replay + qualified-person attestation", False),
                ("Raw PHI / payloads", "never leaves your VPC; redacted by default", True),
            )
        ]
        return {
            "transport": transport,
            "consents": self.consents,
            "connectedActive": active,
            "connectedPending": pending,
            "lastPackSent": "Coalition · live API" if active else "none",
            "format": "AIR evidence API v1",
            "premiumSignal": "strong" if active else "adequate",
        }

    def settings(self, operator: OperatorContext) -> dict[str, object]:
        return {
            "plan": "Enterprise plan",
            "sections": [
                {
                    "title": "Organization",
                    "accent": "var(--vio)",
                    "rows": [
                        {"label": "Legal entity", "detail": "Delaware C-Corp", "kind": "value", "value": "Vindicara Inc."},
                        {"label": "Workspace", "kind": "value", "value": "vindicara.io"},
                        {"label": "Operator", "kind": "value", "value": operator.name},
                    ],
                },
                {
                    "title": "Identity & security",
                    "accent": "var(--blue)",
                    "rows": [
                        {"label": "SSO via Auth0", "detail": "org-wide single sign-on", "kind": "toggle", "on": True, "accent": "vio"},
                        {"label": "Session subject", "kind": "value", "value": operator.sub},
                    ],
                },
            ],
        }

    def _delegations(self, agents: list[AgentIdentity]) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        for agent in agents:
            if agent.agent_id in self.revoked_agents or agent.is_suspended:
                status = "uncovered"
                expires = "revoked"
            elif agent.is_active:
                status = "covered"
                expires = "active"
            else:
                status = "expired"
                expires = "renew"
            rows.append(
                {
                    "authorizer": {"name": "registry", "role": "AIR identity", "sub": "system|registry"},
                    "agent": agent.name,
                    "policy": "company-floor",
                    "method": "auth0",
                    "expires": expires,
                    "status": status,
                }
            )
        if not rows:
            rows.append(
                {
                    "authorizer": {"name": "none", "role": "no agents registered", "sub": ""},
                    "agent": "register via /v1/agents",
                    "policy": None,
                    "method": "none",
                    "expires": "—",
                    "status": "uncovered",
                }
            )
        return rows

    def _findings(self, agents: list[AgentIdentity]) -> list[dict[str, object]]:
        findings: list[dict[str, object]] = []
        for agent in agents:
            if agent.agent_id in self.resolved_findings:
                continue
            if agent.is_suspended:
                fid = f"suspend-{agent.agent_id}"
                findings.append(self._finding(fid, "high", f"{agent.name} is suspended", "SV-SCOPE", "contained"))
            elif agent.agent_id in self.revoked_agents:
                fid = f"revoke-{agent.agent_id}"
                findings.append(self._finding(fid, "critical", f"{agent.name} delegation revoked", "SV-AUTH-01", "awaiting"))
        return findings

    @staticmethod
    def _finding(fid: str, severity: str, title: str, check: str, state: str) -> dict[str, object]:
        awaiting = state == "awaiting"
        return {
            "id": fid,
            "severity": severity,
            "title": title,
            "check": check,
            "response": {
                "state": state,
                "label": "Awaiting your decision" if awaiting else "AIR contained the agent",
            },
            "actions": [
                {"label": "Revoke", "intent": "revoke", "tone": "crit"},
                {"label": "Evidence", "intent": "evidence", "tone": "ok"},
            ],
        }

    @staticmethod
    def _enforcement(agents: list[AgentIdentity]) -> list[dict[str, str]]:
        events: list[dict[str, str]] = []
        for agent in agents[:4]:
            if agent.is_suspended:
                events.append({"kind": "blocked", "text": f"<b>Blocked</b> tool call · {agent.name}", "at": "live"})
            else:
                events.append({"kind": "verified", "text": f"<b>Verified</b> {agent.name} within scope", "at": "live"})
        if not events:
            events.append({"kind": "sealed", "text": "<b>Sealed</b> ops chain anchor ready", "at": "live"})
        return events

    @staticmethod
    def _finding_meta(findings: list[dict[str, object]]) -> str:
        crit = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        return f"{high} high · {crit} critical"

    @staticmethod
    def _operator(operator: OperatorContext, grants: int) -> dict[str, object]:
        remaining = max(0, operator.session_expires_at - int(time.time()))
        minutes = f"{remaining // 60}m" if remaining else "session"
        return {
            "name": operator.name,
            "role": "Flightdeck operator",
            "authMethod": "auth0",
            "sessionExpires": minutes,
            "grantsAuthorized": grants,
        }
