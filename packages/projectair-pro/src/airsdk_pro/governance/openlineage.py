"""OpenLineage exporter: converts governance data to OpenLineage events."""
from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ConfigDict

from airsdk_pro.governance.types import DataAccessRecord, GovernanceIndex


class OLDataset(BaseModel):
    model_config = ConfigDict(extra="forbid")
    namespace: str
    name: str
    facets: dict[str, Any] = {}


class OLJob(BaseModel):
    model_config = ConfigDict(extra="forbid")
    namespace: str
    name: str
    facets: dict[str, Any] = {}


class OLRun(BaseModel):
    model_config = ConfigDict(extra="forbid")
    runId: str
    facets: dict[str, Any] = {}


class OLRunEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    eventType: str
    eventTime: str
    run: OLRun
    job: OLJob
    inputs: list[OLDataset] = []
    outputs: list[OLDataset] = []
    producer: str


def _access_to_event(
    access: DataAccessRecord,
    chain_id: str,
) -> OLRunEvent:
    inputs: list[OLDataset] = []
    outputs: list[OLDataset] = []

    for asset in access.data_assets:
        ds = OLDataset(
            namespace=asset.namespace or "default",
            name=asset.asset_id,
            facets={"air_sensitivity": {"level": asset.sensitivity}} if asset.sensitivity else {},
        )
        if access.access_type in ("read", "unknown"):
            inputs.append(ds)
        else:
            outputs.append(ds)

    facets: dict[str, Any] = {}
    if access.policy_decision:
        facets["air_containment"] = {"decision": access.policy_decision}
    if access.identity_proof:
        facets["air_identity"] = {"signer_key": access.identity_proof}

    return OLRunEvent(
        eventType="COMPLETE",
        eventTime=access.timestamp,
        run=OLRun(runId=chain_id, facets=facets),
        job=OLJob(
            namespace="air",
            name=access.tool_name,
        ),
        inputs=inputs,
        outputs=outputs,
        producer="https://vindicara.io/air",
    )


def export_openlineage(
    index: GovernanceIndex,
    chain_id: str,
) -> list[OLRunEvent]:
    """Convert all indexed accesses to OpenLineage RunEvents."""
    return [_access_to_event(access, chain_id) for access in index.accesses]


def export_openlineage_jsonl(events: list[OLRunEvent]) -> str:
    """Serialize OpenLineage events to JSONL."""
    lines: list[str] = []
    for event in events:
        lines.append(json.dumps(event.model_dump(), separators=(",", ":")))
    return "\n".join(lines)
