"""Chain indexer: walks AgDR chains and extracts data access records."""
from __future__ import annotations

import re
from collections import defaultdict

from airsdk.types import AgDRRecord, StepKind

from airsdk_pro.governance.registry import DataAssetRegistry
from airsdk_pro.governance.types import AccessType, DataAccessRecord, GovernanceIndex

_READ_PATTERNS = re.compile(r"read|get|fetch|query|select|list|describe|scan", re.IGNORECASE)
_WRITE_PATTERNS = re.compile(r"write|put|insert|update|create|set|upload|post", re.IGNORECASE)
_DELETE_PATTERNS = re.compile(r"delete|remove|drop|purge|destroy|truncate", re.IGNORECASE)


def _infer_access_type(tool_name: str, tool_args: dict[str, object] | None) -> AccessType:
    if tool_args and "access_type" in tool_args:
        raw = str(tool_args["access_type"]).lower()
        try:
            return AccessType(raw)
        except ValueError:
            pass
    if _DELETE_PATTERNS.search(tool_name):
        return AccessType.DELETE
    if _WRITE_PATTERNS.search(tool_name):
        return AccessType.WRITE
    if _READ_PATTERNS.search(tool_name):
        return AccessType.READ
    return AccessType.UNKNOWN


def _find_approval(
    records: list[AgDRRecord],
    challenge_id: str,
    start_idx: int,
) -> AgDRRecord | None:
    for rec in records[start_idx:]:
        if rec.kind != StepKind.HUMAN_APPROVAL:
            continue
        if rec.payload.human_approval and rec.payload.human_approval.challenge_id == challenge_id:
            return rec
    return None


def index_chains(
    chains: list[list[AgDRRecord]],
    registry: DataAssetRegistry | None = None,
) -> GovernanceIndex:
    """Walk chains and build a governance index of data accesses."""
    accesses: list[DataAccessRecord] = []
    by_subject: dict[str, list[int]] = defaultdict(list)
    by_asset: dict[str, list[int]] = defaultdict(list)
    by_agent: dict[str, list[int]] = defaultdict(list)

    for chain in chains:
        for idx, record in enumerate(chain):
            if record.kind != StepKind.TOOL_START:
                continue
            if record.payload.data_assets is None and record.payload.data_subjects is None:
                continue

            assets = record.payload.data_assets or []
            subjects = record.payload.data_subjects or []

            if registry:
                for asset in assets:
                    defn = registry.lookup(asset.asset_id)
                    if defn and not asset.sensitivity:
                        asset.sensitivity = defn.sensitivity

            policy_decision: str | None = None
            if record.payload.blocked:
                policy_decision = "blocked"
            elif record.payload.challenge_id:
                policy_decision = "stepped_up"
            else:
                policy_decision = "allowed"

            approval = None
            if record.payload.challenge_id:
                approval_rec = _find_approval(chain, record.payload.challenge_id, idx + 1)
                if approval_rec and approval_rec.payload.human_approval:
                    approval = approval_rec.payload.human_approval

            access = DataAccessRecord(
                step_id=record.step_id,
                timestamp=record.timestamp,
                agent_id=record.signer_key,
                tool_name=record.payload.tool_name or "",
                access_type=_infer_access_type(
                    record.payload.tool_name or "",
                    record.payload.tool_args,
                ),
                data_assets=assets,
                data_subjects=subjects,
                identity_proof=record.signer_key,
                policy_decision=policy_decision,
                approval=approval,
            )

            pos = len(accesses)
            accesses.append(access)

            for subject in subjects:
                by_subject[subject.subject_id].append(pos)
            for asset in assets:
                by_asset[asset.asset_id].append(pos)
            by_agent[record.signer_key].append(pos)

    return GovernanceIndex(
        accesses=accesses,
        by_subject=dict(by_subject),
        by_asset=dict(by_asset),
        by_agent=dict(by_agent),
    )
