#!/usr/bin/env python3
"""End-to-end governance demo: tag, index, query, DSAR, export."""
from __future__ import annotations

import tempfile
from pathlib import Path

from airsdk.agdr import load_chain
from airsdk.recorder import AIRRecorder
from airsdk.types import DataAssetRef, DataSubjectRef

from airsdk_pro.governance.classifier import classify_sensitivity
from airsdk_pro.governance.dsar import generate_dsar, render_dsar_markdown
from airsdk_pro.governance.indexer import index_chains
from airsdk_pro.governance.openlineage import export_openlineage, export_openlineage_jsonl
from airsdk_pro.governance.query import query_by_subject
from airsdk_pro.governance.registry import AssetDefinition, DataAssetRegistry


def main() -> None:
    tmp = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
    log_path = Path(tmp.name)
    tmp.close()
    rec = AIRRecorder(log_path=log_path)

    rec.llm_start(prompt="Look up patient 42's records and appointments.")
    rec.llm_end(response="I will query the patients table and appointments.")

    rec.tool_start(
        tool_name="query_patients",
        tool_args={"sql": "SELECT * FROM patients WHERE id = 42"},
        data_assets=[DataAssetRef(asset_id="patients", asset_type="table", namespace="clinic_db", sensitivity="restricted")],
        data_subjects=[DataSubjectRef(subject_id="patient-42", subject_type="patient", jurisdiction="HIPAA")],
    )
    rec.tool_end(tool_name="query_patients", tool_output='[{"name": "Jane Doe", "diagnosis": "Type 2 Diabetes"}]')

    rec.tool_start(
        tool_name="read_appointments",
        tool_args={"patient_id": "42"},
        data_assets=[DataAssetRef(asset_id="appointments", asset_type="table", namespace="clinic_db")],
        data_subjects=[DataSubjectRef(subject_id="patient-42", subject_type="patient", jurisdiction="HIPAA")],
    )
    rec.tool_end(tool_name="read_appointments", tool_output='[{"date": "2026-05-20", "doctor": "Dr. Smith"}]')

    rec.tool_start(
        tool_name="write_summary",
        tool_args={"path": "/reports/patient-42-summary.pdf"},
        data_assets=[DataAssetRef(asset_id="reports", asset_type="file", namespace="output")],
        data_subjects=[DataSubjectRef(subject_id="patient-42")],
    )
    rec.tool_end(tool_name="write_summary", tool_output="Written.")
    rec.agent_finish(final_output="Patient summary generated.")

    chain = load_chain(log_path)

    registry = DataAssetRegistry([
        AssetDefinition(id="patients", type="table", namespace="clinic_db", sensitivity="restricted", regulations=["HIPAA"], retention_days=2555),
        AssetDefinition(id="appointments", type="table", namespace="clinic_db", sensitivity="confidential", regulations=["HIPAA"]),
        AssetDefinition(id="reports", type="file", namespace="output", sensitivity="confidential"),
    ])

    idx = index_chains([chain], registry=registry)
    p = lambda msg: __builtins__.__dict__["print"](msg)  # noqa: E731
    p(f"\n=== Governance Index ===")
    p(f"Accesses: {len(idx.accesses)}")
    p(f"Subjects: {list(idx.by_subject.keys())}")
    p(f"Assets:   {list(idx.by_asset.keys())}")

    results = query_by_subject(idx, "patient-42")
    p(f"\n=== Query: patient-42 ===")
    p(f"Found {len(results)} access(es)")

    report = generate_dsar(idx, "patient-42", subject_type="patient", jurisdiction="HIPAA")
    p(f"\n=== DSAR Report ===")
    p(render_dsar_markdown(report))

    events = export_openlineage(idx, chain_id=str(log_path))
    jsonl = export_openlineage_jsonl(events)
    p(f"=== OpenLineage ===")
    p(f"Exported {len(events)} events ({len(jsonl)} bytes)")

    suggestions = classify_sensitivity(chain)
    p(f"\n=== Classifier ===")
    p(f"{len(suggestions)} sensitivity suggestion(s)")
    for s in suggestions:
        p(f"  {s.step_id[:8]}... -> {s.suggested_sensitivity} ({s.suggested_jurisdiction}) [{','.join(s.matched_categories[:3])}]")

    log_path.unlink(missing_ok=True)
    p("\nDone.")


if __name__ == "__main__":
    main()
