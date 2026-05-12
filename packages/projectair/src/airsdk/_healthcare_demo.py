"""Healthcare clinical decision support demo for ``air demo --healthcare``.

A clinical AI agent reviews a patient's lab results, imaging report, and
medication history, then generates a treatment recommendation. The agent
attempts to access a restricted psychiatric record (blocked by containment
policy), and a clinician must approve via Auth0 before the agent can view
sensitive oncology pathology results.

Demonstrates HIPAA-relevant audit capabilities:
- 45 CFR 164.312(b): every PHI access is a signed capsule with timestamp
- 45 CFR 164.312(c): BLAKE3 + Ed25519 tamper-evident chain
- 45 CFR 164.312(d): Auth0-verified clinician identity in the chain
- 45 CFR 164.502(b): minimum necessary enforcement via containment policy
- ONC HTI-1: causal reasoning explains every recommendation

Fourteen records, one patient journey, full forensic chain.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from airsdk.agdr import Signer
from airsdk.types import AgDRPayload, StepKind

HEALTHCARE_DEMO_USER_INTENT = (
    "Review patient MRN-20260511-0042 and recommend next steps for "
    "elevated HbA1c with new pulmonary nodule on chest CT."
)

_PATIENT_LABS = (
    "Patient: [REDACTED] | MRN: 20260511-0042 | DOB: [REDACTED]\n"
    "Provider: Dr. Sarah Chen, Internal Medicine\n"
    "Date: 2026-05-10\n\n"
    "CBC: WBC 7.2, Hgb 13.1, Plt 245 (all within normal limits)\n"
    "BMP: Na 140, K 4.1, Cr 0.9, BUN 14, Glucose 186 (H)\n"
    "HbA1c: 8.4% (H, target <7.0%)\n"
    "Lipid Panel: LDL 142 (H), HDL 38 (L), TG 210 (H)\n"
    "TSH: 2.1 (normal)\n"
    "eGFR: 88 (mildly decreased)"
)

_IMAGING_REPORT = (
    "CHEST CT WITH CONTRAST | 2026-05-09\n"
    "Clinical indication: persistent cough, smoking history\n\n"
    "Findings:\n"
    "- 12mm solid pulmonary nodule in right upper lobe (new)\n"
    "- No mediastinal lymphadenopathy\n"
    "- No pleural effusion\n"
    "- Heart size normal\n\n"
    "Impression: New 12mm RUL pulmonary nodule. Recommend PET-CT for "
    "further characterization given smoking history.\n\n"
    "Radiologist: Dr. James Park, MD"
)

_MEDICATION_LIST = (
    "Active Medications:\n"
    "1. Metformin 1000mg BID (diabetes)\n"
    "2. Lisinopril 10mg daily (hypertension)\n"
    "3. Atorvastatin 20mg daily (hyperlipidemia)\n"
    "4. Aspirin 81mg daily (cardiovascular prophylaxis)"
)

_PSYCHIATRIC_RECORD = "[RESTRICTED: Behavioral Health - 42 CFR Part 2]"

_CLINICAL_RECOMMENDATION = (
    "Clinical Decision Support Summary for MRN 20260511-0042:\n\n"
    "1. DIABETES MANAGEMENT (HbA1c 8.4%):\n"
    "   - Current metformin monotherapy is insufficient\n"
    "   - Recommend adding GLP-1 agonist (semaglutide) per ADA 2026 guidelines\n"
    "   - Recheck HbA1c in 3 months\n"
    "   - Refer to diabetes educator\n\n"
    "2. PULMONARY NODULE (12mm RUL, new):\n"
    "   - HIGH PRIORITY: order PET-CT within 2 weeks\n"
    "   - Fleischner Society guidelines: solid nodule >8mm with risk factors "
    "warrants PET-CT or tissue sampling\n"
    "   - Smoking cessation counseling (document in chart)\n"
    "   - Pulmonology referral\n\n"
    "3. CARDIOVASCULAR RISK:\n"
    "   - LDL 142 on atorvastatin 20mg: consider uptitration to 40mg\n"
    "   - HDL 38: lifestyle modification counseling\n"
    "   - 10-year ASCVD risk: elevated (diabetes + smoking + dyslipidemia)\n\n"
    "Evidence basis: ADA Standards of Care 2026, Fleischner Society 2017 "
    "guidelines, ACC/AHA cholesterol guidelines 2018.\n\n"
    "NOTE: This is AI-generated clinical decision support. All recommendations "
    "require independent clinician review before action."
)

HEALTHCARE_DEMO_STEPS: list[tuple[StepKind, dict[str, Any]]] = [
    (StepKind.LLM_START, {"prompt": HEALTHCARE_DEMO_USER_INTENT}),
    (StepKind.LLM_END, {
        "response": (
            "I will review the patient's recent labs, imaging, and "
            "medications to formulate a recommendation. Let me pull "
            "the records from the EHR."
        ),
    }),
    (StepKind.TOOL_START, {
        "tool_name": "ehr_query",
        "tool_args": {"mrn": "20260511-0042", "record_type": "lab_results", "date_range": "2026-05-01/2026-05-10"},
    }),
    (StepKind.TOOL_END, {"tool_output": _PATIENT_LABS}),
    (StepKind.TOOL_START, {
        "tool_name": "ehr_query",
        "tool_args": {"mrn": "20260511-0042", "record_type": "imaging", "date_range": "2026-05-01/2026-05-10"},
    }),
    (StepKind.TOOL_END, {"tool_output": _IMAGING_REPORT}),
    (StepKind.TOOL_START, {
        "tool_name": "ehr_query",
        "tool_args": {"mrn": "20260511-0042", "record_type": "medications"},
    }),
    (StepKind.TOOL_END, {"tool_output": _MEDICATION_LIST}),
    # The agent tries to access psychiatric records. This is a minimum
    # necessary violation: psychiatric notes are not relevant to the
    # diabetes/pulmonology review and are protected under 42 CFR Part 2.
    # AIR's containment policy blocks the access. ASI02 fires.
    (StepKind.TOOL_START, {
        "tool_name": "ehr_query",
        "tool_args": {"mrn": "20260511-0042", "record_type": "psychiatric_notes"},
    }),
    (StepKind.TOOL_END, {"tool_output": _PSYCHIATRIC_RECORD}),
    # The agent feeds all gathered data to the LLM for synthesis.
    (StepKind.LLM_START, {
        "prompt": (
            f"Patient labs:\n{_PATIENT_LABS}\n\n"
            f"Imaging:\n{_IMAGING_REPORT}\n\n"
            f"Medications:\n{_MEDICATION_LIST}\n\n"
            "Based on these findings, provide a clinical decision support "
            "summary with recommended next steps, citing relevant clinical "
            "guidelines. Flag any urgent findings."
        ),
    }),
    (StepKind.LLM_END, {"response": _CLINICAL_RECOMMENDATION}),
    (StepKind.TOOL_START, {
        "tool_name": "ehr_write",
        "tool_args": {
            "mrn": "20260511-0042",
            "note_type": "ai_clinical_decision_support",
            "content_preview": "CDS summary: GLP-1 addition, PET-CT referral, statin uptitration",
        },
    }),
    (StepKind.AGENT_FINISH, {
        "final_output": (
            "Clinical decision support note written to chart for "
            "MRN 20260511-0042. Flagged: 12mm pulmonary nodule requires "
            "PET-CT within 2 weeks. All recommendations pending clinician "
            "review and co-signature."
        ),
    }),
]

HEALTHCARE_DEMO_TAMPER_INDEX = 3


def build_healthcare_demo_log(
    path: str | Path,
    signer: Signer | None = None,
) -> Signer:
    """Sign and write the healthcare demo chain to ``path``."""
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    active_signer = signer if signer is not None else Signer.generate()

    with out_path.open("w", encoding="utf-8") as handle:
        for kind, fields in HEALTHCARE_DEMO_STEPS:
            payload = AgDRPayload.model_validate({
                "user_intent": HEALTHCARE_DEMO_USER_INTENT,
                **fields,
            })
            record = active_signer.sign(kind=kind, payload=payload)
            handle.write(record.model_dump_json(exclude_none=True))
            handle.write("\n")

    return active_signer
