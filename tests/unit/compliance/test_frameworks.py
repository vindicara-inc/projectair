"""Tests for compliance framework definitions."""

from vindicara.compliance.frameworks import (
    FRAMEWORKS,
    get_framework,
    get_framework_info,
    list_frameworks,
)
from vindicara.compliance.models import ComplianceFramework


class TestFrameworks:
    def test_four_frameworks_defined(self) -> None:
        assert len(FRAMEWORKS) == 4

    def test_eu_ai_act_has_8_controls(self) -> None:
        fw = get_framework(ComplianceFramework.EU_AI_ACT_ARTICLE_72)
        assert len(fw.controls) == 8

    def test_nist_has_8_controls(self) -> None:
        fw = get_framework(ComplianceFramework.NIST_AI_RMF)
        assert len(fw.controls) == 8

    def test_soc2_has_8_controls(self) -> None:
        fw = get_framework(ComplianceFramework.SOC2_AI)
        assert len(fw.controls) == 8

    def test_hipaa_has_8_controls(self) -> None:
        fw = get_framework(ComplianceFramework.HIPAA_SECURITY)
        assert len(fw.controls) == 8
        assert fw.version == "2026-nprm"

    def test_hipaa_control_ids_are_sequential(self) -> None:
        fw = get_framework(ComplianceFramework.HIPAA_SECURITY)
        ids = [c.control_id for c in fw.controls]
        assert ids == [f"HIPAA-{i}" for i in range(1, 9)]

    def test_get_framework_info(self) -> None:
        info = get_framework_info(ComplianceFramework.EU_AI_ACT_ARTICLE_72)
        assert info.name == "EU AI Act Article 72"
        assert info.control_count == 8
        assert info.version == "1.0"

    def test_hipaa_framework_info(self) -> None:
        info = get_framework_info(ComplianceFramework.HIPAA_SECURITY)
        assert info.name == "HIPAA Security Rule (2026 NPRM)"
        assert info.control_count == 8
        assert info.version == "2026-nprm"

    def test_list_frameworks(self) -> None:
        frameworks = list_frameworks()
        assert len(frameworks) == 4
        ids = {f.framework_id for f in frameworks}
        assert ComplianceFramework.EU_AI_ACT_ARTICLE_72 in ids
        assert ComplianceFramework.NIST_AI_RMF in ids
        assert ComplianceFramework.SOC2_AI in ids
        assert ComplianceFramework.HIPAA_SECURITY in ids

    def test_all_controls_have_required_evidence(self) -> None:
        for fw in FRAMEWORKS.values():
            for ctrl in fw.controls:
                assert len(ctrl.required_evidence_types) > 0
                assert ctrl.min_evidence_count >= 1
