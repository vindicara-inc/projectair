"""Tests for the OpenLineage exporter."""
from __future__ import annotations

import json

from airsdk_pro.governance.openlineage import export_openlineage, export_openlineage_jsonl
from airsdk_pro.governance.types import GovernanceIndex


class TestOpenLineage:
    def test_export_produces_events(self, sample_index: GovernanceIndex) -> None:
        events = export_openlineage(sample_index, chain_id="test-chain")
        assert len(events) == 2

    def test_event_structure(self, sample_index: GovernanceIndex) -> None:
        events = export_openlineage(sample_index, chain_id="test-chain")
        event = events[0]
        assert event.eventType == "COMPLETE"
        assert event.producer == "https://vindicara.io/air"
        assert event.job.namespace == "air"
        assert event.job.name == "query_patients"
        assert event.run.runId == "test-chain"

    def test_read_produces_inputs(self, sample_index: GovernanceIndex) -> None:
        events = export_openlineage(sample_index, chain_id="test-chain")
        event = events[0]
        assert len(event.inputs) == 1
        assert event.inputs[0].name == "patients"

    def test_jsonl_output(self, sample_index: GovernanceIndex) -> None:
        events = export_openlineage(sample_index, chain_id="test-chain")
        jsonl = export_openlineage_jsonl(events)
        lines = jsonl.strip().split("\n")
        assert len(lines) == 2
        parsed = json.loads(lines[0])
        assert parsed["eventType"] == "COMPLETE"

    def test_containment_facet(self, sample_index: GovernanceIndex) -> None:
        events = export_openlineage(sample_index, chain_id="test-chain")
        facets = events[0].run.facets
        assert "air_containment" in facets
        assert facets["air_containment"]["decision"] == "allowed"
