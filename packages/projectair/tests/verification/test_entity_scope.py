"""Tests for EntityScope-based entity verification."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from airsdk.types import EntityScope, IntentSpec


def test_entity_scope_static() -> None:
    scope = EntityScope(scope_type="static")
    assert scope.scope_type == "static"


def test_entity_scope_facility() -> None:
    scope = EntityScope(
        scope_type="facility",
        facility="HOSP-MAIN",
        unit="5-EAST",
        time_window_hours=12,
    )
    assert scope.facility == "HOSP-MAIN"
    assert scope.unit == "5-EAST"


def test_entity_scope_roster() -> None:
    scope = EntityScope(
        scope_type="roster",
        roster_source="fhir://hospital.org/List/icu-active",
        refresh_interval_seconds=300,
    )
    assert scope.roster_source is not None


def test_entity_scope_predicate() -> None:
    scope = EntityScope(
        scope_type="predicate",
        predicate="message_type == 'ORU^R01' AND ordering_service == 'ENDO'",
    )
    assert scope.predicate is not None


def test_intent_spec_allows_entity_scope_alone() -> None:
    spec = IntentSpec(
        goal="Monitor ward 5-East",
        entity_scope=EntityScope(scope_type="facility", facility="HOSP-MAIN"),
    )
    assert spec.entity_scope is not None
    assert spec.allowed_entities == []


def test_intent_spec_allows_entities_alone() -> None:
    spec = IntentSpec(
        goal="Review patient MRN-0042",
        allowed_entities=["MRN-0042"],
    )
    assert spec.entity_scope is None


def test_intent_spec_entities_and_scope_exclusive() -> None:
    with pytest.raises(ValidationError, match="mutually exclusive"):
        IntentSpec(
            goal="test",
            allowed_entities=["MRN-0042"],
            entity_scope=EntityScope(scope_type="facility", facility="X"),
        )


def test_facility_scope_matches_facility() -> None:
    scope = EntityScope(scope_type="facility", facility="HOSP-MAIN")
    assert scope.matches_facility("HOSP-MAIN")
    assert not scope.matches_facility("OTHER-HOSP")


def test_non_facility_scope_matches_any() -> None:
    scope = EntityScope(scope_type="roster", roster_source="fhir://x")
    assert scope.matches_facility("ANY-FACILITY")
