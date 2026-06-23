"""Contract: the license issuer only mints features defined in the registry.

Pairs with ``packages/projectair-pro/tests/test_feature_contract.py`` (the
enforce side). Together they pin both ends to ``airsdk.features`` so a granted
feature can never drift from a checked one.
"""
from __future__ import annotations

from airsdk import features as F

from vindicara.licensing.issuer import (
    _INDIVIDUAL_FEATURES,
    _PRICE_TO_PLAN,
    _TEAM_FEATURES,
)


def test_tier_bundles_are_registry_features() -> None:
    for feat in (*_INDIVIDUAL_FEATURES, *_TEAM_FEATURES):
        assert F.is_known_feature(feat), f"issuer mints {feat!r} not in airsdk.features"


def test_every_priced_plan_mints_only_registry_features() -> None:
    for price_id, plan in _PRICE_TO_PLAN.items():
        for feat in plan.features:
            assert F.is_known_feature(feat), (
                f"price {price_id} mints {feat!r}, which is not in the registry"
            )


def test_team_is_superset_of_individual() -> None:
    assert set(_INDIVIDUAL_FEATURES) <= set(_TEAM_FEATURES)
