"""Tests for the data asset registry."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import yaml

from airsdk_pro.governance.registry import AssetDefinition, DataAssetRegistry


class TestRegistry:
    def test_lookup_found(self, sample_registry: DataAssetRegistry) -> None:
        defn = sample_registry.lookup("patients")
        assert defn is not None
        assert defn.sensitivity == "restricted"
        assert "HIPAA" in defn.regulations

    def test_lookup_not_found(self, sample_registry: DataAssetRegistry) -> None:
        assert sample_registry.lookup("nonexistent") is None

    def test_all_assets(self, sample_registry: DataAssetRegistry) -> None:
        assert len(sample_registry.all_assets()) == 3

    def test_from_yaml(self, tmp_path: Path) -> None:
        data = {
            "assets": [
                {"id": "users", "type": "table", "sensitivity": "confidential"},
                {"id": "logs", "type": "file"},
            ]
        }
        yaml_path = tmp_path / "assets.yaml"
        yaml_path.write_text(yaml.dump(data))
        reg = DataAssetRegistry.from_yaml(yaml_path)
        assert reg.lookup("users") is not None
        assert reg.lookup("users").sensitivity == "confidential"
        assert reg.lookup("logs") is not None

    def test_from_json(self, tmp_path: Path) -> None:
        data = {"assets": [{"id": "events", "type": "stream"}]}
        json_path = tmp_path / "assets.json"
        json_path.write_text(json.dumps(data))
        reg = DataAssetRegistry.from_json(json_path)
        assert reg.lookup("events") is not None

    def test_asset_definition_regulations_default(self) -> None:
        defn = AssetDefinition(id="x", type="y")
        assert defn.regulations == []
