"""Data asset registry for governance enrichment."""
from __future__ import annotations

import json
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field


class AssetDefinition(BaseModel):
    """Metadata for a single data asset in the governance registry."""

    model_config = ConfigDict(extra="forbid")

    id: str
    type: str
    namespace: str = ""
    sensitivity: str = ""
    regulations: list[str] = Field(default_factory=list)
    retention_days: int | None = None
    owner: str = ""


class DataAssetRegistry:
    """Loads and serves data asset definitions from YAML or JSON."""

    def __init__(self, assets: list[AssetDefinition]) -> None:
        self._assets: dict[str, AssetDefinition] = {a.id: a for a in assets}

    def lookup(self, asset_id: str) -> AssetDefinition | None:
        return self._assets.get(asset_id)

    def all_assets(self) -> list[AssetDefinition]:
        return list(self._assets.values())

    @classmethod
    def from_yaml(cls, path: str | Path) -> DataAssetRegistry:
        with Path(path).open() as f:
            data = yaml.safe_load(f)
        assets = [AssetDefinition.model_validate(a) for a in data.get("assets", [])]
        return cls(assets)

    @classmethod
    def from_json(cls, path: str | Path) -> DataAssetRegistry:
        with Path(path).open() as f:
            data = json.load(f)
        assets = [AssetDefinition.model_validate(a) for a in data.get("assets", [])]
        return cls(assets)
