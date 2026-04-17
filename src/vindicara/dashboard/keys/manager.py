"""API key generation, hashing, rotation, and scoping."""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()

VALID_SCOPES = {"guard", "mcp", "agents", "monitor", "compliance"}
GRACE_PERIOD_HOURS = 24


class APIKeyRecord(BaseModel):
    key_id: str
    user_id: str
    name: str
    key_hash: str
    key_prefix: str
    scopes: list[str] = Field(default_factory=list)
    created_at: str = ""
    revoked: bool = False
    rotated_from: str = ""
    grace_expires: str = ""


class APIKeyManager:
    """In-memory API key management. DynamoDB in production."""

    def __init__(self) -> None:
        self._keys: dict[str, APIKeyRecord] = {}
        self._hash_index: dict[str, str] = {}

    def create_key(
        self,
        user_id: str,
        name: str,
        scopes: list[str] | None = None,
    ) -> tuple[str, APIKeyRecord]:
        """Create a new API key. Returns (raw_key, record). Raw key shown once only."""
        raw_key = f"vnd_live_{secrets.token_hex(32)}"
        key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        key_id = f"key_{secrets.token_hex(8)}"
        validated_scopes = [s for s in (scopes or []) if s in VALID_SCOPES]

        record = APIKeyRecord(
            key_id=key_id,
            user_id=user_id,
            name=name,
            key_hash=key_hash,
            key_prefix=raw_key[:12] + "..." + raw_key[-4:],
            scopes=validated_scopes if validated_scopes else list(VALID_SCOPES),
            created_at=datetime.now(UTC).isoformat(),
        )
        self._keys[key_id] = record
        self._hash_index[key_hash] = key_id
        logger.info("keys.created", key_id=key_id, user_id=user_id, name=name)
        return raw_key, record

    def list_keys(self, user_id: str) -> list[APIKeyRecord]:
        """List all active keys for a user."""
        return [k for k in self._keys.values() if k.user_id == user_id and not k.revoked]

    def revoke_key(self, key_id: str, user_id: str) -> bool:
        """Revoke a key. Returns True if found and revoked."""
        record = self._keys.get(key_id)
        if record is None or record.user_id != user_id:
            return False
        self._keys[key_id] = record.model_copy(update={"revoked": True})
        self._hash_index.pop(record.key_hash, None)
        logger.info("keys.revoked", key_id=key_id)
        return True

    def rotate_key(self, key_id: str, user_id: str) -> tuple[str, APIKeyRecord] | None:
        """Rotate a key: create new one, keep old for grace period."""
        old = self._keys.get(key_id)
        if old is None or old.user_id != user_id or old.revoked:
            return None

        grace = (datetime.now(UTC) + timedelta(hours=GRACE_PERIOD_HOURS)).isoformat()
        self._keys[key_id] = old.model_copy(update={"grace_expires": grace})

        raw_key, new_record = self.create_key(user_id, old.name, old.scopes)
        self._keys[new_record.key_id] = new_record.model_copy(update={"rotated_from": key_id})
        logger.info("keys.rotated", old_key_id=key_id, new_key_id=new_record.key_id)
        return raw_key, new_record

    def validate_key(self, raw_key: str) -> APIKeyRecord | None:
        """Validate a raw API key. Returns record if valid."""
        key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        key_id = self._hash_index.get(key_hash)
        if key_id is None:
            return None
        record = self._keys.get(key_id)
        if record is None or record.revoked:
            return None
        return record


_manager = APIKeyManager()


def get_key_manager() -> APIKeyManager:
    return _manager
