"""Password hashing and validation using bcrypt."""

import re

import bcrypt

from vindicara.dashboard.auth.models import PasswordValidation

BCRYPT_COST_FACTOR = 12
MIN_PASSWORD_LENGTH = 12


def hash_password(password: str) -> str:
    """Hash a password with bcrypt at cost factor 12."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_COST_FACTOR)).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against a bcrypt hash."""
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def validate_password(password: str) -> PasswordValidation:
    """Check password complexity: min 12 chars, upper, lower, digit."""
    errors: list[str] = []
    if len(password) < MIN_PASSWORD_LENGTH:
        errors.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter")
    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter")
    if not re.search(r"\d", password):
        errors.append("Password must contain at least one digit")
    return PasswordValidation(valid=len(errors) == 0, errors=errors)
