"""Auth data models."""

from pydantic import BaseModel, Field


class SignupRequest(BaseModel):
    email: str
    password: str
    confirm_password: str


class LoginRequest(BaseModel):
    email: str
    password: str
    totp_code: str = ""


class User(BaseModel):
    user_id: str
    email: str
    password_hash: str
    created_at: str = ""
    verified: bool = False
    mfa_enabled: bool = False
    mfa_secret: str = ""
    failed_login_attempts: int = 0
    locked_until: str = ""


class Session(BaseModel):
    session_id: str
    user_id: str
    created_at: str = ""
    expires_at: str = ""
    revoked: bool = False


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    csrf_token: str


class PasswordValidation(BaseModel):
    valid: bool
    errors: list[str] = Field(default_factory=list)


class VerificationToken(BaseModel):
    token: str
    user_id: str
    expires_at: str
