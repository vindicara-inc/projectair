"""Environment-based configuration using Pydantic Settings."""

from pydantic import Field
from pydantic_settings import BaseSettings

_DEFAULT_CORS_ORIGINS = [
    "https://vindicara.io",
    "https://www.vindicara.io",
    "https://dashboard.vindicara.io",
]


class VindicaraSettings(BaseSettings):
    """Application configuration loaded from environment variables."""

    model_config = {"env_prefix": "VINDICARA_"}

    api_key: str = Field(default="", description="Vindicara API key")
    api_base_url: str = Field(
        default="https://d1xzz26fz4.execute-api.us-east-1.amazonaws.com",
        description="Base URL for Vindicara API",
    )
    offline_mode: bool = Field(
        default=False,
        description="Run in offline mode (local evaluation only)",
    )
    log_level: str = Field(default="INFO", description="Logging level")
    aws_region: str = Field(default="us-east-1", description="AWS region")
    aws_account_id: str = Field(default="", description="AWS account ID for CDK")
    stage: str = Field(default="dev", description="Deployment stage")
    request_timeout_seconds: float = Field(
        default=10.0,
        description="HTTP request timeout in seconds",
    )
    cors_origins: list[str] = Field(
        default=_DEFAULT_CORS_ORIGINS,
        description="Allowed CORS origins",
    )
    rate_limit_requests: int = Field(
        default=100,
        description="Max API requests per window per key",
    )
    rate_limit_window_seconds: int = Field(
        default=60,
        description="Rate limit sliding window in seconds",
    )
    jwt_secret: str = Field(
        default="",
        description="JWT signing secret. Empty means generate a random per-process secret.",
    )
    users_table: str = Field(
        default="",
        description="DynamoDB table name for user/session/key storage. Empty means in-memory.",
    )
    verify_base_url: str = Field(
        default="http://localhost:8000",
        description="Base URL for email verification links.",
    )
    ses_sender: str = Field(
        default="noreply@vindicara.io",
        description="Verified SES sender identity for outbound email.",
    )
    stripe_secret_key: str = Field(
        default="",
        description="Stripe secret key (sk_live_... or sk_test_...). Server-side only.",
    )
    stripe_webhook_secret: str = Field(
        default="",
        description="Stripe webhook signing secret (whsec_...) for signature verification.",
    )
    resend_api_key: str = Field(
        default="",
        description="Resend transactional email API key. Empty disables email delivery (logs instead).",
    )
    license_signing_key_pem: str = Field(
        default="",
        description=(
            "Ed25519 vendor private key in PEM format for signing license tokens. "
            "Loaded as a string so the secret can come from a single env var or "
            "Secrets Manager fetch. Empty disables auto-issuance."
        ),
    )
    license_default_duration_days: int = Field(
        default=30,
        description=(
            "Default license duration when issued from a Stripe webhook. 30 covers a monthly "
            "subscription with a small grace window; renewal events extend on next invoice.paid."
        ),
    )
    pro_wheel_signed_url: str = Field(
        default="",
        description=(
            "Pre-signed (or otherwise time-limited) URL where buyers can download the "
            "projectair-pro wheel after purchase. Embedded in the activation email."
        ),
    )
