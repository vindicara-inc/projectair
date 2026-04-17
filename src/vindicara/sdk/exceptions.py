"""Typed exceptions for the Vindicara SDK."""


class VindicaraError(Exception):
    """Base exception for all Vindicara errors."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(self.message)


class VindicaraPolicyViolation(VindicaraError):
    """Raised when a policy evaluation results in a block verdict."""

    def __init__(self, message: str, policy_id: str) -> None:
        self.policy_id = policy_id
        super().__init__(message)


class VindicaraAuthError(VindicaraError):
    """Raised when authentication fails (invalid or missing API key)."""


class VindicaraRateLimited(VindicaraError):
    """Raised when the API rate limit is exceeded."""

    def __init__(self, message: str, retry_after_seconds: float) -> None:
        self.retry_after_seconds = retry_after_seconds
        super().__init__(message)


class VindicaraConnectionError(VindicaraError):
    """Raised when the SDK cannot reach the Vindicara API."""


class VindicaraValidationError(VindicaraError):
    """Raised when input validation fails before evaluation."""


class VindicaraMCPRiskDetected(VindicaraError):
    """Raised when an MCP scan detects critical security risks."""

    def __init__(self, message: str, risk_score: float) -> None:
        self.risk_score = risk_score
        super().__init__(message)


class VindicaraAgentSuspended(VindicaraError):
    """Raised when an operation targets a suspended agent."""

    def __init__(self, message: str, agent_id: str) -> None:
        self.agent_id = agent_id
        super().__init__(message)


class PolicyNotFoundError(VindicaraError):
    """Raised when a requested policy does not exist in the registry."""
