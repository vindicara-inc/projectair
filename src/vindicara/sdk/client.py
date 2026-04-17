"""VindicaraClient: sync and async interfaces for guard() evaluation."""

import structlog

from vindicara.compliance.collector import EvidenceCollector
from vindicara.compliance.frameworks import list_frameworks
from vindicara.compliance.models import ComplianceFramework, ComplianceReport, FrameworkInfo
from vindicara.compliance.reporter import ComplianceReporter
from vindicara.config.settings import VindicaraSettings
from vindicara.engine.evaluator import Evaluator
from vindicara.identity.authz import AuthzEngine
from vindicara.identity.models import AgentIdentity, CheckResult
from vindicara.identity.registry import AgentRegistry
from vindicara.mcp.findings import ScanMode, ScanReport
from vindicara.mcp.scanner import MCPScanner
from vindicara.monitor.baseline import BaselineStore
from vindicara.monitor.breaker import CircuitBreaker
from vindicara.monitor.drift import DriftDetector
from vindicara.monitor.models import BehaviorEvent, BreakerConfig, BreakerStatus, DriftScore
from vindicara.sdk.types import GuardResult

logger = structlog.get_logger()


class MCPNamespace:
    """MCP security scanning methods."""

    def __init__(self, scanner: MCPScanner) -> None:
        self._scanner = scanner

    async def scan(
        self,
        server_url: str = "",
        config: dict[str, object] | None = None,
        mode: str = "auto",
        timeout: float = 30.0,
        dry_run: bool = False,
    ) -> ScanReport:
        return await self._scanner.scan(
            server_url=server_url,
            config=config,
            mode=ScanMode(mode),
            timeout=timeout,
            dry_run=dry_run,
        )

    async def scan_config(self, config: dict[str, object]) -> ScanReport:
        return await self._scanner.scan(config=config, mode=ScanMode.STATIC)


class AgentsNamespace:
    """Agent identity and access management methods."""

    def __init__(self, registry: AgentRegistry, authz: AuthzEngine) -> None:
        self._registry = registry
        self._authz = authz

    def register(
        self,
        name: str,
        permitted_tools: list[str] | None = None,
        data_scope: list[str] | None = None,
        limits: dict[str, int] | None = None,
    ) -> AgentIdentity:
        return self._registry.register(name=name, permitted_tools=permitted_tools, data_scope=data_scope, limits=limits)

    def get(self, agent_id: str) -> AgentIdentity:
        return self._registry.get(agent_id)

    def list(self) -> list[AgentIdentity]:
        return self._registry.list_agents()

    def check(self, agent_id: str, tool: str) -> CheckResult:
        return self._authz.check_tool(agent_id, tool)

    def suspend(self, agent_id: str, reason: str = "Manual suspension") -> AgentIdentity:
        return self._registry.suspend(agent_id, reason=reason)


class ComplianceNamespace:
    """Compliance report generation methods."""

    def __init__(self, reporter: ComplianceReporter) -> None:
        self._reporter = reporter

    def generate(
        self,
        framework: str,
        system_id: str,
        period: str = "",
    ) -> ComplianceReport:
        """Generate a compliance report."""
        return self._reporter.generate(
            framework=ComplianceFramework(framework),
            system_id=system_id,
            period=period,
        )

    def frameworks(self) -> list[FrameworkInfo]:
        """List available compliance frameworks."""
        return list_frameworks()


class MonitorNamespace:
    """Behavioral drift detection methods."""

    def __init__(
        self,
        store: BaselineStore,
        detector: DriftDetector,
        breaker: CircuitBreaker,
    ) -> None:
        self._store = store
        self._detector = detector
        self._breaker = breaker

    def record(
        self,
        agent_id: str,
        tool: str,
        data_scope: str = "",
        metadata: dict[str, str] | None = None,
    ) -> BehaviorEvent:
        """Record an agent behavior event."""
        event = BehaviorEvent(
            agent_id=agent_id,
            tool=tool,
            data_scope=data_scope,
            metadata=metadata or {},
        )
        return self._store.record(event)

    def get_drift(self, agent_id: str, window_minutes: int = 60) -> DriftScore:
        """Get drift score for an agent."""
        return self._detector.check_drift(agent_id, window_minutes)

    def set_breaker(
        self,
        agent_id: str,
        threshold: float = 0.8,
        auto_suspend: bool = True,
    ) -> BreakerConfig:
        """Configure a circuit breaker for an agent."""
        config = BreakerConfig(
            agent_id=agent_id,
            threshold=threshold,
            auto_suspend=auto_suspend,
        )
        return self._breaker.set_config(config)

    def check_breaker(self, agent_id: str) -> BreakerStatus:
        """Check circuit breaker status."""
        return self._breaker.check(agent_id)


class VindicaraClient:
    """Main client for interacting with Vindicara.

    Supports both offline (local evaluation) and online (API) modes.
    """

    def __init__(
        self,
        api_key: str = "",
        offline: bool = False,
        base_url: str = "",
    ) -> None:
        settings = VindicaraSettings()
        self._api_key = api_key or settings.api_key
        self._offline = offline or settings.offline_mode
        self._base_url = base_url or settings.api_base_url
        self._evaluator = Evaluator.with_builtins()
        self._scanner = MCPScanner()
        self.mcp = MCPNamespace(self._scanner)
        self._agent_registry = AgentRegistry()
        self._authz_engine = AuthzEngine(self._agent_registry)
        self.agents = AgentsNamespace(self._agent_registry, self._authz_engine)
        self._evidence_collector = EvidenceCollector()
        self._compliance_reporter = ComplianceReporter(self._evidence_collector)
        self.compliance = ComplianceNamespace(self._compliance_reporter)
        self._baseline_store = BaselineStore()
        self._drift_detector = DriftDetector(self._baseline_store)
        self._circuit_breaker = CircuitBreaker(self._drift_detector, self._agent_registry)
        self.monitor = MonitorNamespace(self._baseline_store, self._drift_detector, self._circuit_breaker)
        self._http_client: object | None = None

        logger.info(
            "vindicara.client.initialized",
            offline=self._offline,
            base_url=self._base_url if not self._offline else "local",
        )

    def guard(
        self,
        input: str = "",
        output: str = "",
        policy: str = "content-safety",
    ) -> GuardResult:
        """Evaluate input and/or output against a policy (synchronous)."""
        if self._offline:
            return self._evaluate_local(input, output, policy)
        return self._evaluate_remote(input, output, policy)

    async def async_guard(
        self,
        input: str = "",
        output: str = "",
        policy: str = "content-safety",
    ) -> GuardResult:
        """Evaluate input and/or output against a policy (asynchronous)."""
        if self._offline:
            return self._evaluate_local(input, output, policy)
        return await self._evaluate_remote_async(input, output, policy)

    def _evaluate_local(
        self,
        input_text: str,
        output_text: str,
        policy_id: str,
    ) -> GuardResult:
        """Evaluate locally using the built-in policy engine."""
        return self._evaluator.evaluate_guard(input_text, output_text, policy_id)

    def _evaluate_remote(
        self,
        input_text: str,
        output_text: str,
        policy_id: str,
    ) -> GuardResult:
        """Evaluate via the remote API (synchronous)."""
        import httpx

        from vindicara.sdk.exceptions import VindicaraConnectionError

        try:
            with httpx.Client(
                base_url=self._base_url,
                headers={"X-Vindicara-Key": self._api_key},
                timeout=10.0,
            ) as client:
                response = client.post(
                    "/v1/guard",
                    json={
                        "input": input_text,
                        "output": output_text,
                        "policy": policy_id,
                    },
                )
                response.raise_for_status()
                return GuardResult.model_validate(response.json())
        except httpx.HTTPStatusError as exc:
            _raise_typed_error(exc)
        except httpx.ConnectError as exc:
            raise VindicaraConnectionError(f"Cannot reach Vindicara API at {self._base_url}: {exc}") from exc
        except httpx.TimeoutException as exc:
            raise VindicaraConnectionError(f"Request to Vindicara API timed out: {exc}") from exc

    async def _evaluate_remote_async(
        self,
        input_text: str,
        output_text: str,
        policy_id: str,
    ) -> GuardResult:
        """Evaluate via the remote API (asynchronous)."""
        import httpx

        from vindicara.sdk.exceptions import VindicaraConnectionError

        try:
            async with httpx.AsyncClient(
                base_url=self._base_url,
                headers={"X-Vindicara-Key": self._api_key},
                timeout=10.0,
            ) as client:
                response = await client.post(
                    "/v1/guard",
                    json={
                        "input": input_text,
                        "output": output_text,
                        "policy": policy_id,
                    },
                )
                response.raise_for_status()
                return GuardResult.model_validate(response.json())
        except httpx.HTTPStatusError as exc:
            _raise_typed_error(exc)
        except httpx.ConnectError as exc:
            raise VindicaraConnectionError(f"Cannot reach Vindicara API at {self._base_url}: {exc}") from exc
        except httpx.TimeoutException as exc:
            raise VindicaraConnectionError(f"Request to Vindicara API timed out: {exc}") from exc


def _raise_typed_error(exc: object) -> None:
    """Map HTTP status errors to typed SDK exceptions. Always raises."""
    import httpx

    from vindicara.sdk.exceptions import (
        VindicaraAuthError,
        VindicaraError,
        VindicaraRateLimited,
    )

    if not isinstance(exc, httpx.HTTPStatusError):
        raise VindicaraError(f"Unexpected error: {exc}") from Exception(str(exc))

    status = exc.response.status_code
    if status == 401:
        raise VindicaraAuthError("Invalid or missing API key") from exc
    if status == 429:
        retry_after = float(exc.response.headers.get("Retry-After", "60"))
        raise VindicaraRateLimited("Rate limit exceeded", retry_after_seconds=retry_after) from exc
    raise VindicaraError(f"API request failed with status {status}: {exc.response.text}") from exc
