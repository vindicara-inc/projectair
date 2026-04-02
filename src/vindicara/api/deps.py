"""FastAPI dependency injection."""

from functools import lru_cache

from vindicara.compliance.collector import EvidenceCollector
from vindicara.compliance.reporter import ComplianceReporter
from vindicara.engine.evaluator import Evaluator
from vindicara.engine.policy import PolicyRegistry
from vindicara.identity.authz import AuthzEngine
from vindicara.identity.registry import AgentRegistry
from vindicara.mcp.scanner import MCPScanner
from vindicara.monitor.baseline import BaselineStore
from vindicara.monitor.breaker import CircuitBreaker
from vindicara.monitor.drift import DriftDetector


@lru_cache(maxsize=1)
def get_evaluator() -> Evaluator:
    return Evaluator.with_builtins()


@lru_cache(maxsize=1)
def get_registry() -> PolicyRegistry:
    return PolicyRegistry.with_builtins()


@lru_cache(maxsize=1)
def get_scanner() -> MCPScanner:
    """Get the singleton MCP scanner instance."""
    return MCPScanner()


@lru_cache(maxsize=1)
def get_agent_registry() -> AgentRegistry:
    return AgentRegistry()


@lru_cache(maxsize=1)
def get_authz_engine() -> AuthzEngine:
    return AuthzEngine(get_agent_registry())


@lru_cache(maxsize=1)
def get_evidence_collector() -> EvidenceCollector:
    return EvidenceCollector()


@lru_cache(maxsize=1)
def get_reporter() -> ComplianceReporter:
    return ComplianceReporter(get_evidence_collector())


@lru_cache(maxsize=1)
def get_baseline_store() -> BaselineStore:
    return BaselineStore()


@lru_cache(maxsize=1)
def get_drift_detector() -> DriftDetector:
    return DriftDetector(get_baseline_store())


@lru_cache(maxsize=1)
def get_circuit_breaker() -> CircuitBreaker:
    return CircuitBreaker(get_drift_detector(), get_agent_registry())
