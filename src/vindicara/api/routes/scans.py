"""POST /v1/mcp/scan endpoint."""

from urllib.parse import urlparse

import structlog
from fastapi import APIRouter, Depends, HTTPException

from vindicara.api.deps import get_scanner
from vindicara.mcp.findings import ScanReport, ScanRequest
from vindicara.mcp.scanner import MCPScanner

logger = structlog.get_logger()

router = APIRouter(prefix="/v1")

_ALLOWED_MCP_HOSTS = frozenset({"mcp.example.com"})


def _validate_allowed_server_url(server_url: str) -> str:
    parsed = urlparse(server_url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="server_url must use http or https")
    host = (parsed.hostname or "").lower()
    if not host:
        raise HTTPException(status_code=400, detail="server_url must include a host")
    if host not in _ALLOWED_MCP_HOSTS:
        raise HTTPException(status_code=400, detail="server_url host is not allowed")
    return server_url


@router.post("/mcp/scan", response_model=ScanReport)
async def scan_mcp(
    request: ScanRequest,
    scanner: MCPScanner = Depends(get_scanner),
) -> ScanReport:
    log = logger.bind(mode=request.mode, server_url=request.server_url)
    log.info("api.mcp_scan.started")

    validated_server_url = _validate_allowed_server_url(request.server_url) if request.server_url else ""

    report = await scanner.scan(
        server_url=validated_server_url,
        config=request.config if request.config else None,
        mode=request.mode,
        timeout=request.timeout_seconds,
        dry_run=request.dry_run,
    )

    log.info(
        "api.mcp_scan.completed",
        risk_score=report.risk_score,
        findings_count=len(report.findings),
    )
    return report
