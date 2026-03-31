"""POST /v1/mcp/scan endpoint."""

import structlog
from fastapi import APIRouter, Depends

from vindicara.api.deps import get_scanner
from vindicara.mcp.findings import ScanReport, ScanRequest
from vindicara.mcp.scanner import MCPScanner

logger = structlog.get_logger()

router = APIRouter(prefix="/v1")


@router.post("/mcp/scan", response_model=ScanReport)
async def scan_mcp(
    request: ScanRequest,
    scanner: MCPScanner = Depends(get_scanner),
) -> ScanReport:
    log = logger.bind(mode=request.mode, server_url=request.server_url)
    log.info("api.mcp_scan.started")

    report = await scanner.scan(
        server_url=request.server_url,
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
