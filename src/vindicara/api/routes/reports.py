"""Compliance report endpoints."""

import structlog
from fastapi import APIRouter, Depends

from vindicara.api.deps import get_reporter
from vindicara.compliance.frameworks import list_frameworks
from vindicara.compliance.models import (
    ComplianceReport,
    FrameworkInfo,
    GenerateReportRequest,
)
from vindicara.compliance.reporter import ComplianceReporter

logger = structlog.get_logger()

router = APIRouter(prefix="/v1")


@router.post("/compliance/reports", response_model=ComplianceReport)
async def generate_report(
    request: GenerateReportRequest,
    reporter: ComplianceReporter = Depends(get_reporter),
) -> ComplianceReport:
    """Generate a compliance report for a framework and period."""
    logger.info(
        "api.compliance.generate",
        framework=request.framework.value,
        system_id=request.system_id,
    )
    return reporter.generate(
        framework=request.framework,
        system_id=request.system_id,
        period=request.period,
    )


@router.get("/compliance/frameworks", response_model=list[FrameworkInfo])
async def get_frameworks() -> list[FrameworkInfo]:
    """List available compliance frameworks."""
    return list_frameworks()
