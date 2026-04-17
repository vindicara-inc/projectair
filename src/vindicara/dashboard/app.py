"""Dashboard sub-application factory with HTMX API endpoints."""

from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from vindicara.api.deps import (
    get_agent_registry,
    get_evaluator,
    get_reporter,
    get_scanner,
)
from vindicara.compliance.models import ComplianceFramework
from vindicara.dashboard.demo import advance_demo, get_demo_state, start_demo
from vindicara.mcp.findings import ScanMode

TEMPLATE_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


def create_dashboard_app() -> FastAPI:
    """Create the dashboard FastAPI sub-application."""
    from vindicara.dashboard.auth.api import router as auth_router
    from vindicara.dashboard.keys.api import router as keys_router
    from vindicara.dashboard.routes import router

    app = FastAPI(docs_url=None, redoc_url=None)
    app.include_router(auth_router)
    app.include_router(keys_router)
    app.include_router(router)

    @app.post("/api/guard/test", response_class=HTMLResponse)
    async def test_guard(
        input_text: str = Form(default=""),
        output_text: str = Form(default=""),
        policy: str = Form(default="content-safety"),
    ) -> HTMLResponse:
        evaluator = get_evaluator()
        try:
            result = evaluator.evaluate_guard(input_text, output_text, policy)
            verdict = result.verdict.value
            if verdict == "allowed":
                pill = '<span class="pill-pass">PASS</span>'
            elif verdict == "blocked":
                pill = '<span class="pill-block">BLOCK</span>'
            else:
                pill = '<span class="pill-warn">WARN</span>'
            rules_html = ""
            for r in result.rules:
                if r.triggered:
                    rules_html += (
                        f'<div style="margin-top:8px;padding:8px;background:rgba(230,57,70,0.05);border-left:2px solid #E63946;">'
                        f'<span class="mono" style="font-size:12px;color:#E63946;">{r.rule_id}</span>'
                        f'<span style="color:#9090A8;font-size:12px;margin-left:8px;">{r.message}</span></div>'
                    )
            return HTMLResponse(
                f'<div class="card" style="padding:16px;">'
                f'<div style="display:flex;align-items:center;gap:12px;margin-bottom:8px;">'
                f'{pill}<span class="mono" style="font-size:12px;color:#9090A8;">{result.latency_ms}ms</span>'
                f'<span class="mono" style="font-size:12px;color:#444458;">policy: {result.policy_id}</span></div>'
                f'{rules_html}</div>'
            )
        except Exception as exc:
            return HTMLResponse(f'<div style="color:#E63946;padding:8px;">{exc}</div>')

    @app.post("/api/agents/register", response_class=HTMLResponse)
    async def register_agent_htmx(
        request: Request,
        name: str = Form(...),
        permitted_tools: str = Form(default=""),
        data_scope: str = Form(default=""),
    ) -> HTMLResponse:
        agent_reg = get_agent_registry()
        tools = [t.strip() for t in permitted_tools.split(",") if t.strip()]
        scopes = [s.strip() for s in data_scope.split(",") if s.strip()]
        agent_reg.register(name=name, permitted_tools=tools, data_scope=scopes)
        agents = agent_reg.list_agents()
        return templates.TemplateResponse(
            name="pages/agents.html",
            request=request,
            context={"active_page": "agents", "agents": agents},
        )

    @app.post("/api/agents/{agent_id}/suspend", response_class=HTMLResponse)
    async def suspend_agent_htmx(request: Request, agent_id: str) -> HTMLResponse:
        agent_reg = get_agent_registry()
        agent_reg.suspend(agent_id, reason="Manual kill switch from dashboard")
        agents = agent_reg.list_agents()
        return templates.TemplateResponse(
            name="pages/agents.html",
            request=request,
            context={"active_page": "agents", "agents": agents},
        )

    @app.post("/api/mcp/scan", response_class=HTMLResponse)
    async def mcp_scan_htmx(server_url: str = Form(default="")) -> HTMLResponse:
        scanner = get_scanner()
        try:
            if server_url:
                report = await scanner.scan(server_url=server_url, mode=ScanMode.LIVE, timeout=15.0)
            else:
                report = await scanner.scan(
                    config={"tools": [{"name": "shell_exec", "description": "Execute shell commands on host system", "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}}}]},
                    mode=ScanMode.STATIC,
                )
            score_color = "#E63946" if report.risk_score > 0.7 else "#EF9F27" if report.risk_score > 0.3 else "#4ADE80"
            findings_html = ""
            for f in report.findings:
                sev = f.severity.value
                pill = f'<span class="pill-block">{sev}</span>' if sev in ("critical", "high") else f'<span class="pill-warn">{sev}</span>'
                findings_html += (
                    f'<div style="padding:12px;border-bottom:1px solid #151520;">'
                    f'<div style="display:flex;gap:8px;align-items:center;margin-bottom:4px;">{pill}'
                    f'<span class="mono" style="font-size:11px;color:#9090A8;">{f.cwe_id}</span>'
                    f'<span style="color:#EFEFEF;font-size:13px;">{f.title}</span></div>'
                    f'<div style="font-size:12px;color:#9090A8;">{f.description}</div></div>'
                )
            if not report.findings:
                findings_html = '<div style="padding:24px;text-align:center;color:#444458;">No findings</div>'
            return HTMLResponse(
                f'<div class="card">'
                f'<div style="padding:16px;border-bottom:1px solid #1A1A28;display:flex;justify-content:space-between;align-items:center;">'
                f'<span style="font-size:13px;font-weight:600;color:#EFEFEF;">Scan Results</span>'
                f'<div><span style="font-size:11px;color:#444458;">Risk Score: </span>'
                f'<span class="mono" style="font-size:20px;color:{score_color};">{report.risk_score:.2f}</span></div></div>'
                f'{findings_html}</div>'
            )
        except Exception as exc:
            return HTMLResponse(f'<div class="card" style="padding:16px;color:#E63946;">{exc}</div>')

    @app.get("/api/compliance/report/{framework_id}", response_class=HTMLResponse)
    async def generate_report_htmx(framework_id: str) -> HTMLResponse:
        reporter = get_reporter()
        try:
            report = reporter.generate(framework=ComplianceFramework(framework_id), system_id="vindicara-demo", period="2026-Q2")
            controls_html = ""
            for ctrl in report.controls:
                status_pill = '<span class="pill-pass">Documented</span>' if ctrl.evidence else '<span class="pill-warn">Pending</span>'
                controls_html += f'<tr><td class="mono" style="font-size:11px;color:#9090A8;">{ctrl.control_id}</td><td style="color:#EFEFEF;">{ctrl.name}</td><td>{status_pill}</td></tr>'
            return HTMLResponse(
                f'<div class="card"><div style="padding:12px 16px;border-bottom:1px solid #1A1A28;">'
                f'<span style="font-size:13px;font-weight:600;color:#EFEFEF;">{report.framework_name}</span>'
                f'<span class="mono" style="font-size:11px;color:#444458;margin-left:12px;">{report.report_id}</span></div>'
                f'<table><thead><tr><th>Control</th><th>Name</th><th>Status</th></tr></thead>'
                f'<tbody>{controls_html}</tbody></table></div>'
            )
        except Exception as exc:
            return HTMLResponse(f'<div style="color:#E63946;padding:16px;">{exc}</div>')

    @app.post("/api/demo/start", response_class=HTMLResponse)
    async def start_demo_htmx(request: Request) -> HTMLResponse:
        start_demo()
        demo = get_demo_state()
        return templates.TemplateResponse(name="components/demo_live.html", request=request, context={"demo": demo})

    @app.get("/api/demo/status", response_class=HTMLResponse)
    async def demo_status_htmx(request: Request) -> HTMLResponse:
        advance_demo()
        demo = get_demo_state()
        return templates.TemplateResponse(name="components/demo_live.html", request=request, context={"demo": demo})

    return app
