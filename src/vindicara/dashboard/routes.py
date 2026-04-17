"""Dashboard page routes."""

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from vindicara.api.deps import (
    get_agent_registry,
    get_baseline_store,
    get_circuit_breaker,
    get_drift_detector,
    get_registry,
)
from vindicara.compliance.frameworks import list_frameworks
from vindicara.dashboard.app import templates
from vindicara.dashboard.demo import get_demo_state

router = APIRouter()

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(name="pages/login.html", request=request, context={"active_page": "login", "error": ""})


@router.get("/signup", response_class=HTMLResponse)
async def signup_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(name="pages/signup.html", request=request, context={"active_page": "signup", "error": ""})


@router.get("/api-keys", response_class=HTMLResponse)
async def api_keys_page(request: Request) -> HTMLResponse:
    from vindicara.dashboard.keys.manager import get_key_manager
    user_id = getattr(request.state, "user_id", "demo")
    manager = get_key_manager()
    keys = manager.list_keys(user_id)
    new_key = request.query_params.get("new_key", "")
    csrf_token = request.cookies.get("vnd_csrf", "")
    return templates.TemplateResponse(
        name="pages/api_keys.html",
        request=request,
        context={"active_page": "api-keys", "keys": keys, "new_key": new_key, "csrf_token": csrf_token},
    )


_PLACEHOLDER_PAGES = [
    "applications", "authentication", "team",
    "event-streams", "monitoring", "security-center",
    "marketplace", "docs", "billing", "settings",
]

_PLACEHOLDER_TITLES = {
    "applications": "Applications",
    "authentication": "Authentication",
    "api-keys": "API Keys",
    "team": "Team",
    "event-streams": "Event Streams",
    "monitoring": "Monitoring",
    "security-center": "Security Center",
    "marketplace": "Marketplace",
    "docs": "Documentation",
    "billing": "Billing",
    "settings": "Settings",
}


@router.get("/", response_class=HTMLResponse)
async def overview(request: Request) -> HTMLResponse:
    policy_registry = get_registry()
    agent_registry = get_agent_registry()
    store = get_baseline_store()
    policies = policy_registry.list_policies()
    agents = agent_registry.list_agents()
    all_events = sum(len(v) for v in store._events.values())
    stats = {"policy_count": len(policies), "agent_count": len(agents), "event_count": all_events}
    return templates.TemplateResponse(
        name="pages/overview.html",
        request=request,
        context={"active_page": "overview", "stats": stats, "agents": agents, "policies": policies},
    )


@router.get("/guard", response_class=HTMLResponse)
async def guard_page(request: Request) -> HTMLResponse:
    policies = get_registry().list_policies()
    return templates.TemplateResponse(
        name="pages/guard.html",
        request=request,
        context={"active_page": "guard", "policies": policies},
    )


@router.get("/agents", response_class=HTMLResponse)
async def agents_page(request: Request) -> HTMLResponse:
    agents = get_agent_registry().list_agents()
    return templates.TemplateResponse(
        name="pages/agents.html",
        request=request,
        context={"active_page": "agents", "agents": agents},
    )


@router.get("/mcp", response_class=HTMLResponse)
async def mcp_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(name="pages/mcp.html", request=request, context={"active_page": "mcp"})


@router.get("/monitor", response_class=HTMLResponse)
async def monitor_page(request: Request) -> HTMLResponse:
    agent_registry = get_agent_registry()
    detector = get_drift_detector()
    breaker = get_circuit_breaker()
    agents = agent_registry.list_agents()
    drift_data = []
    for agent in agents:
        drift = detector.check_drift(agent.agent_id)
        breaker_status = breaker.check(agent.agent_id)
        drift_data.append({
            "agent_name": agent.name,
            "score": drift.score,
            "alert_count": len(drift.alerts),
            "breaker_tripped": breaker_status.tripped,
        })
    return templates.TemplateResponse(
        name="pages/monitor.html",
        request=request,
        context={"active_page": "monitor", "drift_data": drift_data},
    )


@router.get("/compliance", response_class=HTMLResponse)
async def compliance_page(request: Request) -> HTMLResponse:
    frameworks = list_frameworks()
    return templates.TemplateResponse(
        name="pages/compliance.html",
        request=request,
        context={"active_page": "compliance", "frameworks": frameworks},
    )


@router.get("/demo", response_class=HTMLResponse)
async def demo_page(request: Request) -> HTMLResponse:
    demo = get_demo_state()
    return templates.TemplateResponse(
        name="pages/demo.html",
        request=request,
        context={"active_page": "demo", "demo": demo},
    )


@router.get("/{page}", response_class=HTMLResponse)
async def placeholder(request: Request, page: str) -> HTMLResponse:
    if page in _PLACEHOLDER_PAGES:
        title = _PLACEHOLDER_TITLES.get(page, page.replace("-", " ").title())
        return templates.TemplateResponse(
            name="pages/placeholder.html",
            request=request,
            context={"active_page": page, "page_title": title},
        )
    return HTMLResponse(status_code=404, content="Page not found")
