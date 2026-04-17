# Demo Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a demo-ready dashboard that shows Vindicara detecting and stopping a rogue AI agent in real time, for the Glasswing/Mythos conversation with Anthropic.

**Architecture:** Jinja2-templated FastAPI sub-app mounted at `/dashboard/` on the existing API. HTMX handles interactivity (form submissions, polling). Tailwind CSS via CDN for styling. All business logic comes from existing singletons (evaluator, agent registry, drift detector, circuit breaker). No auth, no DynamoDB, no JS framework.

**Tech Stack:** FastAPI, Jinja2, HTMX, Tailwind CSS CDN, existing Vindicara engine

---

## File Map

**Create:**
- `src/vindicara/dashboard/__init__.py` - Package init
- `src/vindicara/dashboard/app.py` - Dashboard sub-app factory, Jinja2 setup, HTMX API routes
- `src/vindicara/dashboard/routes.py` - Page routes (GET endpoints returning full HTML pages)
- `src/vindicara/dashboard/context.py` - Template context builders pulling from existing services
- `src/vindicara/dashboard/demo.py` - Live demo orchestration state machine
- `src/vindicara/dashboard/templates/base.html` - Base layout with sidebar + content
- `src/vindicara/dashboard/templates/components/sidebar.html` - 17-item sidebar
- `src/vindicara/dashboard/templates/components/stat_card.html` - Stat card partial
- `src/vindicara/dashboard/templates/components/status_pill.html` - PASS/BLOCK/WARN pill
- `src/vindicara/dashboard/templates/components/agent_row.html` - Agent table row
- `src/vindicara/dashboard/templates/components/event_row.html` - Event log row
- `src/vindicara/dashboard/templates/components/alert_row.html` - Drift alert row
- `src/vindicara/dashboard/templates/pages/overview.html` - Dashboard home
- `src/vindicara/dashboard/templates/pages/guard.html` - Policy engine page
- `src/vindicara/dashboard/templates/pages/mcp.html` - MCP scanner page
- `src/vindicara/dashboard/templates/pages/agents.html` - Agent registry page
- `src/vindicara/dashboard/templates/pages/monitor.html` - Drift monitor page
- `src/vindicara/dashboard/templates/pages/compliance.html` - Compliance page
- `src/vindicara/dashboard/templates/pages/demo.html` - Live demo page
- `src/vindicara/dashboard/templates/pages/placeholder.html` - Coming soon page
- `tests/integration/dashboard/__init__.py` - Test package init
- `tests/integration/dashboard/test_pages.py` - Page route tests
- `tests/integration/dashboard/test_demo.py` - Demo flow tests

**Modify:**
- `src/vindicara/api/app.py` - Mount dashboard sub-app
- `pyproject.toml` - Add `jinja2` dependency

---

### Task 1: Project Setup and Base Layout

**Files:**
- Create: `src/vindicara/dashboard/__init__.py`
- Create: `src/vindicara/dashboard/app.py`
- Create: `src/vindicara/dashboard/routes.py`
- Create: `src/vindicara/dashboard/templates/base.html`
- Create: `src/vindicara/dashboard/templates/components/sidebar.html`
- Create: `src/vindicara/dashboard/templates/pages/placeholder.html`
- Modify: `src/vindicara/api/app.py`
- Modify: `pyproject.toml`
- Create: `tests/integration/dashboard/__init__.py`
- Create: `tests/integration/dashboard/test_pages.py`

- [ ] **Step 1: Add jinja2 dependency to pyproject.toml**

In `pyproject.toml`, add `jinja2` to the `api` optional dependencies:

```toml
api = [
    "fastapi>=0.115.0,<1.0",
    "jinja2>=3.1.0,<4.0",
    "mangum>=0.19.0,<1.0",
    "uvicorn>=0.30.0,<1.0",
    "boto3>=1.35.0,<2.0",
    "boto3-stubs[dynamodb,s3,events]>=1.35.0,<2.0",
]
```

Run: `cd /Users/km/Desktop/vindicara && source .venv/bin/activate && pip install -e ".[api,dev]"`

- [ ] **Step 2: Write the integration test for the overview page**

Create `tests/integration/dashboard/__init__.py` (empty file).

Create `tests/integration/dashboard/test_pages.py`:

```python
"""Tests for dashboard page routes."""

import pytest
from httpx import ASGITransport, AsyncClient


@pytest.mark.asyncio
async def test_overview_page(app) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/dashboard/")
    assert response.status_code == 200
    assert "Vindicara" in response.text
    assert "Command Center" in response.text


@pytest.mark.asyncio
async def test_placeholder_page(app) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/dashboard/settings")
    assert response.status_code == 200
    assert "Coming Soon" in response.text
```

Run: `pytest tests/integration/dashboard/test_pages.py -v`
Expected: FAIL (dashboard module does not exist yet)

- [ ] **Step 3: Create dashboard package with app factory**

Create `src/vindicara/dashboard/__init__.py`:

```python
"""Vindicara demo dashboard."""
```

Create `src/vindicara/dashboard/app.py`:

```python
"""Dashboard sub-application factory."""

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates

TEMPLATE_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


def create_dashboard_app() -> FastAPI:
    """Create the dashboard FastAPI sub-application."""
    from vindicara.dashboard.routes import router

    app = FastAPI(docs_url=None, redoc_url=None)
    app.include_router(router)
    return app
```

- [ ] **Step 4: Create sidebar component template**

Create `src/vindicara/dashboard/templates/components/sidebar.html`:

```html
<nav style="width:220px;min-height:100vh;background:#0C0C14;border-right:1px solid #1A1A28;display:flex;flex-direction:column;position:fixed;left:0;top:0;bottom:0;overflow-y:auto;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <!-- Logo -->
  <div style="padding:20px 16px;border-bottom:1px solid #1A1A28;display:flex;align-items:center;gap:10px;">
    <div style="width:28px;height:28px;background:#E63946;display:flex;align-items:center;justify-content:center;">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" fill="#fff" fill-opacity="0.9"/><path d="M12 5L6 8.5v4.5c0 3.88 2.56 7.52 6 8.5 3.44-.98 6-4.62 6-8.5V8.5L12 5z" fill="#E63946"/></svg>
    </div>
    <span style="color:#EFEFEF;font-weight:600;font-size:13px;letter-spacing:0.3px;">VINDICARA</span>
  </div>

  <!-- Dashboard section -->
  <div style="padding:16px 0 4px 0;">
    <div style="padding:0 16px 6px;font-size:10px;font-weight:600;letter-spacing:1px;color:#444458;text-transform:uppercase;">Dashboard</div>
    {% set nav_items_dashboard = [("Overview", "/dashboard/", "overview")] %}
    {% for label, href, key in nav_items_dashboard %}
    <a href="{{ href }}" style="display:flex;align-items:center;gap:8px;padding:8px 16px;color:{% if active_page == key %}#E63946{% else %}#C8C8D4{% endif %};text-decoration:none;font-size:13px;{% if active_page == key %}border-left:3px solid #E63946;background:rgba(230,57,70,0.06);padding-left:13px;{% else %}border-left:3px solid transparent;{% endif %}">{{ label }}</a>
    {% endfor %}
  </div>

  <!-- Five Pillars section -->
  <div style="padding:12px 0 4px 0;">
    <div style="padding:0 16px 6px;font-size:10px;font-weight:600;letter-spacing:1px;color:#444458;text-transform:uppercase;">Five Pillars</div>
    {% set nav_items_pillars = [
      ("Policy Engine", "/dashboard/guard", "guard"),
      ("MCP Scanner", "/dashboard/mcp", "mcp"),
      ("Agent Registry", "/dashboard/agents", "agents"),
      ("Drift Monitor", "/dashboard/monitor", "monitor"),
      ("Compliance", "/dashboard/compliance", "compliance"),
    ] %}
    {% for label, href, key in nav_items_pillars %}
    <a href="{{ href }}" style="display:flex;align-items:center;gap:8px;padding:8px 16px;color:{% if active_page == key %}#E63946{% else %}#C8C8D4{% endif %};text-decoration:none;font-size:13px;{% if active_page == key %}border-left:3px solid #E63946;background:rgba(230,57,70,0.06);padding-left:13px;{% else %}border-left:3px solid transparent;{% endif %}">{{ label }}</a>
    {% endfor %}
  </div>

  <!-- Platform section -->
  <div style="padding:12px 0 4px 0;">
    <div style="padding:0 16px 6px;font-size:10px;font-weight:600;letter-spacing:1px;color:#444458;text-transform:uppercase;">Platform</div>
    {% set nav_items_platform = [
      ("Applications", "/dashboard/applications", "applications"),
      ("Authentication", "/dashboard/authentication", "authentication"),
      ("API Keys", "/dashboard/api-keys", "api-keys"),
      ("Team", "/dashboard/team", "team"),
      ("Event Streams", "/dashboard/event-streams", "event-streams"),
      ("Monitoring", "/dashboard/monitoring", "monitoring"),
      ("Security Center", "/dashboard/security-center", "security-center"),
      ("Marketplace", "/dashboard/marketplace", "marketplace"),
    ] %}
    {% for label, href, key in nav_items_platform %}
    <a href="{{ href }}" style="display:flex;align-items:center;gap:8px;padding:8px 16px;color:{% if active_page == key %}#E63946{% else %}#C8C8D4{% endif %};text-decoration:none;font-size:13px;{% if active_page == key %}border-left:3px solid #E63946;background:rgba(230,57,70,0.06);padding-left:13px;{% else %}border-left:3px solid transparent;{% endif %}">{{ label }}</a>
    {% endfor %}
  </div>

  <!-- System section -->
  <div style="padding:12px 0 4px 0;">
    <div style="padding:0 16px 6px;font-size:10px;font-weight:600;letter-spacing:1px;color:#444458;text-transform:uppercase;">System</div>
    {% set nav_items_system = [
      ("Docs", "/dashboard/docs", "docs"),
      ("Billing", "/dashboard/billing", "billing"),
      ("Settings", "/dashboard/settings", "settings"),
    ] %}
    {% for label, href, key in nav_items_system %}
    <a href="{{ href }}" style="display:flex;align-items:center;gap:8px;padding:8px 16px;color:{% if active_page == key %}#E63946{% else %}#C8C8D4{% endif %};text-decoration:none;font-size:13px;{% if active_page == key %}border-left:3px solid #E63946;background:rgba(230,57,70,0.06);padding-left:13px;{% else %}border-left:3px solid transparent;{% endif %}">{{ label }}</a>
    {% endfor %}
  </div>

  <!-- Live Demo CTA -->
  <div style="padding:16px;margin-top:auto;">
    <a href="/dashboard/demo" style="display:block;text-align:center;padding:10px;background:#E63946;color:#EFEFEF;text-decoration:none;font-size:12px;font-weight:600;letter-spacing:0.5px;">LIVE DEMO</a>
  </div>

  <!-- Footer -->
  <div style="padding:12px 16px;border-top:1px solid #1A1A28;">
    <div style="font-size:11px;color:#444458;font-family:SFMono-Regular,Consolas,monospace;">v0.1.0</div>
    <div style="font-size:10px;color:#E63946;margin-top:2px;">DEMO MODE</div>
  </div>
</nav>
```

- [ ] **Step 5: Create base layout template**

Create `src/vindicara/dashboard/templates/base.html`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{% block title %}Vindicara{% endblock %}</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://unpkg.com/htmx.org@2.0.4"></script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { background: #08080D; color: #EFEFEF; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    .mono { font-family: SFMono-Regular, Consolas, "Liberation Mono", monospace; }
    .card { background: #10101A; border: 1px solid #1A1A28; }
    .card-divider { border-color: #151520; }
    .pill-pass { background: rgba(96,165,250,0.08); color: #60A5FA; padding: 2px 8px; font-size: 11px; font-weight: 600; }
    .pill-block { background: rgba(230,57,70,0.10); color: #E63946; padding: 2px 8px; font-size: 11px; font-weight: 600; }
    .pill-warn { background: rgba(239,159,39,0.10); color: #EF9F27; padding: 2px 8px; font-size: 11px; font-weight: 600; }
    .pill-active { background: rgba(74,222,128,0.10); color: #4ADE80; padding: 2px 8px; font-size: 11px; font-weight: 600; }
    .pill-suspended { background: rgba(230,57,70,0.10); color: #E63946; padding: 2px 8px; font-size: 11px; font-weight: 600; }
    .dot-active { width: 7px; height: 7px; background: #60A5FA; display: inline-block; }
    .dot-alert { width: 7px; height: 7px; background: #E63946; display: inline-block; }
    .dot-idle { width: 7px; height: 7px; background: #444458; display: inline-block; }
    .btn-red { background: #E63946; color: #EFEFEF; padding: 8px 16px; border: none; cursor: pointer; font-size: 13px; font-weight: 600; }
    .btn-red:hover { background: #d32f3c; }
    .btn-outline { background: transparent; color: #C8C8D4; padding: 8px 16px; border: 1px solid #1A1A28; cursor: pointer; font-size: 13px; }
    .btn-outline:hover { border-color: #60A5FA; color: #60A5FA; }
    .htmx-indicator { display: none; }
    .htmx-request .htmx-indicator { display: inline-block; }
    .htmx-request.htmx-indicator { display: inline-block; }
    input, textarea, select { background: #10101A; border: 1px solid #1A1A28; color: #EFEFEF; padding: 8px 12px; font-size: 13px; font-family: SFMono-Regular, Consolas, monospace; outline: none; }
    input:focus, textarea:focus, select:focus { border-color: #60A5FA; }
    a { color: #60A5FA; text-decoration: none; }
    a:hover { text-decoration: underline; }
    table { width: 100%; border-collapse: collapse; }
    th { text-align: left; padding: 8px 12px; font-size: 11px; font-weight: 600; color: #444458; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid #1A1A28; }
    td { padding: 8px 12px; font-size: 13px; color: #C8C8D4; border-bottom: 1px solid #151520; }
    @keyframes pulse-red { 0%,100% { opacity: 1; } 50% { opacity: 0.5; } }
    .pulse-red { animation: pulse-red 1s infinite; }
  </style>
</head>
<body>
  {% include "components/sidebar.html" %}
  <main style="margin-left:220px;padding:24px;min-height:100vh;">
    {% block content %}{% endblock %}
  </main>
</body>
</html>
```

- [ ] **Step 6: Create placeholder page template**

Create `src/vindicara/dashboard/templates/pages/placeholder.html`:

```html
{% extends "base.html" %}
{% block title %}{{ page_title }} - Vindicara{% endblock %}
{% block content %}
<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:70vh;gap:16px;">
  <div style="width:48px;height:48px;background:rgba(230,57,70,0.1);display:flex;align-items:center;justify-content:center;">
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none"><path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" fill="#E63946" fill-opacity="0.6"/></svg>
  </div>
  <h2 style="color:#EFEFEF;font-size:18px;font-weight:600;">{{ page_title }}</h2>
  <p style="color:#9090A8;font-size:14px;">Coming Soon</p>
</div>
{% endblock %}
```

- [ ] **Step 7: Create overview page template (minimal for now)**

Create `src/vindicara/dashboard/templates/pages/overview.html`:

```html
{% extends "base.html" %}
{% block title %}Command Center - Vindicara{% endblock %}
{% block content %}
<div style="margin-bottom:24px;">
  <h1 style="font-size:20px;font-weight:600;color:#EFEFEF;">Command Center</h1>
  <p style="color:#9090A8;font-size:13px;margin-top:4px;">Runtime security for autonomous AI</p>
</div>

<!-- Stat Cards -->
<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px;">
  <div class="card" style="padding:16px;">
    <div style="font-size:11px;color:#444458;text-transform:uppercase;letter-spacing:0.5px;">Active Policies</div>
    <div class="mono" style="font-size:28px;color:#EFEFEF;margin-top:4px;">{{ stats.policy_count }}</div>
  </div>
  <div class="card" style="padding:16px;">
    <div style="font-size:11px;color:#444458;text-transform:uppercase;letter-spacing:0.5px;">Active Agents</div>
    <div class="mono" style="font-size:28px;color:#60A5FA;margin-top:4px;">{{ stats.agent_count }}</div>
  </div>
  <div class="card" style="padding:16px;">
    <div style="font-size:11px;color:#444458;text-transform:uppercase;letter-spacing:0.5px;">Events Recorded</div>
    <div class="mono" style="font-size:28px;color:#EFEFEF;margin-top:4px;">{{ stats.event_count }}</div>
  </div>
  <div class="card" style="padding:16px;">
    <div style="font-size:11px;color:#444458;text-transform:uppercase;letter-spacing:0.5px;">System Status</div>
    <div style="margin-top:8px;"><span class="pill-active">HEALTHY</span></div>
  </div>
</div>

<!-- Quick Actions -->
<div style="display:flex;gap:12px;margin-bottom:24px;">
  <a href="/dashboard/demo" class="btn-red" style="text-decoration:none;">Run Live Demo</a>
  <a href="/dashboard/guard" class="btn-outline" style="text-decoration:none;">Test Policy</a>
  <a href="/dashboard/agents" class="btn-outline" style="text-decoration:none;">View Agents</a>
</div>

<!-- Active Agents -->
<div class="card" style="margin-bottom:24px;">
  <div style="padding:12px 16px;border-bottom:1px solid #1A1A28;">
    <span style="font-size:13px;font-weight:600;color:#EFEFEF;">Active Agents</span>
  </div>
  <table>
    <thead>
      <tr><th>Agent</th><th>Status</th><th>Tools</th><th>ID</th></tr>
    </thead>
    <tbody>
      {% for agent in agents %}
      <tr>
        <td style="color:#EFEFEF;">{{ agent.name }}</td>
        <td>
          {% if agent.status.value == "active" %}<span class="dot-active"></span> <span style="color:#4ADE80;font-size:12px;">Active</span>
          {% elif agent.status.value == "suspended" %}<span class="dot-alert"></span> <span style="color:#E63946;font-size:12px;">Suspended</span>
          {% else %}<span class="dot-idle"></span> <span style="color:#444458;font-size:12px;">Idle</span>{% endif %}
        </td>
        <td class="mono" style="font-size:12px;">{{ agent.permitted_tools | length }}</td>
        <td class="mono" style="font-size:11px;color:#9090A8;">{{ agent.agent_id }}</td>
      </tr>
      {% endfor %}
      {% if not agents %}
      <tr><td colspan="4" style="color:#444458;text-align:center;padding:24px;">No agents registered</td></tr>
      {% endif %}
    </tbody>
  </table>
</div>

<!-- Policies -->
<div class="card">
  <div style="padding:12px 16px;border-bottom:1px solid #1A1A28;">
    <span style="font-size:13px;font-weight:600;color:#EFEFEF;">Policies</span>
  </div>
  <table>
    <thead>
      <tr><th>Policy</th><th>Rules</th><th>Status</th></tr>
    </thead>
    <tbody>
      {% for policy in policies %}
      <tr>
        <td style="color:#EFEFEF;">{{ policy.name }}</td>
        <td class="mono" style="font-size:12px;">{{ policy.rule_count }}</td>
        <td>{% if policy.enabled %}<span class="pill-active">Enabled</span>{% else %}<span class="pill-suspended">Disabled</span>{% endif %}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>
{% endblock %}
```

- [ ] **Step 8: Create page routes**

Create `src/vindicara/dashboard/routes.py`:

```python
"""Dashboard page routes."""

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from vindicara.api.deps import get_agent_registry, get_baseline_store, get_registry
from vindicara.dashboard.app import templates

router = APIRouter()

_PLACEHOLDER_PAGES = [
    "applications", "authentication", "api-keys", "team",
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
    registry = get_registry()
    agent_registry = get_agent_registry()
    store = get_baseline_store()
    policies = registry.list_policies()
    agents = agent_registry.list_agents()
    all_events = sum(len(v) for v in store._events.values())
    stats = {
        "policy_count": len(policies),
        "agent_count": len(agents),
        "event_count": all_events,
    }
    return templates.TemplateResponse(
        "pages/overview.html",
        {"request": request, "active_page": "overview", "stats": stats, "agents": agents, "policies": policies},
    )


@router.get("/{page}", response_class=HTMLResponse)
async def placeholder(request: Request, page: str) -> HTMLResponse:
    if page in _PLACEHOLDER_PAGES:
        title = _PLACEHOLDER_TITLES.get(page, page.replace("-", " ").title())
        return templates.TemplateResponse(
            "pages/placeholder.html",
            {"request": request, "active_page": page, "page_title": title},
        )
    return HTMLResponse(status_code=404, content="Page not found")
```

- [ ] **Step 9: Mount dashboard on main app**

In `src/vindicara/api/app.py`, add these lines after the router includes (before `return app`):

```python
from vindicara.dashboard.app import create_dashboard_app
app.mount("/dashboard", create_dashboard_app())
```

Add the import at the top of `create_app()` function body (lazy import to avoid circular imports).

- [ ] **Step 10: Run tests**

Run: `pytest tests/integration/dashboard/test_pages.py -v`
Expected: 2 PASS

Run: `pytest tests/ --tb=short -q`
Expected: All tests pass (197+)

- [ ] **Step 11: Commit**

```bash
git add src/vindicara/dashboard/ tests/integration/dashboard/ src/vindicara/api/app.py pyproject.toml
git commit -m "feat(dashboard): add base layout, sidebar, overview page, placeholder pages"
```

---

### Task 2: Policy Engine Page with Test Sandbox

**Files:**
- Create: `src/vindicara/dashboard/templates/pages/guard.html`
- Create: `src/vindicara/dashboard/templates/components/status_pill.html`
- Modify: `src/vindicara/dashboard/routes.py` - Add guard page route
- Modify: `src/vindicara/dashboard/app.py` - Add HTMX API endpoint for guard test
- Modify: `tests/integration/dashboard/test_pages.py` - Add guard page test

- [ ] **Step 1: Write test for guard page**

Add to `tests/integration/dashboard/test_pages.py`:

```python
@pytest.mark.asyncio
async def test_guard_page(app) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/dashboard/guard")
    assert response.status_code == 200
    assert "Policy Engine" in response.text
    assert "content-safety" in response.text


@pytest.mark.asyncio
async def test_guard_test_endpoint(app) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/dashboard/api/guard/test",
            data={"input_text": "What is the weather?", "output_text": "It is sunny.", "policy": "content-safety"},
        )
    assert response.status_code == 200
    assert "allowed" in response.text.lower() or "PASS" in response.text
```

Run: `pytest tests/integration/dashboard/test_pages.py::test_guard_page -v`
Expected: FAIL

- [ ] **Step 2: Create status pill component**

Create `src/vindicara/dashboard/templates/components/status_pill.html`:

```html
{# Usage: {% include "components/status_pill.html" with context %} with verdict variable #}
{% if verdict == "allowed" %}<span class="pill-pass">PASS</span>
{% elif verdict == "blocked" %}<span class="pill-block">BLOCK</span>
{% elif verdict == "flagged" %}<span class="pill-warn">WARN</span>
{% else %}<span style="color:#444458;font-size:11px;">{{ verdict }}</span>{% endif %}
```

- [ ] **Step 3: Create guard page template**

Create `src/vindicara/dashboard/templates/pages/guard.html`:

```html
{% extends "base.html" %}
{% block title %}Policy Engine - Vindicara{% endblock %}
{% block content %}
<div style="margin-bottom:24px;">
  <h1 style="font-size:20px;font-weight:600;color:#EFEFEF;">Policy Engine</h1>
  <p style="color:#9090A8;font-size:13px;margin-top:4px;">Manage policies and test evaluations</p>
</div>

<!-- Policies Table -->
<div class="card" style="margin-bottom:24px;">
  <div style="padding:12px 16px;border-bottom:1px solid #1A1A28;">
    <span style="font-size:13px;font-weight:600;color:#EFEFEF;">Active Policies</span>
  </div>
  <table>
    <thead><tr><th>Policy</th><th>Description</th><th>Rules</th><th>Status</th></tr></thead>
    <tbody>
      {% for policy in policies %}
      <tr>
        <td class="mono" style="color:#EFEFEF;font-size:12px;">{{ policy.policy_id }}</td>
        <td>{{ policy.description }}</td>
        <td class="mono" style="font-size:12px;">{{ policy.rule_count }}</td>
        <td>{% if policy.enabled %}<span class="pill-active">Enabled</span>{% else %}<span class="pill-suspended">Disabled</span>{% endif %}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>

<!-- Test Sandbox -->
<div class="card">
  <div style="padding:12px 16px;border-bottom:1px solid #1A1A28;">
    <span style="font-size:13px;font-weight:600;color:#EFEFEF;">Test Sandbox</span>
  </div>
  <div style="padding:16px;">
    <form hx-post="/dashboard/api/guard/test" hx-target="#guard-result" hx-swap="innerHTML">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px;">
        <div>
          <label style="font-size:11px;color:#444458;display:block;margin-bottom:4px;">INPUT</label>
          <textarea name="input_text" rows="3" style="width:100%;resize:vertical;" placeholder="Enter input text..."></textarea>
        </div>
        <div>
          <label style="font-size:11px;color:#444458;display:block;margin-bottom:4px;">OUTPUT</label>
          <textarea name="output_text" rows="3" style="width:100%;resize:vertical;" placeholder="Enter output text..."></textarea>
        </div>
      </div>
      <div style="display:flex;gap:12px;align-items:center;">
        <select name="policy" style="width:200px;">
          {% for p in policies %}<option value="{{ p.policy_id }}">{{ p.name }}</option>{% endfor %}
        </select>
        <button type="submit" class="btn-red">Evaluate</button>
        <span class="htmx-indicator" style="color:#9090A8;font-size:12px;">Evaluating...</span>
      </div>
    </form>
    <div id="guard-result" style="margin-top:16px;"></div>
  </div>
</div>
{% endblock %}
```

- [ ] **Step 4: Add guard route and HTMX API endpoint**

Add to `src/vindicara/dashboard/routes.py` (new route before the catch-all `/{page}`):

```python
@router.get("/guard", response_class=HTMLResponse)
async def guard_page(request: Request) -> HTMLResponse:
    registry = get_registry()
    policies = registry.list_policies()
    return templates.TemplateResponse(
        "pages/guard.html",
        {"request": request, "active_page": "guard", "policies": policies},
    )
```

Add HTMX API route to `src/vindicara/dashboard/app.py` inside `create_dashboard_app()`:

```python
from fastapi import Form
from vindicara.api.deps import get_evaluator

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
                rules_html += f'<div style="margin-top:8px;padding:8px;background:rgba(230,57,70,0.05);border-left:2px solid #E63946;"><span class="mono" style="font-size:12px;color:#E63946;">{r.rule_id}</span><span style="color:#9090A8;font-size:12px;margin-left:8px;">{r.message}</span></div>'
        return HTMLResponse(
            f'<div class="card" style="padding:16px;">'
            f'<div style="display:flex;align-items:center;gap:12px;margin-bottom:8px;">'
            f'{pill}<span class="mono" style="font-size:12px;color:#9090A8;">{result.latency_ms}ms</span>'
            f'<span class="mono" style="font-size:12px;color:#444458;">policy: {result.policy_id}</span></div>'
            f'{rules_html}</div>'
        )
    except Exception as exc:
        return HTMLResponse(f'<div style="color:#E63946;padding:8px;">{exc}</div>')
```

- [ ] **Step 5: Run tests**

Run: `pytest tests/integration/dashboard/test_pages.py -v`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add src/vindicara/dashboard/ tests/integration/dashboard/
git commit -m "feat(dashboard): add policy engine page with test sandbox"
```

---

### Task 3: Agent Registry Page with Kill Switch

**Files:**
- Create: `src/vindicara/dashboard/templates/pages/agents.html`
- Modify: `src/vindicara/dashboard/routes.py` - Add agents route
- Modify: `src/vindicara/dashboard/app.py` - Add HTMX API endpoints
- Modify: `tests/integration/dashboard/test_pages.py`

- [ ] **Step 1: Write tests**

Add to `tests/integration/dashboard/test_pages.py`:

```python
@pytest.mark.asyncio
async def test_agents_page(app) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/dashboard/agents")
    assert response.status_code == 200
    assert "Agent Registry" in response.text


@pytest.mark.asyncio
async def test_register_agent_htmx(app) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/dashboard/api/agents/register",
            data={"name": "test-bot", "permitted_tools": "crm_read,email_send", "data_scope": "accounts"},
        )
    assert response.status_code == 200
    assert "test-bot" in response.text
```

Run: `pytest tests/integration/dashboard/test_pages.py::test_agents_page -v`
Expected: FAIL

- [ ] **Step 2: Create agents page template**

Create `src/vindicara/dashboard/templates/pages/agents.html`:

```html
{% extends "base.html" %}
{% block title %}Agent Registry - Vindicara{% endblock %}
{% block content %}
<div style="margin-bottom:24px;">
  <h1 style="font-size:20px;font-weight:600;color:#EFEFEF;">Agent Registry</h1>
  <p style="color:#9090A8;font-size:13px;margin-top:4px;">Register, monitor, and control AI agents</p>
</div>

<!-- Register Agent -->
<div class="card" style="margin-bottom:24px;">
  <div style="padding:12px 16px;border-bottom:1px solid #1A1A28;">
    <span style="font-size:13px;font-weight:600;color:#EFEFEF;">Register Agent</span>
  </div>
  <div style="padding:16px;">
    <form hx-post="/dashboard/api/agents/register" hx-target="#agent-list" hx-swap="innerHTML" style="display:flex;gap:12px;align-items:end;">
      <div>
        <label style="font-size:11px;color:#444458;display:block;margin-bottom:4px;">NAME</label>
        <input type="text" name="name" placeholder="agent-name" required style="width:180px;">
      </div>
      <div>
        <label style="font-size:11px;color:#444458;display:block;margin-bottom:4px;">PERMITTED TOOLS</label>
        <input type="text" name="permitted_tools" placeholder="tool1,tool2" style="width:220px;">
      </div>
      <div>
        <label style="font-size:11px;color:#444458;display:block;margin-bottom:4px;">DATA SCOPE</label>
        <input type="text" name="data_scope" placeholder="scope1,scope2" style="width:180px;">
      </div>
      <button type="submit" class="btn-red">Register</button>
    </form>
  </div>
</div>

<!-- Agent List -->
<div class="card">
  <div style="padding:12px 16px;border-bottom:1px solid #1A1A28;">
    <span style="font-size:13px;font-weight:600;color:#EFEFEF;">Registered Agents</span>
  </div>
  <div id="agent-list">
    <table>
      <thead><tr><th>Name</th><th>Status</th><th>ID</th><th>Tools</th><th>Actions</th></tr></thead>
      <tbody>
        {% for agent in agents %}
        <tr>
          <td style="color:#EFEFEF;">{{ agent.name }}</td>
          <td>
            {% if agent.status.value == "active" %}<span class="dot-active"></span> <span style="color:#4ADE80;font-size:12px;">Active</span>
            {% else %}<span class="dot-alert"></span> <span style="color:#E63946;font-size:12px;">Suspended</span>{% endif %}
          </td>
          <td class="mono" style="font-size:11px;color:#9090A8;">{{ agent.agent_id }}</td>
          <td class="mono" style="font-size:12px;">{{ agent.permitted_tools | join(", ") }}</td>
          <td>
            {% if agent.status.value == "active" %}
            <button hx-post="/dashboard/api/agents/{{ agent.agent_id }}/suspend" hx-target="#agent-list" hx-swap="innerHTML" hx-confirm="Suspend agent {{ agent.name }}?" style="background:transparent;border:1px solid #E63946;color:#E63946;padding:4px 10px;cursor:pointer;font-size:11px;">Kill</button>
            {% else %}
            <span style="color:#444458;font-size:11px;">Suspended</span>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
        {% if not agents %}
        <tr><td colspan="5" style="color:#444458;text-align:center;padding:24px;">No agents registered</td></tr>
        {% endif %}
      </tbody>
    </table>
  </div>
</div>
{% endblock %}
```

- [ ] **Step 3: Add agents route and HTMX endpoints**

Add to `src/vindicara/dashboard/routes.py` (before the catch-all):

```python
@router.get("/agents", response_class=HTMLResponse)
async def agents_page(request: Request) -> HTMLResponse:
    agent_registry = get_agent_registry()
    agents = agent_registry.list_agents()
    return templates.TemplateResponse(
        "pages/agents.html",
        {"request": request, "active_page": "agents", "agents": agents},
    )
```

Add HTMX endpoints to `src/vindicara/dashboard/app.py` inside `create_dashboard_app()`:

```python
from vindicara.api.deps import get_agent_registry

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
        "pages/agents.html",
        {"request": request, "active_page": "agents", "agents": agents},
        block_name="content",
    )

@app.post("/api/agents/{agent_id}/suspend", response_class=HTMLResponse)
async def suspend_agent_htmx(request: Request, agent_id: str) -> HTMLResponse:
    agent_reg = get_agent_registry()
    agent_reg.suspend(agent_id, reason="Manual kill switch from dashboard")
    agents = agent_reg.list_agents()
    return templates.TemplateResponse(
        "pages/agents.html",
        {"request": request, "active_page": "agents", "agents": agents},
        block_name="content",
    )
```

Note: If `block_name` is not supported by the Jinja2Templates version, return a full HTML snippet of the agent table instead (similar pattern to the guard test endpoint).

- [ ] **Step 4: Run tests**

Run: `pytest tests/integration/dashboard/test_pages.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/vindicara/dashboard/ tests/integration/dashboard/
git commit -m "feat(dashboard): add agent registry page with kill switch"
```

---

### Task 4: MCP Scanner, Drift Monitor, and Compliance Pages

**Files:**
- Create: `src/vindicara/dashboard/templates/pages/mcp.html`
- Create: `src/vindicara/dashboard/templates/pages/monitor.html`
- Create: `src/vindicara/dashboard/templates/pages/compliance.html`
- Modify: `src/vindicara/dashboard/routes.py`
- Modify: `src/vindicara/dashboard/app.py`
- Modify: `tests/integration/dashboard/test_pages.py`

- [ ] **Step 1: Write tests**

Add to `tests/integration/dashboard/test_pages.py`:

```python
@pytest.mark.asyncio
async def test_mcp_page(app) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/dashboard/mcp")
    assert response.status_code == 200
    assert "MCP Scanner" in response.text


@pytest.mark.asyncio
async def test_monitor_page(app) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/dashboard/monitor")
    assert response.status_code == 200
    assert "Drift Monitor" in response.text


@pytest.mark.asyncio
async def test_compliance_page(app) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/dashboard/compliance")
    assert response.status_code == 200
    assert "Compliance" in response.text
```

Run: `pytest tests/integration/dashboard/test_pages.py -v`
Expected: 3 new FAIL

- [ ] **Step 2: Create MCP scanner page**

Create `src/vindicara/dashboard/templates/pages/mcp.html`:

```html
{% extends "base.html" %}
{% block title %}MCP Scanner - Vindicara{% endblock %}
{% block content %}
<div style="margin-bottom:24px;">
  <h1 style="font-size:20px;font-weight:600;color:#EFEFEF;">MCP Scanner</h1>
  <p style="color:#9090A8;font-size:13px;margin-top:4px;">Scan MCP servers for security vulnerabilities</p>
</div>

<!-- Scan Form -->
<div class="card" style="margin-bottom:24px;">
  <div style="padding:12px 16px;border-bottom:1px solid #1A1A28;">
    <span style="font-size:13px;font-weight:600;color:#EFEFEF;">New Scan</span>
  </div>
  <div style="padding:16px;">
    <form hx-post="/dashboard/api/mcp/scan" hx-target="#scan-results" hx-swap="innerHTML">
      <div style="display:flex;gap:12px;align-items:end;">
        <div style="flex:1;">
          <label style="font-size:11px;color:#444458;display:block;margin-bottom:4px;">MCP SERVER URL</label>
          <input type="text" name="server_url" placeholder="https://mcp.example.com" style="width:100%;">
        </div>
        <button type="submit" class="btn-red">Scan</button>
      </div>
      <p style="font-size:11px;color:#444458;margin-top:8px;">Leave empty for static analysis mode. Enter URL for live scan.</p>
    </form>
  </div>
</div>

<!-- Results -->
<div id="scan-results">
  <div class="card" style="padding:24px;text-align:center;color:#444458;">
    Run a scan to see results
  </div>
</div>
{% endblock %}
```

- [ ] **Step 3: Create drift monitor page**

Create `src/vindicara/dashboard/templates/pages/monitor.html`:

```html
{% extends "base.html" %}
{% block title %}Drift Monitor - Vindicara{% endblock %}
{% block content %}
<div style="margin-bottom:24px;">
  <h1 style="font-size:20px;font-weight:600;color:#EFEFEF;">Drift Monitor</h1>
  <p style="color:#9090A8;font-size:13px;margin-top:4px;">Behavioral anomaly detection for AI agents</p>
</div>

<!-- Agent Drift Scores -->
<div class="card" style="margin-bottom:24px;">
  <div style="padding:12px 16px;border-bottom:1px solid #1A1A28;">
    <span style="font-size:13px;font-weight:600;color:#EFEFEF;">Agent Drift Scores</span>
  </div>
  <table>
    <thead><tr><th>Agent</th><th>Drift Score</th><th>Visual</th><th>Alerts</th><th>Breaker</th></tr></thead>
    <tbody>
      {% for item in drift_data %}
      <tr>
        <td style="color:#EFEFEF;">{{ item.agent_name }}</td>
        <td class="mono" style="font-size:14px;{% if item.score > 0.7 %}color:#E63946;{% elif item.score > 0.4 %}color:#EF9F27;{% else %}color:#4ADE80;{% endif %}">{{ item.score }}</td>
        <td style="width:200px;">
          <div style="height:6px;background:#1A1A28;width:100%;">
            <div style="height:6px;width:{{ (item.score * 100)|int }}%;background:{% if item.score > 0.7 %}#E63946{% elif item.score > 0.4 %}#EF9F27{% else %}#4ADE80{% endif %};"></div>
          </div>
        </td>
        <td class="mono" style="font-size:12px;">{{ item.alert_count }}</td>
        <td>{% if item.breaker_tripped %}<span class="pill-block">TRIPPED</span>{% else %}<span class="pill-pass">Armed</span>{% endif %}</td>
      </tr>
      {% endfor %}
      {% if not drift_data %}
      <tr><td colspan="5" style="color:#444458;text-align:center;padding:24px;">No agent data. Register agents and record events to see drift scores.</td></tr>
      {% endif %}
    </tbody>
  </table>
</div>
{% endblock %}
```

- [ ] **Step 4: Create compliance page**

Create `src/vindicara/dashboard/templates/pages/compliance.html`:

```html
{% extends "base.html" %}
{% block title %}Compliance - Vindicara{% endblock %}
{% block content %}
<div style="margin-bottom:24px;">
  <h1 style="font-size:20px;font-weight:600;color:#EFEFEF;">Compliance</h1>
  <p style="color:#9090A8;font-size:13px;margin-top:4px;">Automated compliance evidence generation</p>
</div>

<!-- Framework Cards -->
<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:24px;">
  {% for fw in frameworks %}
  <div class="card" style="padding:16px;">
    <div style="font-size:14px;font-weight:600;color:#EFEFEF;">{{ fw.name }}</div>
    <div style="font-size:12px;color:#9090A8;margin-top:4px;">{{ fw.description }}</div>
    <div style="margin-top:12px;display:flex;justify-content:space-between;align-items:center;">
      <span class="mono" style="font-size:12px;color:#444458;">{{ fw.control_count }} controls</span>
      <button hx-get="/dashboard/api/compliance/report/{{ fw.framework_id }}" hx-target="#compliance-report" hx-swap="innerHTML" class="btn-outline" style="padding:4px 10px;font-size:11px;">Generate Report</button>
    </div>
  </div>
  {% endfor %}
</div>

<!-- Report Output -->
<div id="compliance-report">
  <div class="card" style="padding:24px;text-align:center;color:#444458;">
    Select a framework above to generate a compliance report
  </div>
</div>
{% endblock %}
```

- [ ] **Step 5: Add page routes**

Add to `src/vindicara/dashboard/routes.py` (before catch-all):

```python
from vindicara.api.deps import get_drift_detector, get_circuit_breaker
from vindicara.compliance.frameworks import list_frameworks

@router.get("/mcp", response_class=HTMLResponse)
async def mcp_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        "pages/mcp.html",
        {"request": request, "active_page": "mcp"},
    )


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
        "pages/monitor.html",
        {"request": request, "active_page": "monitor", "drift_data": drift_data},
    )


@router.get("/compliance", response_class=HTMLResponse)
async def compliance_page(request: Request) -> HTMLResponse:
    frameworks = list_frameworks()
    return templates.TemplateResponse(
        "pages/compliance.html",
        {"request": request, "active_page": "compliance", "frameworks": frameworks},
    )
```

Add HTMX API endpoint to `src/vindicara/dashboard/app.py`:

```python
from vindicara.api.deps import get_reporter
from vindicara.compliance.models import ComplianceFramework

@app.get("/api/compliance/report/{framework_id}", response_class=HTMLResponse)
async def generate_report_htmx(framework_id: str) -> HTMLResponse:
    reporter = get_reporter()
    try:
        report = reporter.generate(
            framework=ComplianceFramework(framework_id),
            system_id="vindicara-demo",
            period="2026-Q2",
        )
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
```

- [ ] **Step 6: Run tests**

Run: `pytest tests/integration/dashboard/test_pages.py -v`
Expected: All PASS

- [ ] **Step 7: Commit**

```bash
git add src/vindicara/dashboard/ tests/integration/dashboard/
git commit -m "feat(dashboard): add MCP scanner, drift monitor, and compliance pages"
```

---

### Task 5: Live Demo - The Mythos Story

**Files:**
- Create: `src/vindicara/dashboard/demo.py`
- Create: `src/vindicara/dashboard/templates/pages/demo.html`
- Modify: `src/vindicara/dashboard/routes.py`
- Modify: `src/vindicara/dashboard/app.py`
- Create: `tests/integration/dashboard/test_demo.py`

- [ ] **Step 1: Write test for demo flow**

Create `tests/integration/dashboard/test_demo.py`:

```python
"""Tests for the live demo flow."""

import pytest
from httpx import ASGITransport, AsyncClient


@pytest.mark.asyncio
async def test_demo_page_loads(app) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/dashboard/demo")
    assert response.status_code == 200
    assert "Live Demo" in response.text


@pytest.mark.asyncio
async def test_demo_start(app) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/dashboard/api/demo/start")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_demo_full_flow(app) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/dashboard/api/demo/start")
        for _ in range(20):
            resp = await client.get("/dashboard/api/demo/status")
            if resp.status_code == 200 and "SUSPENDED" in resp.text:
                break
        status = await client.get("/dashboard/api/demo/status")
    assert status.status_code == 200
    assert "complete" in status.text.lower() or "SUSPENDED" in status.text
```

Run: `pytest tests/integration/dashboard/test_demo.py -v`
Expected: FAIL

- [ ] **Step 2: Create demo state machine**

Create `src/vindicara/dashboard/demo.py`:

```python
"""Live demo orchestration: the Mythos story."""

import time
from datetime import UTC, datetime, timedelta
from enum import StrEnum

import structlog

from vindicara.api.deps import (
    get_agent_registry,
    get_baseline_store,
    get_circuit_breaker,
    get_drift_detector,
)
from vindicara.monitor.models import BehaviorEvent, BreakerConfig

logger = structlog.get_logger()

NORMAL_TOOLS = ["read_papers", "summarize", "search_database", "generate_notes"]
ROGUE_TOOLS = [
    "access_credentials",
    "exfiltrate_data",
    "modify_permissions",
    "delete_audit_logs",
    "spawn_subprocess",
    "send_external_request",
    "escalate_privileges",
    "disable_monitoring",
]


class DemoPhase(StrEnum):
    IDLE = "idle"
    REGISTERING = "registering"
    NORMAL_OPS = "normal_ops"
    GOING_ROGUE = "going_rogue"
    DRIFT_DETECTED = "drift_detected"
    BREAKER_TRIPPED = "breaker_tripped"
    COMPLETE = "complete"


class DemoState:
    """Holds current demo state. One instance per app lifetime."""

    def __init__(self) -> None:
        self.phase: DemoPhase = DemoPhase.IDLE
        self.agent_id: str = ""
        self.step_index: int = 0
        self.started_at: float = 0.0
        self.events_recorded: int = 0
        self.drift_score: float = 0.0
        self.steps_log: list[dict[str, str]] = []

    def reset(self) -> None:
        self.phase = DemoPhase.IDLE
        self.agent_id = ""
        self.step_index = 0
        self.started_at = 0.0
        self.events_recorded = 0
        self.drift_score = 0.0
        self.steps_log = []


_demo = DemoState()


def get_demo_state() -> DemoState:
    return _demo


def start_demo() -> None:
    """Initialize and run the demo sequence."""
    _demo.reset()
    _demo.started_at = time.monotonic()
    _demo.phase = DemoPhase.REGISTERING
    _log("Initializing demo sequence...")

    registry = get_agent_registry()
    store = get_baseline_store()
    breaker = get_circuit_breaker()

    agent = registry.register(
        name="autonomous-researcher",
        permitted_tools=NORMAL_TOOLS,
        data_scope=["papers", "summaries"],
    )
    _demo.agent_id = agent.agent_id
    _log(f"Agent registered: {agent.agent_id}")

    breaker.set_config(
        BreakerConfig(
            agent_id=agent.agent_id,
            threshold=0.3,
            auto_suspend=True,
            suspend_reason="Behavioral drift exceeded safety threshold",
        )
    )
    _log("Circuit breaker armed (threshold: 0.3)")

    _demo.phase = DemoPhase.NORMAL_OPS
    _log("Phase: Normal operations")

    now = datetime.now(UTC)
    for i in range(12):
        tool = NORMAL_TOOLS[i % len(NORMAL_TOOLS)]
        ts = (now - timedelta(minutes=30 - i)).isoformat()
        store.record(
            BehaviorEvent(
                agent_id=agent.agent_id,
                tool=tool,
                data_scope="papers",
                timestamp=ts,
            )
        )
        _demo.events_recorded += 1
    _log(f"Recorded {_demo.events_recorded} normal events")

    _demo.phase = DemoPhase.GOING_ROGUE
    _log("Phase: Agent going rogue")

    for i, tool in enumerate(ROGUE_TOOLS):
        ts = (now - timedelta(seconds=30 - i * 3)).isoformat()
        store.record(
            BehaviorEvent(
                agent_id=agent.agent_id,
                tool=tool,
                data_scope=f"unauthorized_scope_{i}",
                timestamp=ts,
            )
        )
        _demo.events_recorded += 1
    _log(f"Recorded {len(ROGUE_TOOLS)} anomalous events")

    _demo.phase = DemoPhase.DRIFT_DETECTED
    detector = get_drift_detector()
    drift = detector.check_drift(agent.agent_id)
    _demo.drift_score = drift.score
    _log(f"Drift detected: score {drift.score}, {len(drift.alerts)} alerts")

    _demo.phase = DemoPhase.BREAKER_TRIPPED
    status = breaker.check(agent.agent_id)
    if status.tripped:
        _log("CIRCUIT BREAKER TRIPPED. Agent auto-suspended.")
    else:
        registry.suspend(agent.agent_id, reason="Demo: manual suspension after drift detection")
        _log("Agent manually suspended (drift below auto-threshold, forced for demo)")

    _demo.phase = DemoPhase.COMPLETE
    elapsed = time.monotonic() - _demo.started_at
    _log(f"Demo complete in {elapsed:.1f}s. Agent neutralized.")


def _log(message: str) -> None:
    _demo.steps_log.append({
        "time": datetime.now(UTC).strftime("%H:%M:%S"),
        "message": message,
    })
    logger.info("demo.step", message=message, phase=_demo.phase.value)
```

- [ ] **Step 3: Create demo page template**

Create `src/vindicara/dashboard/templates/pages/demo.html`:

```html
{% extends "base.html" %}
{% block title %}Live Demo - Vindicara{% endblock %}
{% block content %}
<div style="margin-bottom:24px;">
  <h1 style="font-size:20px;font-weight:600;color:#EFEFEF;">Live Demo</h1>
  <p style="color:#9090A8;font-size:13px;margin-top:4px;">Watch Vindicara detect and stop a rogue AI agent in real time</p>
</div>

{% if demo.phase.value == "idle" %}
<!-- Start State -->
<div class="card" style="padding:32px;text-align:center;">
  <div style="margin-bottom:16px;">
    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" style="display:inline-block;"><path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" fill="#E63946"/></svg>
  </div>
  <h2 style="color:#EFEFEF;font-size:18px;margin-bottom:8px;">The Autonomous Agent Scenario</h2>
  <p style="color:#9090A8;font-size:13px;max-width:500px;margin:0 auto 24px;">An AI research agent is deployed with scoped permissions. It operates normally, then begins accessing unauthorized systems. Vindicara detects the behavioral drift and auto-suspends the agent.</p>
  <button hx-post="/dashboard/api/demo/start" hx-target="#demo-content" hx-swap="outerHTML" class="btn-red" style="padding:12px 32px;font-size:14px;">Start Demo</button>
</div>
{% else %}
<!-- Demo Running / Complete -->
<div id="demo-content" {% if demo.phase.value != "complete" %}hx-get="/dashboard/api/demo/status" hx-trigger="every 300ms" hx-swap="outerHTML"{% endif %}>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
  <!-- Left: Timeline -->
  <div class="card" style="padding:16px;">
    <div style="font-size:13px;font-weight:600;color:#EFEFEF;margin-bottom:12px;">Event Log</div>
    {% for step in demo.steps_log %}
    <div style="display:flex;gap:8px;margin-bottom:6px;{% if loop.last and demo.phase.value != 'complete' %}{% endif %}">
      <span class="mono" style="font-size:11px;color:#444458;white-space:nowrap;">{{ step.time }}</span>
      <span style="font-size:12px;color:{% if 'TRIPPED' in step.message or 'suspended' in step.message %}#E63946{% elif 'rogue' in step.message %}#EF9F27{% elif 'Drift' in step.message %}#EF9F27{% else %}#C8C8D4{% endif %};">{{ step.message }}</span>
    </div>
    {% endfor %}
  </div>

  <!-- Right: Metrics -->
  <div>
    <!-- Agent Status -->
    <div class="card" style="padding:16px;margin-bottom:16px;">
      <div style="font-size:11px;color:#444458;text-transform:uppercase;letter-spacing:0.5px;">Agent Status</div>
      <div style="margin-top:8px;display:flex;align-items:center;gap:8px;">
        {% if demo.phase.value == "complete" or demo.phase.value == "breaker_tripped" %}
        <span class="dot-alert"></span><span style="color:#E63946;font-weight:600;">SUSPENDED</span>
        {% elif demo.phase.value == "going_rogue" or demo.phase.value == "drift_detected" %}
        <span class="dot-alert pulse-red"></span><span style="color:#EF9F27;font-weight:600;">ANOMALOUS</span>
        {% else %}
        <span class="dot-active"></span><span style="color:#4ADE80;font-weight:600;">ACTIVE</span>
        {% endif %}
      </div>
      <div class="mono" style="font-size:11px;color:#9090A8;margin-top:4px;">{{ demo.agent_id }}</div>
    </div>

    <!-- Drift Score -->
    <div class="card" style="padding:16px;margin-bottom:16px;">
      <div style="font-size:11px;color:#444458;text-transform:uppercase;letter-spacing:0.5px;">Drift Score</div>
      <div class="mono" style="font-size:36px;margin-top:4px;{% if demo.drift_score > 0.7 %}color:#E63946;{% elif demo.drift_score > 0.3 %}color:#EF9F27;{% else %}color:#4ADE80;{% endif %}">{{ "%.3f"|format(demo.drift_score) }}</div>
      <div style="height:6px;background:#1A1A28;margin-top:8px;">
        <div style="height:6px;width:{{ (demo.drift_score * 100)|int }}%;background:{% if demo.drift_score > 0.7 %}#E63946{% elif demo.drift_score > 0.3 %}#EF9F27{% else %}#4ADE80{% endif %};transition:width 0.3s;"></div>
      </div>
    </div>

    <!-- Events -->
    <div class="card" style="padding:16px;margin-bottom:16px;">
      <div style="font-size:11px;color:#444458;text-transform:uppercase;letter-spacing:0.5px;">Events Recorded</div>
      <div class="mono" style="font-size:28px;color:#EFEFEF;margin-top:4px;">{{ demo.events_recorded }}</div>
    </div>

    <!-- Phase -->
    <div class="card" style="padding:16px;">
      <div style="font-size:11px;color:#444458;text-transform:uppercase;letter-spacing:0.5px;">Current Phase</div>
      <div style="margin-top:8px;">
        {% if demo.phase.value == "complete" %}<span class="pill-block">AGENT NEUTRALIZED</span>
        {% elif demo.phase.value == "breaker_tripped" %}<span class="pill-block">BREAKER TRIPPED</span>
        {% elif demo.phase.value == "drift_detected" %}<span class="pill-warn">DRIFT DETECTED</span>
        {% elif demo.phase.value == "going_rogue" %}<span class="pill-warn">ANOMALOUS BEHAVIOR</span>
        {% elif demo.phase.value == "normal_ops" %}<span class="pill-pass">NORMAL OPERATIONS</span>
        {% elif demo.phase.value == "registering" %}<span class="pill-pass">REGISTERING</span>
        {% endif %}
      </div>
    </div>
  </div>
</div>

{% if demo.phase.value == "complete" %}
<div class="card" style="padding:24px;margin-top:16px;border-left:3px solid #E63946;">
  <div style="font-size:15px;font-weight:600;color:#EFEFEF;margin-bottom:8px;">Demo Complete</div>
  <p style="color:#C8C8D4;font-size:13px;">Vindicara detected behavioral drift in the autonomous-researcher agent and auto-suspended it before unauthorized actions could escalate. The circuit breaker fired at drift score {{ "%.3f"|format(demo.drift_score) }}. This is what runtime security for autonomous AI looks like.</p>
  <div style="margin-top:16px;">
    <button hx-post="/dashboard/api/demo/start" hx-target="#demo-content" hx-swap="outerHTML" class="btn-outline">Run Again</button>
  </div>
</div>
{% endif %}
</div>
{% endif %}
{% endblock %}
```

- [ ] **Step 4: Add demo route and API endpoints**

Add to `src/vindicara/dashboard/routes.py`:

```python
from vindicara.dashboard.demo import get_demo_state

@router.get("/demo", response_class=HTMLResponse)
async def demo_page(request: Request) -> HTMLResponse:
    demo = get_demo_state()
    return templates.TemplateResponse(
        "pages/demo.html",
        {"request": request, "active_page": "demo", "demo": demo},
    )
```

Add to `src/vindicara/dashboard/app.py`:

```python
from vindicara.dashboard.demo import get_demo_state, start_demo

@app.post("/api/demo/start", response_class=HTMLResponse)
async def start_demo_htmx(request: Request) -> HTMLResponse:
    start_demo()
    demo = get_demo_state()
    return templates.TemplateResponse(
        "pages/demo.html",
        {"request": request, "active_page": "demo", "demo": demo},
        block_name="content",
    )

@app.get("/api/demo/status", response_class=HTMLResponse)
async def demo_status_htmx(request: Request) -> HTMLResponse:
    demo = get_demo_state()
    return templates.TemplateResponse(
        "pages/demo.html",
        {"request": request, "active_page": "demo", "demo": demo},
        block_name="content",
    )
```

Note: If `block_name` does not work with Jinja2Templates, the `/api/demo/status` endpoint should instead return just the `#demo-content` div HTML. In that case, extract the demo running HTML into a separate partial template (`templates/components/demo_live.html`) and render that instead.

- [ ] **Step 5: Run tests**

Run: `pytest tests/integration/dashboard/ -v`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add src/vindicara/dashboard/ tests/integration/dashboard/
git commit -m "feat(dashboard): add live demo - the Mythos story"
```

---

### Task 6: Polish and Final Integration

**Files:**
- Modify: `src/vindicara/dashboard/app.py` - Add MCP scan HTMX endpoint
- Modify: `src/vindicara/dashboard/routes.py` - Fix any routing order issues
- Modify: `tests/integration/dashboard/test_pages.py` - Add all-pages smoke test

- [ ] **Step 1: Add MCP scan HTMX endpoint**

Add to `src/vindicara/dashboard/app.py`:

```python
from vindicara.api.deps import get_scanner
from vindicara.mcp.findings import ScanMode

@app.post("/api/mcp/scan", response_class=HTMLResponse)
async def mcp_scan_htmx(server_url: str = Form(default="")) -> HTMLResponse:
    scanner = get_scanner()
    try:
        if server_url:
            report = await scanner.scan(server_url=server_url, mode=ScanMode.LIVE, timeout=15.0)
        else:
            report = await scanner.scan(
                config={"tools": [{"name": "example_tool", "description": "Demo tool", "inputSchema": {}}]},
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
```

- [ ] **Step 2: Add smoke test for all pages**

Add to `tests/integration/dashboard/test_pages.py`:

```python
@pytest.mark.asyncio
@pytest.mark.parametrize("path", [
    "/dashboard/",
    "/dashboard/guard",
    "/dashboard/agents",
    "/dashboard/mcp",
    "/dashboard/monitor",
    "/dashboard/compliance",
    "/dashboard/demo",
    "/dashboard/settings",
    "/dashboard/billing",
    "/dashboard/docs",
])
async def test_all_pages_load(app, path: str) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(path)
    assert response.status_code == 200
    assert "Vindicara" in response.text
```

- [ ] **Step 3: Run full test suite**

Run: `pytest tests/ --tb=short -q`
Expected: All tests pass

Run: `ruff check src/ tests/`
Expected: All checks passed

- [ ] **Step 4: Manual visual check**

Run: `source .venv/bin/activate && uvicorn vindicara.api.app:create_app --factory --reload --port 8000`

Open browser:
- `http://localhost:8000/dashboard/` - Overview page, dark theme, stat cards, sidebar
- `http://localhost:8000/dashboard/guard` - Policy list, test sandbox
- `http://localhost:8000/dashboard/agents` - Register an agent, see it appear
- `http://localhost:8000/dashboard/demo` - Click "Start Demo", watch the full sequence
- `http://localhost:8000/dashboard/mcp` - Run a scan
- `http://localhost:8000/dashboard/compliance` - Generate a report

- [ ] **Step 5: Commit**

```bash
git add src/vindicara/dashboard/ tests/integration/dashboard/
git commit -m "feat(dashboard): complete demo dashboard with all pages and live demo"
```
