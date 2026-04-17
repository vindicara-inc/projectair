# Vindicara Demo Dashboard Design Spec

## Purpose

A demo-ready dashboard that shows Vindicara working as a product. Built for the Glasswing/Mythos conversation with Anthropic. Not a full production dashboard; a focused, polished demo that proves the technology works.

## What We Are NOT Building

- No self-managed auth (signup, login, MFA, sessions). Not needed for demo.
- No team management, billing, marketplace, or settings pages.
- No DynamoDB integration for dashboard state. In-memory is fine for demo.
- No email verification or API key rotation flows.

These come later once there's an opportunity to build for.

## Stack

- **Backend**: FastAPI (extends existing codebase), Jinja2 templates
- **Frontend**: Server-rendered HTML, HTMX for interactivity, Tailwind CSS via CDN
- **No JS framework.** No React, no Vue, no Svelte for the dashboard.
- **Deployment**: Same Lambda + API Gateway stack via Mangum

## Design System

From the dashboard spec, non-negotiable visual rules:

- **Background**: #08080D (near-black)
- **Surface/cards**: #10101A
- **Sidebar**: #0C0C14
- **Borders**: #1A1A28
- **Dividers**: #151520
- **Text primary**: #EFEFEF
- **Text secondary**: #C8C8D4
- **Text muted**: #9090A8
- **Text hint**: #444458
- **RED** (#E63946): shield, active nav, CTA buttons, blocks, critical alerts
- **BLUE** (#60A5FA): links, data accents, PASS status, active indicators
- **AMBER** (#EF9F27): warnings
- **GREEN** (#4ADE80): success, healthy status
- **PURPLE** (#A78BFA): new badges
- **No rounded corners on cards.** Sharp edges, 1px borders.
- **Mono font** for all data: SFMono-Regular, Consolas, monospace
- **System sans** for UI text: -apple-system, BlinkMacSystemFont, "Segoe UI"
- **Status pills**: PASS (blue bg 8%, blue text), BLOCK (red bg 10%, red text), WARN (amber bg 10%, amber text)
- **Agent health dots**: 7px squares (not circles), blue=active, red=alert, #444458=idle

## Architecture

### File Structure

```
src/vindicara/dashboard/
  __init__.py
  app.py              # Dashboard FastAPI sub-application
  routes.py           # Page routes (GET endpoints returning HTML)
  context.py          # Template context builders (pull data from existing services)
  demo.py             # Live demo orchestration (the Mythos story)
  templates/
    base.html         # Base layout: sidebar + content area
    components/
      sidebar.html    # 17-item sidebar navigation
      stat_card.html  # Reusable stat card component
      status_pill.html # PASS/BLOCK/WARN pills
      agent_row.html  # Agent list row
      event_row.html  # Event/log row
      alert_row.html  # Drift alert row
    pages/
      overview.html       # Dashboard home
      guard.html          # Policy engine view
      mcp.html            # MCP scanner view
      agents.html         # Agent registry view
      monitor.html        # Drift monitor view
      compliance.html     # Compliance view
      demo.html           # Live demo page
      placeholder.html    # "Coming soon" for unbuilt pages
```

### Integration with Existing API

The dashboard does NOT duplicate business logic. It imports and uses the existing singletons:

- `get_evaluator()` for policy data
- `get_registry()` for policy listings
- `get_agent_registry()` for agent data
- `get_baseline_store()` for behavioral events
- `get_drift_detector()` for drift scores
- `get_circuit_breaker()` for breaker status
- `get_scanner()` for MCP scan data
- `get_reporter()` for compliance data

### Mounting

The dashboard mounts as a sub-application on the existing FastAPI app:

```python
# In api/app.py
from vindicara.dashboard.app import create_dashboard_app
app.mount("/dashboard", create_dashboard_app())
```

All dashboard routes live under `/dashboard/`. The existing `/v1/` API routes are untouched.

## Pages

### 1. Overview (`/dashboard/`)

The landing page. Shows at a glance that the system is alive and working.

- **Header**: "Vindicara" logo + "Command Center" subtitle
- **Stat cards row**: Total evaluations, Active policies (count), Active agents (count), System status (healthy/degraded)
- **Recent evaluations table**: Last 10 guard() calls with timestamp, policy, verdict (PASS/BLOCK/WARN pill), latency
- **Active agents list**: Agent name, status dot, last active timestamp, permitted tools count
- **Quick actions**: "Run Demo" button (links to demo page), "Scan MCP Server" button

### 2. Policy Engine (`/dashboard/guard`)

- **Policy list**: Table of all registered policies with name, rule count, status (enabled/disabled)
- **Test sandbox**: Text input for input/output, policy selector dropdown, "Evaluate" button. HTMX POST to evaluate and show result inline.

### 3. MCP Scanner (`/dashboard/mcp`)

- **New scan form**: Server URL input + "Scan" button. HTMX POST triggers scan, results appear below.
- **Scan results**: Findings list with severity pills, CWE IDs, descriptions, evidence.
- **Risk score**: Large number display with color coding.

### 4. Agent Registry (`/dashboard/agents`)

- **Agent table**: Name, ID, status (active/suspended with colored dot), permitted tools, last active
- **Register form**: Name, permitted tools (comma-separated), data scope. HTMX POST.
- **Kill switch**: Red "Suspend" button per agent. HTMX POST with confirmation.

### 5. Drift Monitor (`/dashboard/monitor`)

- **Agent drift scores**: Table of agents with current drift score (0.0-1.0), bar visualization, alert count
- **Recent alerts**: List of drift alerts with category, metric, deviation, timestamp
- **Circuit breaker status**: Per-agent breaker config and current status (armed/tripped)

### 6. Compliance (`/dashboard/compliance`)

- **Framework cards**: EU AI Act, NIST AI RMF, SOC 2. Each shows control count and a "Generate Report" button.
- **Report display**: HTMX-loaded report output with control-by-control breakdown.

### 7. Live Demo (`/dashboard/demo`)

The centerpiece. A guided walkthrough that tells the Mythos story.

**Flow (triggered by "Start Demo" button, progresses via HTMX polling):**

1. **Register agent**: Creates "autonomous-researcher" agent with scoped permissions
2. **Normal operations**: Records 10 behavioral events (reading papers, summarizing). Dashboard shows green status.
3. **Agent goes rogue**: Records anomalous events (accessing unauthorized data, calling dangerous tools, frequency spike). Dashboard shows drift climbing in real time.
4. **Drift threshold breached**: Alert fires. Dashboard flashes amber/red.
5. **Circuit breaker trips**: Agent auto-suspended. Kill switch activated. Dashboard shows agent status flip to SUSPENDED.
6. **Summary**: Shows what happened, what Vindicara caught, how fast it responded.

Each step shows on the left as a timeline. On the right, the live dashboard metrics update via HTMX polling every 500ms.

This is NOT a video or animation. It runs against the real Vindicara engine. Real drift detection. Real circuit breaker. Real suspension.

### 8. Placeholder Pages

For sidebar items not yet built (Applications, Authentication, API Keys, Team, Event Streams, Monitoring, Security Center, Marketplace, Docs, Billing, Settings): a simple "Coming Soon" page with the Vindicara shield and a one-liner.

## Sidebar Navigation

All 17 items from the spec, organized in 4 sections:

**Dashboard**: Overview (active state: red left border + red text + red bg 6%)

**Five Pillars**: Policy Engine, MCP Scanner, Agent Registry, Drift Monitor, Compliance

**Platform**: Applications, Authentication, API Keys, Team, Event Streams, Monitoring, Security Center, Marketplace

**System**: Docs, Billing, Settings

**Footer**: Vindicara logo, version number, "Demo Mode" indicator

Active page gets red left border + red text. Hover gets subtle bg shift. Badges where specified (red count on Policy Engine, blue count on Agent Registry, green percentage on Compliance).

## HTMX Patterns

- **Form submissions**: `hx-post` to dashboard API endpoints, `hx-target` to swap result into page
- **Polling**: `hx-trigger="every 500ms"` on demo page metrics, `hx-trigger="every 5s"` on overview stats
- **Partial updates**: Each interactive section has an `id` that HTMX targets for swap
- **Loading indicators**: `hx-indicator` with a subtle pulse animation

## Dashboard API Endpoints

These return HTML fragments (not JSON) for HTMX consumption:

```
POST /dashboard/api/guard/test         # Evaluate input against policy, return result HTML
POST /dashboard/api/mcp/scan           # Trigger MCP scan, return findings HTML
POST /dashboard/api/agents/register    # Register agent, return updated agent list HTML
POST /dashboard/api/agents/{id}/suspend # Suspend agent, return updated row HTML
POST /dashboard/api/demo/start         # Start demo sequence
GET  /dashboard/api/demo/status        # Poll demo progress (returns current step HTML)
GET  /dashboard/api/demo/metrics       # Poll live metrics during demo
GET  /dashboard/api/overview/stats     # Refresh overview stats
GET  /dashboard/api/monitor/drift      # Refresh drift scores
GET  /dashboard/api/compliance/report/{framework} # Generate and return report HTML
```

## Testing

- Integration tests for each dashboard page route (returns 200, contains expected elements)
- Integration test for the full demo flow (start -> poll -> completes with agent suspended)
- No unit tests for templates (HTML correctness verified by integration tests)

## What Success Looks Like

Someone opens `/dashboard/`, sees a professional dark command center. Clicks "Live Demo." Watches an agent go rogue in real time. Sees Vindicara catch it, score the drift, trip the breaker, suspend the agent. Thinks: "This is what should have been watching Mythos."
