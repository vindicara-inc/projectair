"""Tests for dashboard page routes."""

import pytest
from httpx import ASGITransport, AsyncClient


@pytest.mark.asyncio
async def test_login_page_accessible(app) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/dashboard/login")
    assert response.status_code == 200
    assert "Sign in" in response.text


@pytest.mark.asyncio
async def test_signup_page_accessible(app) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/dashboard/signup")
    assert response.status_code == 200
    assert "Create your account" in response.text


@pytest.mark.asyncio
async def test_unauthenticated_redirects_to_login(app) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False) as client:
        response = await client.get("/dashboard/")
    assert response.status_code == 302
    assert "/dashboard/login" in response.headers.get("location", "")


@pytest.mark.asyncio
async def test_overview_page(app, authed_cookies) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", cookies=authed_cookies) as client:
        response = await client.get("/dashboard/")
    assert response.status_code == 200
    assert "Command Center" in response.text


@pytest.mark.asyncio
async def test_guard_page(app, authed_cookies) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", cookies=authed_cookies) as client:
        response = await client.get("/dashboard/guard")
    assert response.status_code == 200
    assert "Policy Engine" in response.text


@pytest.mark.asyncio
async def test_agents_page(app, authed_cookies) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", cookies=authed_cookies) as client:
        response = await client.get("/dashboard/agents")
    assert response.status_code == 200
    assert "Agent Registry" in response.text


@pytest.mark.asyncio
async def test_mcp_page(app, authed_cookies) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", cookies=authed_cookies) as client:
        response = await client.get("/dashboard/mcp")
    assert response.status_code == 200
    assert "MCP Scanner" in response.text


@pytest.mark.asyncio
async def test_monitor_page(app, authed_cookies) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", cookies=authed_cookies) as client:
        response = await client.get("/dashboard/monitor")
    assert response.status_code == 200
    assert "Drift Monitor" in response.text


@pytest.mark.asyncio
async def test_compliance_page(app, authed_cookies) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", cookies=authed_cookies) as client:
        response = await client.get("/dashboard/compliance")
    assert response.status_code == 200
    assert "Compliance" in response.text


@pytest.mark.asyncio
async def test_placeholder_page(app, authed_cookies) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", cookies=authed_cookies) as client:
        response = await client.get("/dashboard/settings")
    assert response.status_code == 200
    assert "Coming Soon" in response.text


@pytest.mark.asyncio
async def test_guard_test_endpoint(app, authed_cookies) -> None:
    csrf = authed_cookies.get("vnd_csrf", "")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", cookies=authed_cookies) as client:
        response = await client.post(
            "/dashboard/api/guard/test",
            data={"input_text": "What is the weather?", "output_text": "It is sunny.", "policy": "content-safety"},
            headers={"X-CSRF-Token": csrf},
        )
    assert response.status_code == 200
    assert "PASS" in response.text


@pytest.mark.asyncio
async def test_register_agent_htmx(app, authed_cookies) -> None:
    csrf = authed_cookies.get("vnd_csrf", "")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", cookies=authed_cookies) as client:
        response = await client.post(
            "/dashboard/api/agents/register",
            data={"name": "test-bot", "permitted_tools": "crm_read,email_send", "data_scope": "accounts"},
            headers={"X-CSRF-Token": csrf},
        )
    assert response.status_code == 200
    assert "test-bot" in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("path", [
    "/dashboard/",
    "/dashboard/guard",
    "/dashboard/agents",
    "/dashboard/mcp",
    "/dashboard/monitor",
    "/dashboard/compliance",
    "/dashboard/settings",
    "/dashboard/billing",
    "/dashboard/docs",
])
async def test_all_pages_return_200(app, authed_cookies, path: str) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", cookies=authed_cookies) as client:
        response = await client.get(path)
    assert response.status_code == 200
