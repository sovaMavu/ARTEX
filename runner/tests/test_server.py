"""MCP tool surface, auth middleware, and body-limit tests."""

from __future__ import annotations

import asyncio

import httpx
import pytest
from fastmcp import Client
from starlette.responses import JSONResponse

from runner.config import Config
from runner.errors import INVALID_ARGUMENT, JOB_NOT_FOUND, SCOPE_MISSING
from runner.server import BearerAuthMiddleware, BodyLimitMiddleware, build_app, build_server


def test_tool_surface_is_fixed(config):
    mcp, _runner = build_server(config)

    async def run():
        async with Client(mcp) as client:
            tools = await client.list_tools()
            return [tool.name for tool in tools]

    names = asyncio.run(run())
    assert names == [
        "net_nmap",
        "net_dns",
        "net_tls",
        "net_snmp",
        "net_smb",
        "net_ldap",
        "net_ssh",
        "job_wait",
        "job_cancel",
    ]


def test_missing_scope_returns_structured_error(config):
    mcp, _runner = build_server(config)

    async def run():
        async with Client(mcp) as client:
            result = await client.call_tool(
                "net_nmap",
                {"task_id": 1, "target": "10.0.0.1", "profile": "top100", "wait_s": 0},
            )
            return result.data

    data = asyncio.run(run())
    assert data["schema"] == "artex.runner.v1"
    assert data["ok"] is False
    assert data["error"]["code"] == SCOPE_MISSING


def test_invalid_tool_arguments_return_invalid_argument(config):
    mcp, _runner = build_server(config)

    async def run():
        async with Client(mcp) as client:
            result = await client.call_tool(
                "net_nmap",
                {"task_id": 1, "target": "10.0.0.1", "profile": "custom"},
            )
            return result.data

    data = asyncio.run(run())
    assert data["error"]["code"] == INVALID_ARGUMENT
    assert data["error"]["details"]["fields"]


def test_job_wait_and_cancel_validation(config):
    mcp, _runner = build_server(config)

    async def run():
        async with Client(mcp) as client:
            bad = await client.call_tool("job_wait", {"job_id": "not-a-ulid"})
            missing = await client.call_tool(
                "job_cancel", {"job_id": "01J00000000000000000000000"}
            )
            return bad.data, missing.data

    bad, missing = asyncio.run(run())
    assert bad["error"]["code"] == INVALID_ARGUMENT
    assert missing["error"]["code"] == JOB_NOT_FOUND


def test_app_exposes_healthz_and_mcp(config):
    app = build_app(config)
    paths = {getattr(route, "path", None) for route in app.router.routes}
    assert "/healthz" in paths
    assert "/mcp" in paths


# ---------------------------------------------------------------------------
# Middleware unit tests (no FastMCP lifespan needed)
# ---------------------------------------------------------------------------


async def _echo_app(scope, receive, send):
    body = b""
    while True:
        message = await receive()
        if message["type"] != "http.request":
            continue
        body += message.get("body", b"")
        if not message.get("more_body", False):
            break
    response = JSONResponse({"bytes": len(body), "path": scope.get("path")})
    await response(scope, receive, send)


def middleware_app(token: str = "x" * 32, max_bytes: int = 16):
    return BearerAuthMiddleware(
        BodyLimitMiddleware(_echo_app, max_bytes=max_bytes),
        token=token,
        path="/mcp",
    )


def request(method: str, path: str, **kwargs):
    async def run():
        transport = httpx.ASGITransport(app=middleware_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(run())


def test_auth_requires_bearer_token():
    assert request("POST", "/mcp", content=b"{}").status_code == 401
    assert request(
        "POST", "/mcp", content=b"{}", headers={"Authorization": "Bearer wrong"}
    ).status_code == 401
    assert request(
        "POST", "/mcp", content=b"{}", headers={"Authorization": "Basic eA=="}
    ).status_code == 401


def test_auth_accepts_exact_token():
    response = request(
        "POST",
        "/mcp",
        content=b"{}",
        headers={"Authorization": "Bearer " + "x" * 32},
    )
    assert response.status_code == 200
    assert response.json()["bytes"] == 2


def test_healthz_is_not_authenticated():
    assert request("GET", "/healthz").status_code == 200


def test_body_limit_rejects_oversized_request():
    response = request(
        "POST",
        "/mcp",
        content=b"x" * 100,
        headers={"Authorization": "Bearer " + "x" * 32},
    )
    assert response.status_code == 413


def test_body_limit_accepts_bounded_request():
    response = request(
        "POST",
        "/mcp",
        content=b"x" * 10,
        headers={"Authorization": "Bearer " + "x" * 32},
    )
    assert response.status_code == 200
    assert response.json()["bytes"] == 10
