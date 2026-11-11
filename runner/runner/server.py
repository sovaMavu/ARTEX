"""FastMCP Streamable HTTP server, bearer auth, and liveness endpoint."""

from __future__ import annotations

import atexit
import logging
import secrets
import sys
from typing import Any, Awaitable, Callable

import uvicorn
from fastmcp import FastMCP
from starlette.datastructures import Headers
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

from . import audit
from .config import Config, ConfigError
from .tools.net import Runner, register_tools

logger = logging.getLogger("artex.runner")

ASGIReceive = Callable[[], Awaitable[dict[str, Any]]]
ASGISend = Callable[[dict[str, Any]], Awaitable[None]]


async def _plain(
    scope: dict[str, Any],
    receive: ASGIReceive,
    send: ASGISend,
    status: int,
    body: str,
    headers: dict[str, str] | None = None,
) -> None:
    response = PlainTextResponse(body, status_code=status, headers=headers)
    await response(scope, receive, send)


class BodyLimitMiddleware:
    """Reject oversized request bodies before they reach FastMCP.

    MCP JSON-RPC requests are small; buffering up to ``max_bytes`` keeps the
    limit deterministic even when a client omits ``Content-Length``.
    """

    def __init__(self, app: Any, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = int(max_bytes)

    async def __call__(self, scope: dict[str, Any], receive: ASGIReceive, send: ASGISend) -> None:
        if scope.get("type") != "http" or scope.get("method") not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        raw_length = headers.get("content-length")
        if raw_length is not None:
            try:
                declared = int(raw_length)
            except ValueError:
                await _plain(scope, receive, send, 400, "invalid content-length")
                return
            if declared < 0 or declared > self.max_bytes:
                await _plain(scope, receive, send, 413, "request body too large")
                return

        chunks: list[bytes] = []
        total = 0
        while True:
            message = await receive()
            if message.get("type") == "http.disconnect":
                return
            if message.get("type") != "http.request":
                continue
            body = message.get("body", b"") or b""
            total += len(body)
            if total > self.max_bytes:
                await _plain(scope, receive, send, 413, "request body too large")
                return
            chunks.append(body)
            if not message.get("more_body", False):
                break

        payload = b"".join(chunks)
        replayed = False

        async def replay() -> dict[str, Any]:
            nonlocal replayed
            if replayed:
                return {"type": "http.request", "body": b"", "more_body": False}
            replayed = True
            return {"type": "http.request", "body": payload, "more_body": False}

        await self.app(scope, replay, send)


class BearerAuthMiddleware:
    """Constant-time bearer auth for the MCP endpoint only."""

    def __init__(self, app: Any, token: str, path: str = "/mcp") -> None:
        self.app = app
        self._token = token.encode("utf-8")
        self._path = path.rstrip("/")

    async def __call__(self, scope: dict[str, Any], receive: ASGIReceive, send: ASGISend) -> None:
        if scope.get("type") == "http":
            request_path = str(scope.get("path") or "").rstrip("/")
            if request_path == self._path:
                headers = Headers(scope=scope)
                authorization = headers.get("authorization") or ""
                scheme, _, value = authorization.partition(" ")
                supplied = value.strip().encode("utf-8")
                if scheme.lower() != "bearer" or not secrets.compare_digest(
                    supplied, self._token
                ):
                    await _plain(
                        scope,
                        receive,
                        send,
                        401,
                        "",
                        {"WWW-Authenticate": "Bearer"},
                    )
                    return
        await self.app(scope, receive, send)


def build_server(config: Config) -> tuple[FastMCP, Runner]:
    """Create the FastMCP server and the typed tool runner."""

    mcp = FastMCP("kali_runner")
    runner = Runner(config)
    if config.net_pack_enabled():
        register_tools(mcp, runner)
    else:
        audit.audit("warn", event="tool_packs", packs=list(config.tool_packs), message="net pack disabled")
    return mcp, runner


def build_app(config: Config) -> Any:
    """Build the ASGI app.  Kept separate so tests can use it directly."""

    mcp, runner = build_server(config)
    app = mcp.http_app(path="/mcp", stateless_http=True)

    async def healthz(_request: Any) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    app.router.routes.insert(0, Route("/healthz", healthz, methods=["GET"]))
    # Last added middleware is outermost: auth runs before body buffering, so
    # an unauthenticated oversized request still gets a bare 401.
    app.add_middleware(BodyLimitMiddleware, max_bytes=config.max_request_bytes)
    app.add_middleware(BearerAuthMiddleware, token=config.token, path="/mcp")
    app.state.runner = runner
    atexit.register(runner.jobs.shutdown)
    audit.audit(
        "info",
        event="startup",
        tool_packs=list(config.tool_packs),
        scope_dir=str(config.scope_dir),
        artifact_root=str(config.artifact_root),
    )
    return app


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stdout,
    )


def main() -> None:
    try:
        config = Config.from_env()
    except ConfigError as exc:
        sys.stderr.write(f"runner configuration error: {exc}\n")
        raise SystemExit(2)
    configure_logging(config.log_level)
    app = build_app(config)
    uvicorn_log_level = "warning" if config.log_level == "warn" else config.log_level
    uvicorn.run(
        app,
        host=config.host,
        port=config.port,
        log_level=uvicorn_log_level,
        access_log=False,
    )


if __name__ == "__main__":  # pragma: no cover
    main()
