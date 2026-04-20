#!/usr/bin/env python3
"""
CTFN Data MCP Server — OAuth 2.1 Resource Server.

Wraps the CTFNDATA risk-metrics API as MCP tools. Authentication is delegated
to Auth0 as an OAuth 2.1 Authorization Server (with Dynamic Client Registration
and PKCE). This process validates Auth0-issued RS256 JWTs via JWKS.

Runs as a streamable-HTTP MCP server on Railway.
"""
import os
import sys
import time
from contextlib import asynccontextmanager

try:
    import httpx
except ImportError:
    print("ERROR: httpx not installed. Run: pip install httpx", file=sys.stderr)
    sys.exit(1)

try:
    import jwt as pyjwt
except ImportError:
    print("ERROR: PyJWT[crypto] not installed. Run: pip install 'PyJWT[crypto]'", file=sys.stderr)
    sys.exit(1)

from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# Upstream CTFNDATA REST API
API_BASE = os.environ.get("CTFNDATA_API_BASE", "https://ctfndata.onrender.com")
API_USER = os.environ.get("CTFNDATA_USER", "deanemcrobie@gmail.com")
API_PASS = os.environ.get("CTFNDATA_PASS", "")

# Auth0 as Authorization Server
AUTH0_DOMAIN = os.environ["AUTH0_DOMAIN"]  # e.g. dev-co8yw00rdyijudwk.us.auth0.com
AUTH0_AUDIENCE = os.environ["AUTH0_AUDIENCE"]  # must match the API Identifier in Auth0
AUTH0_ISSUER = f"https://{AUTH0_DOMAIN}/"
AUTH0_JWKS_URL = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"

# This server's public URL (used in Protected Resource Metadata and
# WWW-Authenticate resource_metadata hints)
SERVER_URL = os.environ.get(
    "SERVER_URL",
    "https://ctfndata-mcp-server-production.up.railway.app",
).rstrip("/")

# ---------------------------------------------------------------------------
# JWKS-backed JWT validator (PyJWT caches keys automatically)
# ---------------------------------------------------------------------------
_jwks_client = pyjwt.PyJWKClient(AUTH0_JWKS_URL, cache_keys=True)


def _verify_jwt(token: str) -> dict | None:
    """Validate an Auth0 RS256 JWT. Returns claims dict on success, None on failure."""
    try:
        signing_key = _jwks_client.get_signing_key_from_jwt(token)
        claims = pyjwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=AUTH0_AUDIENCE,
            issuer=AUTH0_ISSUER,
        )
        return claims
    except Exception as e:
        print(f"JWT validation failed: {e}", file=sys.stderr)
        return None


def _extract_bearer(request: Request) -> str | None:
    """Extract bearer token from the Authorization header."""
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    return None


def _www_authenticate(error: str | None = None) -> str:
    """Build an RFC 6750 / MCP-compliant WWW-Authenticate header value."""
    parts = [f'Bearer realm="CTFN Data MCP"']
    if error:
        parts.append(f'error="{error}"')
    parts.append(f'resource_metadata="{SERVER_URL}/.well-known/oauth-protected-resource"')
    return ", ".join(parts)


# ---------------------------------------------------------------------------
# OAuth discovery / health endpoints
# ---------------------------------------------------------------------------
async def protected_resource_metadata(request: Request) -> JSONResponse:
    """RFC 9728 Protected Resource Metadata.

    Advertises which Authorization Server can mint tokens for this resource.
    Claude Desktop fetches this after getting a 401 with WWW-Authenticate.
    """
    return JSONResponse({
        "resource": AUTH0_AUDIENCE,
        "authorization_servers": [AUTH0_ISSUER.rstrip("/")],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
    })


async def health_endpoint(request: Request) -> JSONResponse:
    """Public health check — no auth required."""
    return JSONResponse({
        "status": "ok",
        "auth": "oauth2.1-auth0",
        "authorization_server": AUTH0_ISSUER.rstrip("/"),
        "audience": AUTH0_AUDIENCE,
    })


# ---------------------------------------------------------------------------
# OAuth middleware — protects /mcp routes
# ---------------------------------------------------------------------------
class OAuthMiddleware(BaseHTTPMiddleware):
    """Validates Auth0-issued bearer tokens on /mcp requests."""

    async def dispatch(self, request: Request, call_next):
        # Only protect /mcp; everything else passes through (health, discovery)
        if not request.url.path.startswith("/mcp"):
            return await call_next(request)

        token = _extract_bearer(request)
        if not token:
            return JSONResponse(
                {"error": "unauthorized", "error_description": "Bearer token required"},
                status_code=401,
                headers={"WWW-Authenticate": _www_authenticate()},
            )

        claims = _verify_jwt(token)
        if not claims:
            return JSONResponse(
                {
                    "error": "invalid_token",
                    "error_description": "Token invalid, expired, or audience/issuer mismatch",
                },
                status_code=401,
                headers={"WWW-Authenticate": _www_authenticate(error="invalid_token")},
            )

        # Attach claims for tools/logging downstream
        request.state.user = claims
        return await call_next(request)


# ---------------------------------------------------------------------------
# Upstream CTFNDATA API client (unchanged)
# ---------------------------------------------------------------------------
_api_token: str | None = None
_api_token_expiry: float = 0.0


def _get_api_token() -> str:
    """Authenticate against the upstream CTFNDATA API and cache the bearer token."""
    global _api_token, _api_token_expiry
    if _api_token and time.time() < _api_token_expiry - 60:
        return _api_token
    resp = httpx.post(
        f"{API_BASE}/login",
        json={"username": API_USER, "password": API_PASS},
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    _api_token = data["access_token"]
    _api_token_expiry = time.time() + data.get("expires_in", 14400)
    return _api_token


def _api_get(path: str, params: dict | None = None) -> dict:
    """Make an authenticated GET request to the upstream CTFNDATA API."""
    global _api_token
    token = _get_api_token()
    resp = httpx.get(
        f"{API_BASE}{path}",
        params=params,
        headers={"Authorization": f"Bearer {token}"},
        timeout=20,
    )
    if resp.status_code == 401:
        _api_token = None
        token = _get_api_token()
        resp = httpx.get(
            f"{API_BASE}{path}",
            params=params,
            headers={"Authorization": f"Bearer {token}"},
            timeout=20,
        )
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# MCP Server & Tools
# ---------------------------------------------------------------------------
mcp = FastMCP(
    "ctfndata",
    instructions=(
        "CTFN Data connector — provides real-time M&A risk metrics from the "
        "CTFNDATA platform. Query break prices, spreads, annualized spreads, "
        "chance of close, risk/reward ratios, and more for active M&A deals. "
        "Use ctfndata_lookup for a specific metric, ctfndata_all for a full "
        "deal snapshot, ctfndata_search to find deals, and ctfndata_deals to "
        "list all tracked deals."
    ),
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    ),
    streamable_http_path="/",
)

AVAILABLE_PARAMS = [
    "target", "acquirer", "listing", "pre_deal", "break", "now", "offer",
    "spread", "ann_spread", "chance_of_close", "risk_reward",
    "gross_spread", "gross_downside", "downside_rt", "premium",
    "ann_date", "close_date", "currency", "deal_type", "deal_status",
    "consideration", "sector", "break_1w", "chance_1w", "updated",
]
META_PARAMS = ["deal_count", "deals", "loaded", "params"]


@mcp.tool()
def ctfndata_lookup(ticker: str, param: str) -> dict:
    """Look up a single M&A risk metric for a deal by ticker.

    Args:
        ticker: Stock ticker symbol (e.g. "ROKU", "HIMS", "SAVE").
        param: The metric to retrieve. Available params:
               target, acquirer, listing, pre_deal, break, now, offer,
               spread, ann_spread, chance_of_close, risk_reward,
               gross_spread, gross_downside, downside_rt, premium,
               ann_date, close_date, currency, deal_type, deal_status,
               consideration, sector, break_1w, chance_1w, updated.
    Returns:
        Dict with the ticker, param name, and value.
    """
    try:
        return _api_get("/api/ctfndata", params={"ticker": ticker.upper(), "param": param.lower()})
    except httpx.HTTPStatusError as e:
        return {"error": f"API error {e.response.status_code}: {e.response.text}"}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def ctfndata_all(ticker: str) -> dict:
    """Get ALL risk metrics for a single M&A deal by ticker.

    Args:
        ticker: Stock ticker symbol (e.g. "ROKU", "HIMS").
    Returns:
        Dict with all available metrics for the deal.
    """
    try:
        return _api_get("/api/ctfndata/all", params={"ticker": ticker.upper()})
    except httpx.HTTPStatusError as e:
        return {"error": f"API error {e.response.status_code}: {e.response.text}"}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def ctfndata_search(query: str, limit: int = 20) -> dict:
    """Search for M&A deals by company name, ticker, or keyword.

    Args:
        query: Search term (e.g. "Disney", "tech", "ROKU").
        limit: Maximum results to return. Default 20.
    Returns:
        Dict with matching deals and their key metrics.
    """
    try:
        return _api_get("/api/ctfndata/search", params={"q": query, "limit": limit})
    except httpx.HTTPStatusError as e:
        return {"error": f"API error {e.response.status_code}: {e.response.text}"}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def ctfndata_deals() -> dict:
    """List all currently tracked M&A deals.

    Returns:
        Dict with deal_count and list of deals (ticker + target name).
    """
    try:
        return _api_get("/api/ctfndata", params={"param": "deals"})
    except httpx.HTTPStatusError as e:
        return {"error": f"API error {e.response.status_code}: {e.response.text}"}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def ctfndata_deal_count() -> dict:
    """Get the total number of M&A deals currently tracked.

    Returns:
        Dict with the current deal count.
    """
    try:
        return _api_get("/api/ctfndata", params={"param": "deal_count"})
    except httpx.HTTPStatusError as e:
        return {"error": f"API error {e.response.status_code}: {e.response.text}"}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def ctfndata_health() -> dict:
    """Check the health/status of the CTFNDATA backend API.

    Returns:
        Dict with status, deal count, and last update time.
    """
    try:
        resp = httpx.get(f"{API_BASE}/health", timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Entry point — composite Starlette app
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8080))
    mcp_app = mcp.streamable_http_app()

    @asynccontextmanager
    async def lifespan(app):
        async with mcp.session_manager.run():
            yield

    app = Starlette(
        routes=[
            Route(
                "/.well-known/oauth-protected-resource",
                protected_resource_metadata,
                methods=["GET"],
            ),
            Route("/health", health_endpoint, methods=["GET"]),
            Mount("/mcp", app=mcp_app),
        ],
        middleware=[
            Middleware(OAuthMiddleware),
        ],
        lifespan=lifespan,
    )

    uvicorn.run(app, host="0.0.0.0", port=port, proxy_headers=True, forwarded_allow_ips="*")
