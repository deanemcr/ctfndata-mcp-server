#!/usr/bin/env python3
"""
CTFN Data MCP Server — exposes CTFNDATA risk-metrics API as MCP tools.

Wraps the REST API at ctfndata.onrender.com so Claude can query
M&A break prices, spreads, odds, and risk/reward metrics directly.

Includes JWT authentication with PostgreSQL user storage.
Users log in once per month and include the token in the MCP URL.

Runs as a streamable-HTTP MCP server (for Railway remote deployment).
"""

import os
import sys
import time
import json
import datetime

try:
    import httpx
except ImportError:
    print("ERROR: httpx not installed. Run: pip install httpx", file=sys.stderr)
    sys.exit(1)

try:
    import jwt as pyjwt
except ImportError:
    print("ERROR: PyJWT not installed. Run: pip install PyJWT", file=sys.stderr)
    sys.exit(1)

try:
    import bcrypt
except ImportError:
    print("ERROR: bcrypt not installed. Run: pip install bcrypt", file=sys.stderr)
    sys.exit(1)

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    print("ERROR: psycopg2 not installed. Run: pip install psycopg2-binary", file=sys.stderr)
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

API_BASE = os.environ.get("CTFNDATA_API_BASE", "https://ctfndata.onrender.com")
API_USER = os.environ.get("CTFNDATA_USER", "deanemcrobie@gmail.com")
API_PASS = os.environ.get("CTFNDATA_PASS", "Mambopoa1!")

DATABASE_URL = os.environ.get("DATABASE_URL", "")
JWT_SECRET = os.environ.get("JWT_SECRET", "change-me-in-production")
JWT_EXPIRY_DAYS = int(os.environ.get("JWT_EXPIRY_DAYS", "30"))

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------


def _get_db():
    """Get a PostgreSQL connection."""
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL not configured")
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = True
    return conn


def _init_db():
    """Create the users table if it doesn't exist."""
    try:
        conn = _get_db()
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    is_admin BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT NOW(),
                    last_login TIMESTAMP
                )
            """)
        conn.close()
        print("Database initialized (users table ready)", file=sys.stderr)
    except Exception as e:
        print(f"WARNING: Database init failed: {e}", file=sys.stderr)
        print("Server will start but auth features won't work without DATABASE_URL", file=sys.stderr)


def _verify_user(username: str, password: str) -> dict | None:
    """Verify username/password against the database. Returns user dict or None."""
    conn = _get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
        cur.execute("SELECT id, username, password_hash, is_admin FROM users WHERE username = %s", (username,))
        row = cur.fetchone()
        if row and bcrypt.checkpw(password.encode("utf-8"), row["password_hash"].encode("utf-8")):
            # Update last_login
            cur.execute("UPDATE users SET last_login = NOW() WHERE id = %s", (row["id"],))
            conn.close()
            return {"id": row["id"], "username": row["username"], "is_admin": row["is_admin"]}
    conn.close()
    return None


def _create_user(username: str, password: str, is_admin: bool = False) -> dict:
    """Create a new user. Returns the user dict."""
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    conn = _get_db()
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO users (username, password_hash, is_admin) VALUES (%s, %s, %s) RETURNING id",
            (username, password_hash, is_admin),
        )
        user_id = cur.fetchone()[0]
    conn.close()
    return {"id": user_id, "username": username, "is_admin": is_admin}


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------


def _create_jwt(user: dict) -> str:
    """Create a JWT token for a user, valid for JWT_EXPIRY_DAYS."""
    payload = {
        "sub": user["username"],
        "uid": user["id"],
        "admin": user.get("is_admin", False),
        "iat": datetime.datetime.now(datetime.timezone.utc),
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=JWT_EXPIRY_DAYS),
    }
    return pyjwt.encode(payload, JWT_SECRET, algorithm="HS256")


def _verify_jwt(token: str) -> dict | None:
    """Verify and decode a JWT token. Returns payload or None."""
    try:
        payload = pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except pyjwt.ExpiredSignatureError:
        return None
    except pyjwt.InvalidTokenError:
        return None


# ---------------------------------------------------------------------------
# Auth endpoints (Starlette routes)
# ---------------------------------------------------------------------------


async def login_endpoint(request: Request) -> JSONResponse:
    """POST /auth/login — authenticate and receive a JWT token."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    username = body.get("username", "").strip()
    password = body.get("password", "")

    if not username or not password:
        return JSONResponse({"error": "username and password required"}, status_code=400)

    try:
        user = _verify_user(username, password)
    except Exception as e:
        return JSONResponse({"error": f"Database error: {e}"}, status_code=500)

    if not user:
        return JSONResponse({"error": "Invalid credentials"}, status_code=401)

    token = _create_jwt(user)
    return JSONResponse({
        "access_token": token,
        "token_type": "bearer",
        "expires_in_days": JWT_EXPIRY_DAYS,
        "username": user["username"],
        "message": (
            f"Token valid for {JWT_EXPIRY_DAYS} days. "
            "Add to your MCP connector URL as: "
            "https://YOUR-HOST/mcp?token=YOUR_TOKEN"
        ),
    })


async def register_endpoint(request: Request) -> JSONResponse:
    """POST /auth/register — create a new user (admin-only, or first user is auto-admin)."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    username = body.get("username", "").strip()
    password = body.get("password", "")
    is_admin = body.get("is_admin", False)

    if not username or not password:
        return JSONResponse({"error": "username and password required"}, status_code=400)

    if len(password) < 8:
        return JSONResponse({"error": "Password must be at least 8 characters"}, status_code=400)

    # Check if this is the first user (auto-promote to admin)
    try:
        conn = _get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM users")
            user_count = cur.fetchone()[0]
        conn.close()
    except Exception as e:
        return JSONResponse({"error": f"Database error: {e}"}, status_code=500)

    if user_count == 0:
        # First user is always admin
        is_admin = True
    else:
        # Require admin token for subsequent registrations
        token = _extract_token(request)
        if not token:
            return JSONResponse({"error": "Admin token required to register new users"}, status_code=401)
        payload = _verify_jwt(token)
        if not payload or not payload.get("admin"):
            return JSONResponse({"error": "Only admins can register new users"}, status_code=403)

    try:
        user = _create_user(username, password, is_admin)
    except psycopg2.errors.UniqueViolation:
        return JSONResponse({"error": f"Username '{username}' already exists"}, status_code=409)
    except Exception as e:
        return JSONResponse({"error": f"Database error: {e}"}, status_code=500)

    token = _create_jwt(user)
    return JSONResponse({
        "message": f"User '{username}' created successfully",
        "is_admin": is_admin,
        "access_token": token,
        "expires_in_days": JWT_EXPIRY_DAYS,
    }, status_code=201)


async def health_endpoint(request: Request) -> JSONResponse:
    """GET /health — public health check."""
    db_ok = False
    try:
        conn = _get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM users")
            user_count = cur.fetchone()[0]
        conn.close()
        db_ok = True
    except Exception:
        user_count = -1

    return JSONResponse({
        "status": "ok",
        "database": "connected" if db_ok else "unavailable",
        "users": user_count,
        "auth": "jwt",
        "token_expiry_days": JWT_EXPIRY_DAYS,
    })


# ---------------------------------------------------------------------------
# Auth middleware — protects /mcp routes
# ---------------------------------------------------------------------------


def _extract_token(request: Request) -> str | None:
    """Extract JWT from query param or Authorization header."""
    # 1. Check query parameter ?token=xxx
    token = request.query_params.get("token")
    if token:
        return token

    # 2. Check Authorization: Bearer xxx header
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()

    return None


class JWTAuthMiddleware(BaseHTTPMiddleware):
    """Middleware that requires a valid JWT for /mcp requests."""

    async def dispatch(self, request: Request, call_next):
        # Only protect /mcp paths
        if request.url.path.startswith("/mcp"):
            token = _extract_token(request)
            if not token:
                return JSONResponse(
                    {"error": "Authentication required. Get a token via POST /auth/login"},
                    status_code=401,
                )
            payload = _verify_jwt(token)
            if not payload:
                return JSONResponse(
                    {"error": "Token expired or invalid. Get a new token via POST /auth/login"},
                    status_code=401,
                )
            # Attach user info to request state
            request.state.user = payload

        return await call_next(request)


# ---------------------------------------------------------------------------
# CTFNDATA API client (upstream)
# ---------------------------------------------------------------------------

# Token cache for the upstream CTFNDATA API
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
    expires_in = data.get("expires_in", 14400)
    _api_token_expiry = time.time() + expires_in
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

    # Initialize database on startup
    _init_db()

    port = int(os.environ.get("PORT", 8080))

    # Get the MCP ASGI app
    mcp_app = mcp.streamable_http_app()

    # Build composite app: auth routes + JWT-protected MCP
    app = Starlette(
        routes=[
            Route("/auth/login", login_endpoint, methods=["POST"]),
            Route("/auth/register", register_endpoint, methods=["POST"]),
            Route("/health", health_endpoint, methods=["GET"]),
            Mount("/mcp", app=mcp_app),
        ],
        middleware=[
            Middleware(JWTAuthMiddleware),
        ],
    )

    uvicorn.run(app, host="0.0.0.0", port=port, proxy_headers=True, forwarded_allow_ips="*")
