#!/usr/bin/env python3
"""
CTFN Data MCP Server — Embedded OAuth 2.1 Authorization Server + Resource Server.

This server acts as its OWN OAuth 2.1 Authorization Server so that MCP clients
(Claude Desktop, etc.) can discover it, perform Dynamic Client Registration,
and obtain access tokens — without the user ever seeing a client_id field.

User authentication is delegated upstream to Auth0 (Universal Login), which
acts as our identity provider via a standard OIDC Authorization Code flow.

Flow (from Claude Desktop's perspective):
  1. User adds custom connector: Name="CTFN Data", URL=this server.
  2. Claude Desktop fetches /.well-known/oauth-protected-resource and the AS
     metadata it points to, then POSTs to /register to get a client_id.
  3. Claude Desktop opens the user's browser to /authorize.
  4. We redirect the browser to Auth0 Universal Login.
  5. User enters username/password; Auth0 redirects back to /callback.
  6. We mint our own short-lived auth code and redirect to Claude's redirect_uri.
  7. Claude POSTs to /token with PKCE verifier; we mint an RS256 JWT.
  8. Claude sends Authorization: Bearer <jwt> to /mcp on every request.

We sign our own tokens (RS256 / JWKS). Auth0 is only used for the Universal
Login page and to look up the user's subject identifier.

Required Railway env vars:
  AUTH0_DOMAIN            dev-co8yw00rdyijudwk.us.auth0.com
  AUTH0_CLIENT_ID         (from the Auth0 Regular Web Application)
  AUTH0_CLIENT_SECRET     (from the Auth0 Regular Web Application)
  MCP_ISSUER              https://ctfndata-mcp-server-production.up.railway.app
  MCP_JWT_SIGNING_KEY     RSA private key PEM (generate: openssl genrsa 2048)
                          Accepts either raw PEM or base64-encoded PEM.
  CTFNDATA_API_BASE       https://ctfndata.onrender.com
  CTFNDATA_USER           (upstream CTFNDATA login)
  CTFNDATA_PASS           (upstream CTFNDATA password)

Auth0 setup:
  1. Create one Regular Web Application.
  2. Allowed Callback URLs: https://ctfndata-mcp-server-production.up.railway.app/callback
  3. Copy the Client ID and Client Secret into Railway.
  4. Create users manually in the Auth0 dashboard (or let users self-sign-up
     if you enable that in the Auth0 tenant).
"""
import base64
import hashlib
import json
import os
import secrets
import sys
import time
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import urlencode

try:
    import httpx
except ImportError:
    print("ERROR: httpx not installed. Run: pip install httpx", file=sys.stderr)
    sys.exit(1)

try:
    import jwt as pyjwt
    from jwt.algorithms import RSAAlgorithm
except ImportError:
    print("ERROR: PyJWT[crypto] not installed. Run: pip install 'PyJWT[crypto]'", file=sys.stderr)
    sys.exit(1)

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("ERROR: cryptography not installed. Run: pip install cryptography", file=sys.stderr)
    sys.exit(1)

from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
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

# This server's public URL. Used as issuer, resource identifier, and audience.
MCP_ISSUER = os.environ.get(
    "MCP_ISSUER",
    "https://ctfndata-mcp-server-production.up.railway.app",
).rstrip("/")

# Upstream IdP (Auth0) — user-facing login page only.
AUTH0_DOMAIN = os.environ["AUTH0_DOMAIN"]
AUTH0_CLIENT_ID = os.environ["AUTH0_CLIENT_ID"]
AUTH0_CLIENT_SECRET = os.environ["AUTH0_CLIENT_SECRET"]
AUTH0_ISSUER = f"https://{AUTH0_DOMAIN}"
AUTH0_AUTHORIZE_URL = f"{AUTH0_ISSUER}/authorize"
AUTH0_TOKEN_URL = f"{AUTH0_ISSUER}/oauth/token"

# Our own RSA signing key for access tokens.
_raw_key = os.environ.get("MCP_JWT_SIGNING_KEY", "").strip()
if not _raw_key:
    print(
        "ERROR: MCP_JWT_SIGNING_KEY env var is required.\n"
        "Generate with: openssl genrsa 2048\n"
        "Paste the full PEM (including BEGIN/END lines) into Railway, or\n"
        "base64-encode the PEM and paste that.",
        file=sys.stderr,
    )
    sys.exit(1)

# Accept either raw PEM (multi-line env var) or base64-encoded PEM (single line).
if not _raw_key.startswith("-----BEGIN"):
    try:
        _raw_key = base64.b64decode(_raw_key).decode("ascii")
    except Exception as e:
        print(f"ERROR: MCP_JWT_SIGNING_KEY is not PEM or base64-PEM: {e}", file=sys.stderr)
        sys.exit(1)

_private_key = serialization.load_pem_private_key(
    _raw_key.encode("ascii"),
    password=None,
    backend=default_backend(),
)
_public_key = _private_key.public_key()
_public_pem = _public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

# Stable kid derived from the public key so rotation is easy.
_kid = hashlib.sha256(_public_pem).hexdigest()[:16]

# Public JWK once at startup.
_public_jwk_raw = RSAAlgorithm.to_jwk(_public_key)
if isinstance(_public_jwk_raw, str):
    _public_jwk = json.loads(_public_jwk_raw)
else:
    _public_jwk = dict(_public_jwk_raw)
_public_jwk["kid"] = _kid
_public_jwk["use"] = "sig"
_public_jwk["alg"] = "RS256"

# ---------------------------------------------------------------------------
# In-memory stores (stateless DCR; short-lived session/code state)
# ---------------------------------------------------------------------------
# authorize sessions: state -> session dict
_authorize_sessions: dict[str, dict[str, Any]] = {}
# our auth codes: code -> record dict
_auth_codes: dict[str, dict[str, Any]] = {}

AUTHORIZE_SESSION_TTL = 600  # 10 minutes
AUTH_CODE_TTL = 60           # 1 minute


def _cleanup_stores() -> None:
    now = time.time()
    for store, ttl in ((_authorize_sessions, AUTHORIZE_SESSION_TTL),
                       (_auth_codes, AUTH_CODE_TTL)):
        expired = [k for k, v in store.items() if now - v.get("created_at", 0) > ttl]
        for k in expired:
            store.pop(k, None)


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sign_client_id(redirect_uris: list[str], client_name: str) -> str:
    """Encode redirect_uris into a signed JWT that serves as the client_id.

    Stateless DCR: we don't store clients; the client_id itself carries
    (signed) the metadata we need to verify /authorize and /token requests.
    """
    payload = {
        "redirect_uris": redirect_uris,
        "client_name": client_name,
        "iat": int(time.time()),
        "typ": "mcp-dcr",
    }
    return pyjwt.encode(
        payload, _private_key, algorithm="RS256", headers={"kid": _kid}
    )


def _verify_client_id(client_id: str) -> dict | None:
    """Verify a signed client_id JWT. Returns its payload or None."""
    try:
        return pyjwt.decode(
            client_id,
            _public_key,
            algorithms=["RS256"],
            options={"verify_aud": False, "verify_exp": False, "require": ["iat"]},
        )
    except Exception as e:
        print(f"client_id verification failed: {e}", file=sys.stderr)
        return None


def _mint_access_token(sub: str, scope: str) -> str:
    now = int(time.time())
    payload = {
        "iss": MCP_ISSUER,
        "sub": sub,
        "aud": MCP_ISSUER,
        "iat": now,
        "exp": now + 3600,
        "scope": scope,
    }
    return pyjwt.encode(
        payload, _private_key, algorithm="RS256", headers={"kid": _kid}
    )


def _verify_access_token(token: str) -> dict | None:
    try:
        return pyjwt.decode(
            token,
            _public_key,
            algorithms=["RS256"],
            audience=MCP_ISSUER,
            issuer=MCP_ISSUER,
        )
    except Exception as e:
        print(f"access token verification failed: {e}", file=sys.stderr)
        return None


def _extract_bearer(request: Request) -> str | None:
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    return None


def _www_authenticate(error: str | None = None) -> str:
    parts = ['Bearer realm="CTFN Data MCP"']
    if error:
        parts.append(f'error="{error}"')
    parts.append(
        f'resource_metadata="{MCP_ISSUER}/.well-known/oauth-protected-resource"'
    )
    return ", ".join(parts)


# ---------------------------------------------------------------------------
# OAuth discovery endpoints
# ---------------------------------------------------------------------------
async def authorization_server_metadata(request: Request) -> JSONResponse:
    """RFC 8414 Authorization Server Metadata — points at ourselves."""
    return JSONResponse({
        "issuer": MCP_ISSUER,
        "authorization_endpoint": f"{MCP_ISSUER}/authorize",
        "token_endpoint": f"{MCP_ISSUER}/token",
        "registration_endpoint": f"{MCP_ISSUER}/register",
        "jwks_uri": f"{MCP_ISSUER}/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
    })


async def protected_resource_metadata(request: Request) -> JSONResponse:
    """RFC 9728 Protected Resource Metadata — authorization_servers is us."""
    return JSONResponse({
        "resource": MCP_ISSUER,
        "authorization_servers": [MCP_ISSUER],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
    })


async def jwks_endpoint(request: Request) -> JSONResponse:
    return JSONResponse({"keys": [_public_jwk]})


async def health_endpoint(request: Request) -> JSONResponse:
    return JSONResponse({
        "status": "ok",
        "auth": "oauth2.1-embedded-as",
        "issuer": MCP_ISSUER,
        "upstream_idp": AUTH0_ISSUER,
    })


# ---------------------------------------------------------------------------
# OAuth Authorization Server endpoints
# ---------------------------------------------------------------------------
async def register_endpoint(request: Request) -> JSONResponse:
    """RFC 7591 Dynamic Client Registration. Stateless — client_id is signed."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid_client_metadata"}, status_code=400)

    redirect_uris = body.get("redirect_uris") or []
    if not isinstance(redirect_uris, list) or not redirect_uris:
        return JSONResponse(
            {"error": "invalid_redirect_uri",
             "error_description": "At least one redirect_uri is required"},
            status_code=400,
        )
    # Sanity-bound the list; prevents abuse if the signed client_id gets huge.
    if len(redirect_uris) > 10:
        return JSONResponse(
            {"error": "invalid_redirect_uri",
             "error_description": "Too many redirect_uris"},
            status_code=400,
        )
    for u in redirect_uris:
        if not isinstance(u, str) or len(u) > 2048:
            return JSONResponse(
                {"error": "invalid_redirect_uri"}, status_code=400
            )

    client_name = body.get("client_name") or "mcp-client"
    if not isinstance(client_name, str) or len(client_name) > 200:
        client_name = "mcp-client"

    client_id = _sign_client_id(redirect_uris, client_name)
    return JSONResponse({
        "client_id": client_id,
        "client_id_issued_at": int(time.time()),
        "redirect_uris": redirect_uris,
        "client_name": client_name,
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
    }, status_code=201)


async def authorize_endpoint(request: Request) -> Response:
    """Validate the /authorize request and redirect the user's browser to Auth0."""
    _cleanup_stores()
    q = request.query_params
    client_id = q.get("client_id")
    redirect_uri = q.get("redirect_uri")
    response_type = q.get("response_type")
    code_challenge = q.get("code_challenge")
    code_challenge_method = q.get("code_challenge_method")
    client_state = q.get("state")
    scope = q.get("scope") or "openid profile email"

    if response_type != "code":
        return JSONResponse(
            {"error": "unsupported_response_type"}, status_code=400
        )
    if not client_id or not redirect_uri:
        return JSONResponse({"error": "invalid_request"}, status_code=400)
    if code_challenge_method != "S256" or not code_challenge:
        return JSONResponse(
            {"error": "invalid_request",
             "error_description": "code_challenge with S256 is required"},
            status_code=400,
        )

    claims = _verify_client_id(client_id)
    if not claims:
        return JSONResponse({"error": "invalid_client"}, status_code=400)
    if redirect_uri not in claims.get("redirect_uris", []):
        return JSONResponse(
            {"error": "invalid_request",
             "error_description": "redirect_uri does not match registered value"},
            status_code=400,
        )

    session_id = secrets.token_urlsafe(32)
    _authorize_sessions[session_id] = {
        "client_id": client_id,
        "client_redirect_uri": redirect_uri,
        "client_state": client_state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "scope": scope,
        "created_at": time.time(),
    }

    upstream_params = {
        "client_id": AUTH0_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": f"{MCP_ISSUER}/callback",
        "scope": "openid profile email",
        "state": session_id,
    }
    return RedirectResponse(
        url=f"{AUTH0_AUTHORIZE_URL}?{urlencode(upstream_params)}",
        status_code=302,
    )


async def callback_endpoint(request: Request) -> Response:
    """Auth0 redirects the browser here after user login; mint our own code."""
    _cleanup_stores()
    q = request.query_params
    code = q.get("code")
    state = q.get("state")
    error = q.get("error")

    if error:
        return JSONResponse(
            {"error": error, "error_description": q.get("error_description", "")},
            status_code=400,
        )
    if not code or not state:
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    session = _authorize_sessions.pop(state, None)
    if not session:
        return JSONResponse(
            {"error": "invalid_request",
             "error_description": "Unknown or expired authorize session"},
            status_code=400,
        )

    # Exchange Auth0 code for tokens (we really only need id_token.sub).
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.post(
                AUTH0_TOKEN_URL,
                data={
                    "grant_type": "authorization_code",
                    "client_id": AUTH0_CLIENT_ID,
                    "client_secret": AUTH0_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": f"{MCP_ISSUER}/callback",
                },
            )
            resp.raise_for_status()
        except Exception as e:
            print(f"Auth0 token exchange failed: {e}", file=sys.stderr)
            return JSONResponse(
                {"error": "server_error",
                 "error_description": "Upstream IdP token exchange failed"},
                status_code=500,
            )

    tokens = resp.json()
    id_token = tokens.get("id_token")
    if not id_token:
        return JSONResponse(
            {"error": "server_error",
             "error_description": "No id_token from upstream IdP"},
            status_code=500,
        )
    # We received this id_token directly from Auth0 over TLS via the code
    # exchange, so per OIDC Core §3.1.3.7 signature verification is optional.
    id_claims = pyjwt.decode(id_token, options={"verify_signature": False})
    sub = id_claims.get("sub")
    if not sub:
        return JSONResponse({"error": "server_error"}, status_code=500)

    our_code = secrets.token_urlsafe(32)
    _auth_codes[our_code] = {
        "sub": sub,
        "client_id": session["client_id"],
        "redirect_uri": session["client_redirect_uri"],
        "code_challenge": session["code_challenge"],
        "code_challenge_method": session["code_challenge_method"],
        "scope": session["scope"],
        "created_at": time.time(),
    }

    params = {"code": our_code}
    if session.get("client_state") is not None:
        params["state"] = session["client_state"]
    target = session["client_redirect_uri"]
    sep = "&" if "?" in target else "?"
    return RedirectResponse(url=f"{target}{sep}{urlencode(params)}", status_code=302)


async def token_endpoint(request: Request) -> JSONResponse:
    """Exchange our auth code for an RS256 access token (PKCE verified)."""
    _cleanup_stores()
    try:
        form = await request.form()
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    grant_type = form.get("grant_type")
    code = form.get("code")
    redirect_uri = form.get("redirect_uri")
    client_id = form.get("client_id")
    code_verifier = form.get("code_verifier")

    if grant_type != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
    if not code or not redirect_uri or not client_id or not code_verifier:
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    # Verify client_id signature (stateless DCR).
    if _verify_client_id(client_id) is None:
        return JSONResponse({"error": "invalid_client"}, status_code=400)

    record = _auth_codes.pop(code, None)  # one-time use
    if not record:
        return JSONResponse(
            {"error": "invalid_grant",
             "error_description": "Unknown or expired code"},
            status_code=400,
        )
    if time.time() - record["created_at"] > AUTH_CODE_TTL:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    if record["client_id"] != client_id:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    if record["redirect_uri"] != redirect_uri:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    # PKCE S256 verification.
    challenge = _b64url(hashlib.sha256(code_verifier.encode("ascii")).digest())
    if challenge != record["code_challenge"]:
        return JSONResponse(
            {"error": "invalid_grant",
             "error_description": "PKCE verification failed"},
            status_code=400,
        )

    access_token = _mint_access_token(record["sub"], record["scope"])
    return JSONResponse({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": record["scope"],
    })


# ---------------------------------------------------------------------------
# OAuth middleware — validates OUR access tokens on /mcp
# ---------------------------------------------------------------------------
class OAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if not request.url.path.startswith("/mcp"):
            return await call_next(request)

        token = _extract_bearer(request)
        if not token:
            return JSONResponse(
                {"error": "unauthorized",
                 "error_description": "Bearer token required"},
                status_code=401,
                headers={"WWW-Authenticate": _www_authenticate()},
            )
        claims = _verify_access_token(token)
        if not claims:
            return JSONResponse(
                {"error": "invalid_token",
                 "error_description": "Token invalid, expired, or issuer/audience mismatch"},
                status_code=401,
                headers={"WWW-Authenticate": _www_authenticate(error="invalid_token")},
            )
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
    # Upstream returns: {"status":"ok","token":"...","user":"...","expires_in_hours":24}
    _api_token = data["token"]
    _api_token_expiry = time.time() + data.get("expires_in_hours", 24) * 3600
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
# MCP Server & Tools (unchanged)
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
            # Authorization Server discovery
            Route(
                "/.well-known/oauth-authorization-server",
                authorization_server_metadata,
                methods=["GET"],
            ),
            # Protected Resource discovery (both forms per RFC 9728 §3.1)
            Route(
                "/.well-known/oauth-protected-resource",
                protected_resource_metadata,
                methods=["GET"],
            ),
            Route(
                "/.well-known/oauth-protected-resource/mcp",
                protected_resource_metadata,
                methods=["GET"],
            ),
            # JWKS
            Route("/jwks.json", jwks_endpoint, methods=["GET"]),
            # Authorization Server endpoints
            Route("/register", register_endpoint, methods=["POST"]),
            Route("/authorize", authorize_endpoint, methods=["GET"]),
            Route("/callback", callback_endpoint, methods=["GET"]),
            Route("/token", token_endpoint, methods=["POST"]),
            # Health
            Route("/health", health_endpoint, methods=["GET"]),
            # Protected MCP
            Mount("/mcp", app=mcp_app),
        ],
        middleware=[
            Middleware(OAuthMiddleware),
        ],
        lifespan=lifespan,
    )

    uvicorn.run(
        app, host="0.0.0.0", port=port,
        proxy_headers=True, forwarded_allow_ips="*",
    )
