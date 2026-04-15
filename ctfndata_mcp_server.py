#!/usr/bin/env python3
"""
CTFN Data MCP Server — exposes CTFNDATA risk-metrics API as MCP tools.

Wraps the REST API at ctfndata.onrender.com so Claude can query
M&A break prices, spreads, odds, and risk/reward metrics directly.

Runs as a streamable-HTTP MCP server (for Railway remote deployment).
"""

import os
import sys
import time
import json

try:
    import httpx
except ImportError:
    print("ERROR: httpx not installed. Run: pip install httpx", file=sys.stderr)
    sys.exit(1)

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

API_BASE = os.environ.get("CTFNDATA_API_BASE", "https://ctfndata.onrender.com")
API_USER = os.environ.get("CTFNDATA_USER", "deanemcrobie@gmail.com")
API_PASS = os.environ.get("CTFNDATA_PASS", "Mambopoa1!")

# Token cache
_token: str | None = None
_token_expiry: float = 0.0


def _get_token() -> str:
    """Authenticate against the CTFNDATA API and cache the bearer token."""
    global _token, _token_expiry

    # Reuse token if still valid (with 60s buffer)
    if _token and time.time() < _token_expiry - 60:
        return _token

    resp = httpx.post(
        f"{API_BASE}/login",
        json={"username": API_USER, "password": API_PASS},
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    _token = data["access_token"]
    # Default to 4-hour expiry if not specified
    expires_in = data.get("expires_in", 14400)
    _token_expiry = time.time() + expires_in
    return _token


def _api_get(path: str, params: dict | None = None) -> dict:
    """Make an authenticated GET request to the CTFNDATA API."""
    token = _get_token()
    resp = httpx.get(
        f"{API_BASE}{path}",
        params=params,
        headers={"Authorization": f"Bearer {token}"},
        timeout=20,
    )
    if resp.status_code == 401:
        # Token expired — force refresh and retry once
        global _token
        _token = None
        token = _get_token()
        resp = httpx.get(
            f"{API_BASE}{path}",
            params=params,
            headers={"Authorization": f"Bearer {token}"},
            timeout=20,
        )
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# MCP Server
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
)


# ---- Available parameters (for reference in tool descriptions) ----
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
               Also accepts aliases like "price" (=now), "downside" (=gross_downside),
               "annualized" (=ann_spread), "odds" (=chance_of_close), etc.

    Returns:
        Dict with the ticker, param name, and value.
    """
    try:
        data = _api_get("/api/ctfndata", params={"ticker": ticker.upper(), "param": param.lower()})
        return data
    except httpx.HTTPStatusError as e:
        return {"error": f"API error {e.response.status_code}: {e.response.text}"}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def ctfndata_all(ticker: str) -> dict:
    """Get ALL risk metrics for a single M&A deal by ticker.

    Returns every available metric in one call — break price, current price,
    offer price, spread, annualized spread, chance of close, risk/reward,
    premium, downside, deal status, advisors, dates, and more.

    Args:
        ticker: Stock ticker symbol (e.g. "ROKU", "HIMS").

    Returns:
        Dict with all available metrics for the deal.
    """
    try:
        data = _api_get("/api/ctfndata/all", params={"ticker": ticker.upper()})
        return data
    except httpx.HTTPStatusError as e:
        return {"error": f"API error {e.response.status_code}: {e.response.text}"}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def ctfndata_search(query: str, limit: int = 20) -> dict:
    """Search for M&A deals by company name, ticker, or keyword.

    Searches across target names, acquirer names, tickers, sectors, and
    other deal fields.

    Args:
        query: Search term (e.g. "Disney", "tech", "ROKU").
        limit: Maximum results to return. Default 20.

    Returns:
        Dict with matching deals and their key metrics.
    """
    try:
        data = _api_get("/api/ctfndata/search", params={"q": query, "limit": limit})
        return data
    except httpx.HTTPStatusError as e:
        return {"error": f"API error {e.response.status_code}: {e.response.text}"}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def ctfndata_deals() -> dict:
    """List all currently tracked M&A deals.

    Returns the full list of tickers and target company names for every
    deal in the CTFNDATA database. Use this to see what's available
    before querying specific deals.

    Returns:
        Dict with deal_count and list of deals (ticker + target name).
    """
    try:
        data = _api_get("/api/ctfndata", params={"param": "deals"})
        return data
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
        data = _api_get("/api/ctfndata", params={"param": "deal_count"})
        return data
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
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8080))
    app = mcp.streamable_http_app()
    uvicorn.run(app, host="0.0.0.0", port=port)
