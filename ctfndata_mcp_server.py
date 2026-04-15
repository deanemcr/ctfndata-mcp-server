#!/usr/bin/env python3
"""
CTFN Data MCP Server - exposes CTFNDATA risk-metrics API as MCP tools.

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

API_BASE = os.environ.get("CTFNDATA_API_BASE", "https://ctfndata.onrender.com")
API_USER = os.environ.get("CTFNDATA_USER", "deanemcrobie@gmail.com")
API_PASS = os.environ.get("CTFNDATA_PASS", "Mambopoa1!")

_token = None
_token_expiry = 0.0


def _get_token():
    global _token, _token_expiry
    if _token and time.time() < _token_expiry - 60:
        return _token
    resp = httpx.post(f"{API_BASE}/login", json={"username": API_USER, "password": API_PASS}, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    _token = data["access_token"]
    expires_in = data.get("expires_in", 14400)
    _token_expiry = time.time() + expires_in
    return _token


def _api_get(path, params=None):
    token = _get_token()
    resp = httpx.get(f"{API_BASE}{path}", params=params, headers={"Authorization": f"Bearer {token}"}, timeout=20)
    if resp.status_code == 401:
        global _token
        _token = None
        token = _get_token()
        resp = httpx.get(f"{API_BASE}{path}", params=params, headers={"Authorization": f"Bearer {token}"}, timeout=20)
    resp.raise_for_status()
    return resp.json()


mcp = FastMCP("ctfndata", instructions="CTFN Data connector for M&A risk metrics. Use ctfndata_lookup, ctfndata_all, ctfndata_search, ctfndata_deals.")


@mcp.tool()
def ctfndata_lookup(ticker: str, param: str) -> dict:
    """Look up a single M&A risk metric for a deal by ticker."""
    try:
        return _api_get("/api/ctfndata", params={"ticker": ticker.upper(), "param": param.lower()})
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def ctfndata_all(ticker: str) -> dict:
    """Get ALL risk metrics for a single M&A deal by ticker."""
    try:
        return _api_get("/api/ctfndata/all", params={"ticker": ticker.upper()})
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def ctfndata_search(query: str, limit: int = 20) -> dict:
    """Search for M&A deals by company name, ticker, or keyword."""
    try:
        return _api_get("/api/ctfndata/search", params={"q": query, "limit": limit})
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def ctfndata_deals() -> dict:
    """List all currently tracked M&A deals."""
    try:
        return _api_get("/api/ctfndata", params={"param": "deals"})
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def ctfndata_deal_count() -> dict:
    """Get the total number of M&A deals currently tracked."""
    try:
        return _api_get("/api/ctfndata", params={"param": "deal_count"})
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def ctfndata_health() -> dict:
    """Check the health/status of the CTFNDATA backend API."""
    try:
        resp = httpx.get(f"{API_BASE}/health", timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        return {"error": str(e)}


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8080))
    app = mcp.streamable_http_app()
    uvicorn.run(app, host="0.0.0.0", port=port)
