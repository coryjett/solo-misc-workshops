"""MCP server with one tool that calls the httpbin API through the gateway.

The bearer token on the incoming MCP request is forwarded unchanged on the
outbound API call, so the API route sees the same identity the MCP server did.
"""
import os
import httpx
from fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_headers

API_BASE = os.environ.get("API_BASE", "http://e2e-gw.e2e-demo.svc.cluster.local:8080/api")

mcp = FastMCP("mcp-api")


@mcp.tool()
def httpbin_get(path: str = "/get") -> str:
    """Call the httpbin API through the gateway at API_BASE + path. Returns status and body."""
    headers = get_http_headers(include={"authorization"})
    auth = headers.get("authorization")
    out = {}
    if auth:
        out["authorization"] = auth
    r = httpx.get(API_BASE + path, headers=out, timeout=10)
    return f"HTTP {r.status_code}\n{r.text[:800]}"


if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=8000, path="/mcp")
