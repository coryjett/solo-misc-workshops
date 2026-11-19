"""Inventory MCP server (fictional data)."""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("inventory", host="0.0.0.0", port=8000, stateless_http=True)
STOCK = {("site-112", "SKU-4471"): 38, ("site-112", "SKU-9902"): 3, ("site-205", "SKU-4471"): 0}

@mcp.tool()
def check_stock(site_id: str, sku: str) -> str:
    """Units on hand for a SKU at a site."""
    return f"{site_id} {sku}: {STOCK.get((site_id, sku), 0)} units"

@mcp.tool()
def low_stock(site_id: str) -> str:
    """SKUs at a site with fewer than 5 units."""
    low = [f"{s}: {n}" for (st, s), n in STOCK.items() if st == site_id and n < 5]
    return "\n".join(low) or "none"

if __name__ == "__main__":
    mcp.run(transport="streamable-http")
