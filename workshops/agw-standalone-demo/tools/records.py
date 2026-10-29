"""Customer records MCP server (fictional data). Returns PII on purpose so the gateway's guardrails have
something to redact, has one destructive tool for the gateway to block, and reports which user identity
actually reached it (the On-Behalf-Of story)."""
import base64, json, os
from mcp.server.fastmcp import FastMCP, Context

mcp = FastMCP("records", host="127.0.0.1", port=int(os.environ.get("PORT", "8000")), stateless_http=True)

CUSTOMERS = {
    "C-1001": {"name": "Jordan Rivera", "dob": "1984-03-12", "phone": "555-201-0142", "plan": "Premium", "status": "active"},
    "C-1002": {"name": "Casey Morgan", "dob": "1971-11-02", "phone": "555-201-0199", "plan": "Basic", "status": "past due"},
}
DEMO_USERS = {"00000000-0000-0000-0000-000000000201": "support-agent", "00000000-0000-0000-0000-000000000202": "ops-manager",
              "00000000-0000-0000-0000-000000000203": "security-analyst"}  # demo realm user ids

def _caller(ctx: Context) -> str:
    try:
        auth = ctx.request_context.request.headers.get("authorization", "")
        claims = json.loads(base64.urlsafe_b64decode(auth.split(".")[1] + "=="))
        sub = claims.get("sub", "?")
        who = claims.get("preferred_username") or DEMO_USERS.get(sub, "unknown user")
        return f"{who} (sub {sub}); token issued by {claims.get('iss')}"
    except Exception:
        return "no user token received"

@mcp.tool()
def lookup_customer(customer_id: str) -> str:
    """Look up a customer's profile."""
    c = CUSTOMERS.get(customer_id)
    if not c:
        return f"No customer {customer_id}"
    return "\n".join([f"Customer {customer_id}: {c['name']}", f"DOB: {c['dob']}", f"Phone: {c['phone']}", f"Plan: {c['plan']}, status {c['status']}"])

@mcp.tool()
def account_status(customer_id: str) -> str:
    """Check a customer's account status."""
    c = CUSTOMERS.get(customer_id)
    return f"{customer_id}: {c['status']}" if c else f"No customer {customer_id}"

@mcp.tool()
def delete_customer_record(customer_id: str) -> str:
    """Permanently delete a customer record. Destructive."""
    return f"DELETED {customer_id} (this should never be reachable through the gateway)"

@mcp.tool()
def whoami(ctx: Context) -> str:
    """Report which user identity reached the records system."""
    return f"Records system sees caller: {_caller(ctx)}"

if __name__ == "__main__":
    mcp.run(transport="streamable-http")
