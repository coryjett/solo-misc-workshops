"""Microsoft 365 WorkIQ stand-in (fictional data): mail, files and meetings. The gateway down-scopes it per
user (mail tools hidden for some groups, send_mail for most) and whoami shows which identity reached it."""
import base64, json
from mcp.server.fastmcp import FastMCP, Context

mcp = FastMCP("workiq", host="0.0.0.0", port=8000, stateless_http=True)

EMAILS = {
    "E-1": {"id": "E-1", "from": "pm@corp.example", "subject": "Q3 roadmap update", "body": "Updated the Q3 roadmap with the new billing milestones."},
    "E-2": {"id": "E-2", "from": "support@corp.example", "subject": "Escalation: customer outage", "body": "Customer reported an outage. Contact: 555-100-2345, account C-9001."},
    "E-3": {"id": "E-3", "from": "security@corp.example", "subject": "Policy reminder", "body": "Please complete the annual security training before Friday."},
    "E-4": {"id": "E-4", "from": "ceo@corp.example", "subject": "All-hands deck draft", "body": "Attached is the draft deck for next week's all-hands."},
}

FILES = {
    "F-1": {"id": "F-1", "title": "Product Strategy.docx", "owner": "pm@corp.example", "snippet": "This document outlines the product strategy and priorities for the next two quarters."},
    "F-2": {"id": "F-2", "title": "Budget Plan.xlsx", "owner": "finance@corp.example", "snippet": "Department budgets, headcount plan and spend thresholds for the fiscal year."},
    "F-3": {"id": "F-3", "title": "Customer Onboarding Guide.pdf", "owner": "ops@corp.example", "snippet": "Step-by-step guide for onboarding new enterprise customers, including security review."},
}

MEETINGS = {
    "today": [
        {"time": "09:00", "title": "Morning standup", "attendees": ["eng@corp.example", "pm@corp.example"]},
        {"time": "13:00", "title": "Customer review", "attendees": ["ceo@corp.example", "client@example.com"]},
        {"time": "16:00", "title": "Security review", "attendees": ["security@corp.example", "eng@corp.example"]},
    ],
}

DEMO_USERS = {"00000000-0000-0000-0000-000000000101": "admin", "00000000-0000-0000-0000-000000000102": "approver", "00000000-0000-0000-0000-000000000103": "eng-dev", "00000000-0000-0000-0000-000000000104": "sales-dev", "00000000-0000-0000-0000-000000000105": "auditor"}  # demo realm user ids

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
def search_mail(query: str) -> str:
    """Search email subjects for a query."""
    hits = [e for e in EMAILS.values() if query.lower() in e["subject"].lower()]
    if not hits:
        return f"No emails matching {query}"
    return "\n".join([f"{e['id']} from {e['from']}: {e['subject']}" for e in hits])

@mcp.tool()
def read_mail(message_id: str) -> str:
    """Read an email by message id."""
    e = EMAILS.get(message_id)
    if not e:
        return f"No email {message_id}"
    return f"From: {e['from']}\nSubject: {e['subject']}\n\n{e['body']}"

@mcp.tool()
def send_mail(to: str, subject: str, body: str) -> str:
    """Send an email. Should only be reachable by users allowed to send."""
    return f"SENT to {to}: {subject} (this should only be reachable by users allowed to send)"

@mcp.tool()
def search_files(query: str) -> str:
    """Search SharePoint files for a query."""
    hits = [f for f in FILES.values() if query.lower() in f["title"].lower() or query.lower() in f["snippet"].lower()]
    if not hits:
        return f"No files matching {query}"
    return "\n".join([f"{f['id']} ({f['owner']}): {f['title']}" for f in hits])

@mcp.tool()
def read_file(file_id: str) -> str:
    """Read a SharePoint file by id."""
    f = FILES.get(file_id)
    if not f:
        return f"No file {file_id}"
    return f"{f['title']} (owner {f['owner']})\n\n{f['snippet']}"

@mcp.tool()
def list_meetings(day: str = "today") -> str:
    """List meetings for a day."""
    ms = MEETINGS.get(day)
    if not ms:
        return f"No meetings for {day}"
    return "\n".join([f"{m['time']}: {m['title']} ({', '.join(m['attendees'])})" for m in ms])

@mcp.tool()
def whoami(ctx: Context) -> str:
    """Report which user identity reached the WorkIQ system."""
    return f"WorkIQ sees caller: {_caller(ctx)}"

if __name__ == "__main__":
    mcp.run(transport="streamable-http")
