"""GitHub MCP server stand-in (fictional org example-co). Read tools, write tools and two
destructive ones, so the gateway can hand each user a read-only or read-write slice of the same server."""
import base64, json
from mcp.server.fastmcp import FastMCP, Context

mcp = FastMCP("github", host="0.0.0.0", port=8000, stateless_http=True)

REPOS = {
    "web-app": {
        "files": {
            "README.md": "# Web App\nCustomer-facing web application.",
            "src/app.py": "def handler(request):\n    return {'status': 'ok'}",
        },
        "prs": [
            {"number": 1, "title": "Add dark mode", "head": "feature/dark-mode", "base": "main"},
            {"number": 2, "title": "Fix login redirect", "head": "fix/login-redirect", "base": "main"},
        ],
    },
    "data-pipeline": {
        "files": {
            "README.md": "# Data Pipeline\nNightly ETL jobs and data quality checks.",
            "src/etl.py": "def run(batch, retries=3):\n    return True",
        },
        "prs": [
            {"number": 1, "title": "Add retry backoff", "head": "feature/backoff", "base": "main"},
            {"number": 2, "title": "Add data quality alerts", "head": "feature/dq-alerts", "base": "main"},
        ],
    },
}

ISSUE_COUNTER = [100]

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
def list_repos() -> str:
    """List repositories in the org."""
    return "\n".join(REPOS.keys())

@mcp.tool()
def get_file_contents(repo: str, path: str) -> str:
    """Get contents of a file in a repo."""
    r = REPOS.get(repo)
    if not r:
        return f"No repo {repo}"
    content = r["files"].get(path)
    return content if content else f"No file {path} in {repo}"

@mcp.tool()
def search_code(query: str) -> str:
    """Search code across repos."""
    hits = []
    for repo, data in REPOS.items():
        for path, content in data["files"].items():
            if query.lower() in content.lower():
                hits.append(f"{repo}/{path}")
    return "\n".join(hits) if hits else f"No code matching {query}"

@mcp.tool()
def list_pull_requests(repo: str) -> str:
    """List open pull requests for a repo."""
    r = REPOS.get(repo)
    if not r:
        return f"No repo {repo}"
    return "\n".join([f"#{pr['number']}: {pr['title']} ({pr['head']} -> {pr['base']})" for pr in r["prs"]])

@mcp.tool()
def create_issue(repo: str, title: str, body: str = "") -> str:
    """Create an issue in a repo."""
    if repo not in REPOS:
        return f"No repo {repo}"
    ISSUE_COUNTER[0] += 1
    return f"CREATED issue #{ISSUE_COUNTER[0]} in {repo}: {title}"

@mcp.tool()
def create_pull_request(repo: str, title: str, head: str, base: str = "main") -> str:
    """Create a pull request."""
    if repo not in REPOS:
        return f"No repo {repo}"
    return f"CREATED PR for {repo}: {title} ({head} -> {base})"

@mcp.tool()
def merge_pull_request(repo: str, number: int) -> str:
    """Merge a pull request. Destructive."""
    if repo not in REPOS:
        return f"No repo {repo}"
    return f"MERGED PR #{number} in {repo} (destructive)"

@mcp.tool()
def delete_branch(repo: str, branch: str) -> str:
    """Delete a branch. Destructive."""
    if repo not in REPOS:
        return f"No repo {repo}"
    return f"DELETED branch {branch} in {repo} (destructive)"

@mcp.tool()
def whoami(ctx: Context) -> str:
    """Report which user identity reached the GitHub system."""
    return f"GitHub sees caller: {_caller(ctx)}"

if __name__ == "__main__":
    mcp.run(transport="streamable-http")
