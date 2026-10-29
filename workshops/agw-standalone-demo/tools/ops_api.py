"""Legacy operations REST API (fictional). Not MCP: the gateway turns its OpenAPI spec into MCP tools."""
import os
from fastapi import FastAPI
app = FastAPI(title="Operations API", version="1.0.0", servers=[{"url": f"http://127.0.0.1:{os.environ.get('PORT', '8000')}"}])
HOURS = {"site-112": "6am-11pm", "site-205": "7am-10pm"}

@app.get("/sites/{site_id}/hours", operation_id="get_site_hours", summary="Opening hours for a site")
def site_hours(site_id: str):
    return {"site_id": site_id, "hours": HOURS.get(site_id, "unknown")}

@app.get("/sites/{site_id}/on-call", operation_id="get_on_call_staff", summary="Staff on call at a site")
def on_call(site_id: str):
    return {"site_id": site_id, "on_call": 2 if site_id == "site-112" else 1}
