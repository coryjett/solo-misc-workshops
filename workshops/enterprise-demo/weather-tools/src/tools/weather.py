"""Weather forecast tool for the weather-tools MCP server."""

from core.server import mcp

_FORECASTS = {
    "san francisco": "Foggy, 58°F, light wind from the west.",
    "new york": "Partly cloudy, 71°F, humid.",
    "london": "Rain, 54°F, overcast all day.",
    "tokyo": "Clear, 77°F, calm.",
}

_ALERTS = {
    "CA": "Heat Advisory: high temperatures inland through Thursday.",
    "FL": "Tropical Storm Watch: monitor the Gulf Coast.",
    "TX": "Severe Thunderstorm Warning: large hail and damaging winds possible.",
    "NY": "Winter Weather Advisory: 3–5 inches of snow overnight.",
}

_STATE_CODES = {
    "california": "CA",
    "florida": "FL",
    "texas": "TX",
    "new york": "NY",
}


@mcp.tool(description="Get the current weather forecast for a city.")
def get_forecast(city: str) -> str:
    """Return a short weather forecast for the given city."""
    return _FORECASTS.get(city.strip().lower(), f"No forecast on file for {city}.")


@mcp.tool(description="Get active weather alerts for a US state (name or two-letter code).")
def get_alerts(state: str) -> str:
    """Return active weather alerts for a US state name or two-letter code."""
    key = state.strip()
    code = key.upper() if len(key) == 2 else _STATE_CODES.get(key.lower(), key.upper())
    return _ALERTS.get(code, f"No active weather alerts for {state}.")
