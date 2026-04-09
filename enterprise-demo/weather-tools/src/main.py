"""Simple weather MCP server."""
import random
from fastmcp import FastMCP

mcp = FastMCP(name="weather-tools")

@mcp.tool()
def get_forecast(city: str) -> str:
    """Get the current weather forecast for a city.
    Args:
        city: The city name (e.g., "San Francisco", "New York")
    Returns:
        A weather forecast for the specified city
    """
    conditions = ["Sunny", "Partly Cloudy", "Cloudy", "Light Rain", "Clear Skies"]
    temp = random.randint(55, 85)
    humidity = random.randint(30, 80)
    condition = random.choice(conditions)
    return (
        f"Weather for {city}:\n"
        f"  Condition: {condition}\n"
        f"  Temperature: {temp}F\n"
        f"  Humidity: {humidity}%\n"
        f"  Wind: {random.randint(5, 20)} mph"
    )

@mcp.tool()
def get_alerts(state: str) -> str:
    """Get active weather alerts for a US state.
    Args:
        state: Two-letter US state code (e.g., "CA", "NY")
    Returns:
        Active weather alerts for the specified state
    """
    alerts = {
        "CA": "Heat Advisory: High temperatures expected in inland areas through Thursday.",
        "FL": "Tropical Storm Watch: Monitor conditions along the Gulf Coast.",
        "TX": "Severe Thunderstorm Warning: Large hail and damaging winds possible.",
        "NY": "Winter Weather Advisory: 3-5 inches of snow expected overnight.",
    }
    state = state.upper()
    if state in alerts:
        return f"Active alerts for {state}:\n  {alerts[state]}"
    return f"No active weather alerts for {state}."

if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=3000, path="/mcp")
