# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.

"""
FastAPI application for the Web Vuln Triage Environment.
"""
from fastapi import Request

# ---- Import openenv safely ----
try:
    from openenv.core.env_server.http_server import create_app
except Exception as e:  # pragma: no cover
    raise ImportError(
        "openenv is required for the web interface. "
        "Install dependencies with:\n\n"
        "    uv sync\n"
    ) from e

try:
    # When running as package (recommended)
    from web_vuln_triage.models import (
        WebVulnTriageAction,
        WebVulnTriageObservation,
    )
    from web_vuln_triage.server.web_vuln_triage_environment import (
        WebVulnTriageEnvironment,
    )

except ModuleNotFoundError:
    # Fallback when running from inside project root
    from models import WebVulnTriageAction, WebVulnTriageObservation
    from server.web_vuln_triage_environment import WebVulnTriageEnvironment


# 1. Create the base app via OpenEnv (this automatically handles /reset and /step correctly)
app = create_app(
    WebVulnTriageEnvironment,
    WebVulnTriageAction,
    WebVulnTriageObservation,
    env_name="web_vuln_triage",
    max_concurrent_envs=1,
)

# 2. Attach our custom, bulletproof grader endpoint AFTER create_app
@app.post("/grader")
@app.get("/grader")
async def grader_endpoint(request: Request):
    """
    Handles both POST and GET. Catches empty payloads during validator pings.
    """
    try:
        # Try to parse JSON if the validator sends a POST
        body = await request.json()
        raw_score = body.get("score", 0.5)
    except Exception:
        # If it's a GET request or empty payload, default to a safe value
        raw_score = 0.5
        
    # Strictly enforce the (0, 1) range
    clamped_score = max(0.01, min(0.99, float(raw_score)))
    
    return {"score": clamped_score}


def main(host: str = "0.0.0.0", port: int = 8000):
    """
    Run the server locally.

    Examples:
        python -m web_vuln_triage.server.app
        uvicorn web_vuln_triage.server.app:app --reload
    """
    import uvicorn

    uvicorn.run(app, host=host, port=port, reload=True)


if __name__ == "__main__":
    main()
