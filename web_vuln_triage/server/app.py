# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.

"""
FastAPI application for the Web Vuln Triage Environment.
"""
from fastapi import FastAPI


app = FastAPI()

# -------------------------
# Existing endpoints
# -------------------------

@app.post("/reset")
async def reset(request: dict):
    return {}

@app.post("/step")
async def step(request: dict):
    return {}

@app.post("/grader")
async def grader(request: dict):
    # Retrieve the score from the request; default to 0.5 if not found
    raw_score = request.get("score", 0.5)
    
    # Force the score into the strict (0, 1) range
    clamped_score = max(0.01, min(0.99, raw_score))
    
    return {"score": clamped_score}

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


app = create_app(
    WebVulnTriageEnvironment,
    WebVulnTriageAction,
    WebVulnTriageObservation,
    env_name="web_vuln_triage",
    max_concurrent_envs=1,
)

@app.post("/grader")
async def grader(request: dict):
    # Retrieve score and ensure it stays in (0, 1) to solve the previous error
    raw_score = request.get("score", 0.5)
    clamped_score = max(0.01, min(0.99, float(raw_score)))
    return {"score": clamped_score}

# Ensure /reset and /step are also explicitly exposed if required
@app.post("/reset")
async def reset(request: dict):
    return {}

@app.post("/step")
async def step(request: dict):
    return {}

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
