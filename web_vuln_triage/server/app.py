# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.

"""
FastAPI application for the Web Vuln Triage Environment.
"""

# ---- Import openenv safely ----
try:
    from openenv.core.env_server.http_server import create_app
except Exception as e:  # pragma: no cover
    raise ImportError(
        "openenv is required for the web interface. "
        "Install dependencies with:\n\n"
        "    uv sync\n"
    ) from e


# ---- Handle imports robustly (works in Docker + local) ----
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


# ---- Create FastAPI app ----
app = create_app(
    WebVulnTriageEnvironment,
    WebVulnTriageAction,
    WebVulnTriageObservation,
    env_name="web_vuln_triage",
    max_concurrent_envs=1,
)


# ---- Entry point ----
def main(host: str = "0.0.0.0", port: int = 8000):
    """
    Run the server locally.

    Examples:
        python -m web_vuln_triage.server.app
        uvicorn web_vuln_triage.server.app:app --reload
    """
    import uvicorn

    uvicorn.run(app, host=host, port=port, reload=True)


# ---- CLI support ----
if __name__ == "__main__":
    main()