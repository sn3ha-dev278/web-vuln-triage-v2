"""
FastAPI application for the Web Vuln Triage Environment.

ARCHITECTURE NOTE:
  create_app() from openenv may lock routing after construction, so we build
  the outer FastAPI app first, register /grader on it, then mount the openenv
  app as a sub-application. The platform validator hits POST /grader on the
  root — this guarantees it is always reachable.
"""
from fastapi import FastAPI

try:
    from openenv.core.env_server.http_server import create_app
except Exception as e:  # pragma: no cover
    raise ImportError(
        "openenv is required for the web interface. "
        "Install dependencies with:\n\n"
        "    uv sync\n"
    ) from e

try:
    from web_vuln_triage.models import (
        WebVulnTriageAction,
        WebVulnTriageObservation,
    )
    from web_vuln_triage.server.web_vuln_triage_environment import (
        WebVulnTriageEnvironment,
        _score_task1,
        _score_task2,
        _score_task3,
        _clamp,
        TASK1_SCENARIOS,
        TASK2_SCENARIOS,
        TASK3_SCENARIOS,
    )
except ModuleNotFoundError:
    from models import WebVulnTriageAction, WebVulnTriageObservation
    from server.web_vuln_triage_environment import (
        WebVulnTriageEnvironment,
        _score_task1,
        _score_task2,
        _score_task3,
        _clamp,
        TASK1_SCENARIOS,
        TASK2_SCENARIOS,
        TASK3_SCENARIOS,
    )

# ── 1. Build the outer app first ─────────────────────────────────────────────
app = FastAPI(title="Web Vulnerability Triage Environment")


# ── 2. Register /grader BEFORE mounting anything ─────────────────────────────
@app.post("/grader")
async def grader(request: dict):
    """
    Grader endpoint required by openenv.yaml.
    Accepts:
        { "task_id": "task1"|"task2"|"task3",
          "response": "<agent answer>",
          "scenario_index": 0 }
    Returns:
        { "score": <float strictly between 0 and 1> }
    """
    task_id = request.get("task_id", "task1")
    response = request.get("response", "")
    scenario_index = int(request.get("scenario_index", 0))

    try:
        if task_id == "task1":
            idx = min(scenario_index, len(TASK1_SCENARIOS) - 1)
            score = _score_task1(response, TASK1_SCENARIOS[idx]["correct_answer"])
        elif task_id == "task2":
            idx = min(scenario_index, len(TASK2_SCENARIOS) - 1)
            score = _score_task2(response, TASK2_SCENARIOS[idx]["correct_answer"])
        elif task_id == "task3":
            idx = min(scenario_index, len(TASK3_SCENARIOS) - 1)
            score = _score_task3(response, TASK3_SCENARIOS[idx]["correct_answer"])
        else:
            score = _clamp(0.05)
    except Exception:
        score = _clamp(0.05)

    # Always clamp to strictly (0, 1)
    return {"score": _clamp(score)}


@app.get("/grader")
async def grader_health():
    """Health-check — lets the validator confirm the grader is live."""
    return {"status": "ok", "tasks": ["task1", "task2", "task3"]}


@app.get("/health")
async def health():
    return {"status": "ok"}


# ── 3. Mount openenv sub-app for /reset, /step, etc. ─────────────────────────
_openenv_app = create_app(
    WebVulnTriageEnvironment,
    WebVulnTriageAction,
    WebVulnTriageObservation,
    env_name="web_vuln_triage",
    max_concurrent_envs=1,
)
app.mount("/env", _openenv_app)


def main(host: str = "0.0.0.0", port: int = 7860):
    """
    Run the server locally.
    Examples:
        python -m web_vuln_triage.server.app
        uvicorn server.app:app --reload --port 7860
    """
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
