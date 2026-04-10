"""
FastAPI application for the Web Vuln Triage Environment.
"""
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

# Create the main app via openenv
app = create_app(
    WebVulnTriageEnvironment,
    WebVulnTriageAction,
    WebVulnTriageObservation,
    env_name="web_vuln_triage",
    max_concurrent_envs=1,
)


@app.post("/grader")
async def grader(request: dict):
    """
    Grader endpoint required by openenv.yaml.
    Accepts: { "task_id": "task1"|"task2"|"task3", "response": "...", "scenario_index": 0 }
    Returns: { "score": float } where score is strictly in (0, 1).
    """
    task_id = request.get("task_id", "task1")
    response = request.get("response", "")
    scenario_index = int(request.get("scenario_index", 0))

    try:
        if task_id == "task1":
            scenarios = TASK1_SCENARIOS
            idx = min(scenario_index, len(scenarios) - 1)
            score = _score_task1(response, scenarios[idx]["correct_answer"])
        elif task_id == "task2":
            scenarios = TASK2_SCENARIOS
            idx = min(scenario_index, len(scenarios) - 1)
            score = _score_task2(response, scenarios[idx]["correct_answer"])
        elif task_id == "task3":
            scenarios = TASK3_SCENARIOS
            idx = min(scenario_index, len(scenarios) - 1)
            score = _score_task3(response, scenarios[idx]["correct_answer"])
        else:
            score = _clamp(0.05)
    except Exception:
        score = _clamp(0.05)

    # Always ensure score is strictly between 0 and 1
    return {"score": _clamp(score)}


@app.get("/grader")
async def grader_health():
    """Health check for the grader endpoint."""
    return {"status": "ok", "tasks": ["task1", "task2", "task3"]}


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
