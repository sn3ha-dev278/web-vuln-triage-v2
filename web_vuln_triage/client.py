"""Web Vulnerability Triage Environment Client."""

from typing import Dict

from openenv.core import EnvClient
from openenv.core.client_types import StepResult
from openenv.core.env_server.types import State

from .models import WebVulnTriageAction, WebVulnTriageObservation


class WebVulnTriageEnv(
    EnvClient[WebVulnTriageAction, WebVulnTriageObservation, State]
):
    """
    Client for the Web Vulnerability Triage Environment.

    Example:
        >>> # Connect to a running server
        >>> env = WebVulnTriageEnv(base_url="http://localhost:8000")
        >>> result = await env.reset()
        >>> result = await env.step(WebVulnTriageAction(response="Critical"))
        >>> await env.close()

    Example with Docker:
        >>> env = await WebVulnTriageEnv.from_docker_image("web_vuln_triage:latest")
        >>> result = await env.reset()
        >>> result = await env.step(WebVulnTriageAction(response="Critical"))
        >>> await env.close()
    """

    def _step_payload(self, action: WebVulnTriageAction) -> Dict:
        """Convert action to JSON payload."""
        return {
            "response": action.response,
        }

    def _parse_result(self, payload: Dict) -> StepResult[WebVulnTriageObservation]:
        """Parse server response into StepResult."""
        obs_data = payload.get("observation", {})
        observation = WebVulnTriageObservation(
            task_id=obs_data.get("task_id", ""),
            task_description=obs_data.get("task_description", ""),
            vulnerability_data=obs_data.get("vulnerability_data", ""),
            feedback=obs_data.get("feedback", ""),
            current_score=obs_data.get("current_score", 0.0),
            attempt_number=obs_data.get("attempt_number", 0),
            done=payload.get("done", False),
            reward=payload.get("reward", 0.0),
            metadata=obs_data.get("metadata", {}),
        )
        return StepResult(
            observation=observation,
            reward=payload.get("reward", 0.0),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: Dict) -> State:
        """Parse server response into State."""
        return State(
            episode_id=payload.get("episode_id"),
            step_count=payload.get("step_count", 0),
        )