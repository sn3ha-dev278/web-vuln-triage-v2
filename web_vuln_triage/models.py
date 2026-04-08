"""
Data models for the Web Vulnerability Triage Environment.
"""

from typing import Optional, List
from openenv.core.env_server.types import Action, Observation
from pydantic import Field


class WebVulnTriageAction(Action):
    """Action taken by the agent - its analysis response."""

    response: str = Field(
        ...,
        description=(
            "Agent's response. For Task 1: one of 'Critical', 'High', 'Medium', 'Low'. "
            "For Task 2: one of 'real' or 'false_positive'. "
            "For Task 3: a comma-separated list of vuln IDs in priority order, e.g. 'V3,V1,V5,V2,V4'."
        )
    )


class WebVulnTriageObservation(Observation):
    """What the agent sees at each step."""

    task_id: str = Field(default="", description="Which task is being run: task1, task2, task3")
    task_description: str = Field(default="", description="Instructions for the agent")
    vulnerability_data: str = Field(default="", description="The vulnerability report or data to analyze")
    feedback: str = Field(default="", description="Feedback after agent submits an answer")
    current_score: float = Field(default=0.0, description="Score so far in this episode")
    attempt_number: int = Field(default=0, description="Which attempt this is (max 3)")