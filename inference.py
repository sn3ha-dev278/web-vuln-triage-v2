"""
Inference script for Web Vulnerability Triage Environment.
Uses OpenAI client with HuggingFace router to run an LLM agent
against the environment and produce a reproducible baseline score.
"""

import asyncio
import os
import sys
from typing import List, Optional

from openai import OpenAI
from web_vuln_triage.client import WebVulnTriageEnv
from web_vuln_triage.models import WebVulnTriageAction

API_BASE_URL = os.getenv("API_BASE_URL") or "https://router.huggingface.co/v1"
API_KEY = os.getenv("HF_TOKEN") or os.getenv("API_KEY")
MODEL_NAME = os.getenv("MODEL_NAME") or "Qwen/Qwen2.5-72B-Instruct"
IMAGE_NAME = os.getenv("IMAGE_NAME") or "web_vuln_triage:latest"

TASK_NAME = "web_vulnerability_triage"
BENCHMARK = "web_vuln_triage_env"
MAX_STEPS = 40
MAX_TOKENS = 256
SUCCESS_SCORE_THRESHOLD = 0.5

# Max possible reward:
# Task1: 5 scenarios x 1.0 = 5.0
# Task2: 5 scenarios x 1.0 = 5.0
# Task3: 2 scenarios x 1.0 = 2.0
MAX_TOTAL_REWARD = 12.0

SYSTEM_PROMPT = """You are an expert cybersecurity analyst specializing in vulnerability triage.

You will be given vulnerability reports and must respond with precise, concise answers.

TASK 1 - Severity Classification:
Respond with EXACTLY one word: Critical, High, Medium, or Low
Base your decision on CVSS score, exploitability, authentication requirements, and public exploit availability.

TASK 2 - False Positive Detection:
Respond with EXACTLY one word: real or false_positive
Analyze the evidence carefully. Consider whether the scanner finding is confirmed by context.

TASK 3 - Remediation Prioritization:
Respond with ONLY a comma-separated list of vulnerability IDs in priority order.
Example format: V2,V3,V1,V4,V5
Consider: CVSS score, unauthenticated access, public exploits, business impact, and urgency.

IMPORTANT RULES:
- Give ONLY the answer, no explanations
- No punctuation except commas in Task 3
- No extra words or sentences
"""


def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(
    step: int,
    action: str,
    reward: float,
    done: bool,
    error: Optional[str],
) -> None:
    error_val = error if error else "null"
    done_val = str(done).lower()
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} done={done_val} error={error_val}",
        flush=True,
    )


def log_end(
    success: bool,
    steps: int,
    score: float,
    rewards: List[float],
) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(
        f"[END] success={str(success).lower()} steps={steps} score={score:.3f} rewards={rewards_str}",
        flush=True,
    )


def get_model_response(
    client: OpenAI,
    task_description: str,
    vulnerability_data: str,
    feedback: str,
    history: List[str],
) -> str:
    """Call the LLM and return its response."""

    user_content = f"{task_description}\n\n{vulnerability_data}"
    if feedback and feedback not in ("New episode started. Good luck!", ""):
        user_content += f"\n\nPrevious feedback: {feedback}"
    if history:
        recent = history[-3:]
        user_content += "\n\nRecent history:\n" + "\n".join(recent)

    try:
        completion = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
            max_tokens=MAX_TOKENS,
            stream=False,
        )
        text = (completion.choices[0].message.content or "").strip()
        text = text.strip(".")
        text = text.strip()
        return text if text else "Medium"
    except Exception as exc:
        print(f"[DEBUG] Model request failed: {exc}", flush=True)
        return "Medium"


async def main() -> None:
    client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)

    # Connect to locally running server
    try:
        env = WebVulnTriageEnv(base_url="http://localhost:8000")
    except Exception as e:
        print(f"[DEBUG] Failed to connect to environment: {e}", flush=True)
        sys.exit(1)

    history: List[str] = []
    rewards: List[float] = []
    steps_taken = 0
    score = 0.0
    success = False

    log_start(task=TASK_NAME, env=BENCHMARK, model=MODEL_NAME)

    try:
        # Reset environment
        result = await env.reset()
        last_task_desc = result.observation.task_description
        last_vuln_data = result.observation.vulnerability_data
        last_feedback = result.observation.feedback

        for step in range(1, MAX_STEPS + 1):
            if result.done:
                break

            # Get model response
            action_text = get_model_response(
                client=client,
                task_description=last_task_desc,
                vulnerability_data=last_vuln_data,
                feedback=last_feedback,
                history=history,
            )

            # Step environment
            result = await env.step(WebVulnTriageAction(response=action_text))
            obs = result.observation

            reward = result.reward or 0.0
            done = result.done
            error = None

            rewards.append(reward)
            steps_taken = step

            last_task_desc = obs.task_description
            last_vuln_data = obs.vulnerability_data
            last_feedback = obs.feedback

            log_step(
                step=step,
                action=action_text,
                reward=reward,
                done=done,
                error=error,
            )

            history.append(
                f"Step {step}: task={obs.task_id} action={action_text!r} "
                f"reward={reward:+.2f} feedback={obs.feedback[:80]}"
            )

            if done:
                break

        # Calculate final score
        score = sum(rewards) / MAX_TOTAL_REWARD if MAX_TOTAL_REWARD > 0 else 0.0
        score = min(max(score, 0.0), 1.0)
        success = score >= SUCCESS_SCORE_THRESHOLD

    except Exception as e:
        print(f"[DEBUG] Episode error: {e}", flush=True)

    finally:
        try:
            await env.close()
        except Exception as e:
            print(f"[DEBUG] env.close() error: {e}", flush=True)
        log_end(
            success=success,
            steps=steps_taken,
            score=score,
            rewards=rewards,
        )


if __name__ == "__main__":
    asyncio.run(main())
