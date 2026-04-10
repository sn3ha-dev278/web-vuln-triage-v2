"""
Inference script for Web Vulnerability Triage Environment.
"""

import asyncio
import os
import sys
from typing import List, Optional

from openai import OpenAI
from web_vuln_triage.client import WebVulnTriageEnv
from web_vuln_triage.models import WebVulnTriageAction

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
API_BASE_URL = os.environ.get("API_BASE_URL", "https://router.huggingface.co/v1")
API_KEY = os.environ.get("API_KEY") or os.environ.get("HF_TOKEN") or ""
MODEL_NAME = os.environ.get("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")
IMAGE_NAME = os.environ.get("IMAGE_NAME", "web_vuln_triage:latest")
ENV_URL = os.environ.get("ENV_URL", "")

BENCHMARK = "web_vuln_triage_env"
TASKS = ["task_easy", "task_medium", "task_hard"]
MAX_STEPS = 15
MAX_TOKENS = 256
SUCCESS_SCORE_THRESHOLD = 0.5
MAX_TOTAL_REWARD = 4.75

SYSTEM_PROMPT = """You are an expert cybersecurity analyst specializing in vulnerability triage.

TASK 1 - Severity Classification:
Respond with EXACTLY one word: Critical, High, Medium, or Low

TASK 2 - False Positive Detection:
Respond with EXACTLY one word: real or false_positive

TASK 3 - Remediation Prioritization:
Respond with ONLY a comma-separated list of vulnerability IDs in priority order.
Example format: V2,V3,V1,V4,V5

RULES:
- Give ONLY the answer, no explanations
- No punctuation except commas in Task 3
- No extra words or sentences
"""


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(
    step: int,
    action: str,
    reward: float,
    done: bool,
    error: Optional[str] = None,
) -> None:
    error_val = error if error else "null"
    done_val = str(done).lower()
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} done={done_val} error={error_val}",
        flush=True,
    )


def log_end(task_id: str, score: float, steps: int) -> None:
    print(f"[END] task={task_id} score={score:.3f} steps={steps}", flush=True)


# ---------------------------------------------------------------------------
# Model call
# ---------------------------------------------------------------------------
def get_model_response(
    client: OpenAI,
    task_description: str,
    vulnerability_data: str,
    feedback: str,
    history: List[str],
) -> str:
    user_content = f"{task_description}\n\n{vulnerability_data}"
    if feedback and feedback not in ("New episode started. Good luck!", ""):
        user_content += f"\n\nPrevious feedback: {feedback}"
    if history:
        user_content += "\n\nRecent history:\n" + "\n".join(history[-3:])

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
        return text if text else "Medium"
    except Exception as exc:
        print(f"[DEBUG] Model request failed: {exc}", flush=True)
        return "Medium"


# ---------------------------------------------------------------------------
# Run a single task
# ---------------------------------------------------------------------------
async def run_task(env: WebVulnTriageEnv, client: OpenAI, task_id: str) -> None:
    history: List[str] = []
    rewards: List[float] = []
    steps_taken = 0
    score = 0.1

    log_start(task=task_id, env=BENCHMARK, model=MODEL_NAME)

    try:
        # Set task then reset
        await env.step(WebVulnTriageAction(response=f"__set_task__:{task_id}"))
        result = await env.reset()

        last_task_desc = result.observation.task_description
        last_vuln_data = result.observation.vulnerability_data
        last_feedback = result.observation.feedback

        for step in range(1, MAX_STEPS + 1):
            if result.done:
                break

            action_text = get_model_response(
                client=client,
                task_description=last_task_desc,
                vulnerability_data=last_vuln_data,
                feedback=last_feedback,
                history=history,
            )

            result = await env.step(WebVulnTriageAction(response=action_text))
            obs = result.observation

            reward = result.reward or 0.0
            done = result.done

            rewards.append(reward)
            steps_taken = step

            last_task_desc = obs.task_description
            last_vuln_data = obs.vulnerability_data
            last_feedback = obs.feedback

            log_step(step=step, action=action_text, reward=reward, done=done)
            history.append(f"{action_text} -> {reward:+.2f}")

            if done:
                break

        raw = sum(rewards) / MAX_TOTAL_REWARD if MAX_TOTAL_REWARD > 0 else 0.0
        score = round(max(0.1, min(0.9, raw)), 3)

    except Exception as e:
        print(f"[DEBUG] Task {task_id} error: {e}", flush=True)
        score = 0.1

    log_end(task_id=task_id, score=score, steps=steps_taken)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
async def main() -> None:
    client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)

    try:
        if IMAGE_NAME and not ENV_URL:
            env = await WebVulnTriageEnv.from_docker_image(IMAGE_NAME)
        elif ENV_URL:
            env = WebVulnTriageEnv(base_url=ENV_URL)
        else:
            env = WebVulnTriageEnv(base_url="http://localhost:7860")
    except Exception as e:
        print(f"[DEBUG] Failed to connect to environment: {e}", flush=True)
        sys.exit(1)

    try:
        for task_id in TASKS:
            await run_task(env, client, task_id)
    finally:
        try:
            await env.close()
        except Exception:
            pass


if __name__ == "__main__":
    asyncio.run(main())
