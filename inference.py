import asyncio
import os
import sys
from typing import List

from openai import OpenAI
from web_vuln_triage.client import WebVulnTriageEnv
from web_vuln_triage.models import WebVulnTriageAction


try:
    API_BASE_URL = os.environ["API_BASE_URL"]
    API_KEY = os.environ["API_KEY"]
except KeyError as e:
    raise RuntimeError(f"Missing required environment variable: {e}")

MODEL_NAME = os.environ.get("MODEL_NAME", "gpt-4o-mini")


TASK_NAME = "web_vulnerability_triage"
BENCHMARK = "web_vuln_triage_env"
MAX_STEPS = 40
MAX_TOKENS = 256
SUCCESS_SCORE_THRESHOLD = 0.5
MAX_TOTAL_REWARD = 12.0


SYSTEM_PROMPT = """You are an expert cybersecurity analyst specializing in vulnerability triage.

TASK 1:
Respond with EXACTLY one word: Critical, High, Medium, or Low

TASK 2:
Respond with EXACTLY one word: real or false_positive

TASK 3:
Respond with ONLY a comma-separated list of vulnerability IDs

RULES:
- No explanations
- No extra words
"""


def log_start(task: str, env: str, model: str):
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool):
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} done={str(done).lower()}",
        flush=True,
    )


def log_end(success: bool, steps: int, score: float):
    print(
        f"[END] success={str(success).lower()} steps={steps} score={score:.3f}",
        flush=True,
    )


def get_model_response(
    client: OpenAI,
    task_description: str,
    vulnerability_data: str,
    feedback: str,
    history: List[str],
) -> str:

    user_content = f"{task_description}\n\n{vulnerability_data}"

    if feedback and feedback not in ("New episode started. Good luck!", ""):
        user_content += f"\n\nFeedback: {feedback}"

    if history:
        user_content += "\n\nRecent:\n" + "\n".join(history[-3:])

    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
        max_tokens=MAX_TOKENS,
    )

    text = (response.choices[0].message.content or "").strip()

    if not text:
        raise RuntimeError("Empty LLM response")

    return text.strip(".")


async def main():

    print(f"[DEBUG] API_BASE_URL: {API_BASE_URL}", flush=True)

    client = OpenAI(
        base_url=API_BASE_URL,
        api_key=API_KEY,
    )

    
    try:
        print("[DEBUG] Performing test LLM call...", flush=True)
        client.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": "test"}],
            max_tokens=5,
        )
    except Exception as e:
        print(f"[ERROR] Test LLM call failed: {e}", flush=True)

    ENV_URL = os.environ.get("ENV_URL")

    try:
        if ENV_URL:
            print(f"[DEBUG] Using remote ENV_URL: {ENV_URL}", flush=True)
            env = WebVulnTriageEnv(base_url=ENV_URL)
        else:
            print("[DEBUG] ENV_URL not found, using localhost", flush=True)
            env = WebVulnTriageEnv(base_url="http://localhost:8000")
    except Exception as e:
        print(f"[ERROR] Env init failed: {e}", flush=True)
        sys.exit(1)

    history: List[str] = []
    rewards: List[float] = []
    steps_taken = 0

    log_start(TASK_NAME, BENCHMARK, MODEL_NAME)

    try:
        result = await env.reset()

        for step in range(1, MAX_STEPS + 1):
            if result.done:
                break

            obs = result.observation

            
            action_text = get_model_response(
                client,
                obs.task_description,
                obs.vulnerability_data,
                obs.feedback,
                history,
            )

            result = await env.step(WebVulnTriageAction(response=action_text))

            reward = result.reward or 0.0
            done = result.done

            rewards.append(reward)
            steps_taken = step

            log_step(step, action_text, reward, done)

            history.append(f"{action_text} -> {reward:+.2f}")

            if done:
                break

        score = sum(rewards) / MAX_TOTAL_REWARD if MAX_TOTAL_REWARD else 0.0
        score = max(0.0, min(score, 1.0))
        success = score >= SUCCESS_SCORE_THRESHOLD

    except Exception as e:
        print(f"[ERROR] Execution failed: {e}", flush=True)
        success = False
        score = 0.0

    finally:
        try:
            await env.close()
        except Exception:
            pass

        log_end(success, steps_taken, score)

if __name__ == "__main__":
    asyncio.run(main())
