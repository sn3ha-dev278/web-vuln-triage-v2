---
title: Web Vulnerability Triage
emoji: 🛡️
colorFrom: blue
colorTo: purple
sdk: docker
pinned: false
---

# Web Vulnerability Triage Environment

An OpenEnv-compatible reinforcement learning environment that simulates
real-world web vulnerability triage workflows. AI agents are trained and
evaluated on tasks that security engineers perform daily — classifying
vulnerability severity, detecting false positives, and prioritizing
remediation.

---

## Motivation

Security teams are overwhelmed with vulnerability scanner output. A single
scan can produce hundreds of findings, many of which are false positives or
low priority. This environment enables AI agents to learn vulnerability
triage through reinforcement learning — with structured rewards that reflect
real security decision-making quality.

This environment is useful for:
- Training agents to reason about cybersecurity risk
- Evaluating LLM performance on structured security analysis tasks
- Benchmarking models on real-world security workflows

---

## Environment Description

The environment presents vulnerability reports and scanner findings to an
agent and rewards correct triage decisions. It progresses through 3 tasks
of increasing difficulty across 12 total scenarios.

At each step:
- The environment sends a vulnerability report as an observation
- The agent submits a triage decision as an action
- The environment grades the decision and returns a reward + feedback
- The agent gets up to 3 attempts per scenario before moving on

### Tasks

| Task | Difficulty | Scenarios | Description |
|------|-----------|-----------|-------------|
| Task 1 | Easy | 5 | Classify vulnerability severity as Critical, High, Medium, or Low |
| Task 2 | Medium | 5 | Detect whether a scanner finding is real or a false positive |
| Task 3 | Hard | 2 | Prioritize 5 vulnerabilities in correct remediation order |

---

## Action Space

The agent submits a single text response per step:

```python
class WebVulnTriageAction(Action):
    response: str  # Agent's triage decision
```

- **Task 1:** Exactly one word — `Critical`, `High`, `Medium`, or `Low`
- **Task 2:** Exactly one word — `real` or `false_positive`
- **Task 3:** Comma-separated list of IDs — e.g. `V2,V3,V1,V4,V5`

---

## Observation Space

At each step the environment returns:

```python
class WebVulnTriageObservation(Observation):
    task_id: str              # "task1", "task2", or "task3"
    task_description: str     # Instructions for the current task
    vulnerability_data: str   # The vulnerability report to analyze
    feedback: str             # Feedback after agent submits an answer
    current_score: float      # Cumulative score so far in the episode
    attempt_number: int       # Current attempt number (max 3 per scenario)
```

---

## Reward Function

The environment provides dense reward signals throughout the episode:

| Situation | Reward |
|-----------|--------|
| Correct answer on attempt 1 | 1.0 |
| Correct answer on attempt 2 | 0.7 |
| Correct answer on attempt 3 | 0.4 |
| Wrong answer | 0.0 |
| Adjacent severity (Task 1) | 0.4 partial credit |
| Task 3 partial order | 0.0 – 0.9 based on pairwise correctness |

Maximum possible reward per episode: **12.0**
- Task 1: 5 scenarios × 1.0 = 5.0
- Task 2: 5 scenarios × 1.0 = 5.0
- Task 3: 2 scenarios × 1.0 = 2.0

The reward function is designed to:
- Reward partial progress (not just binary success/failure)
- Penalize delayed correct answers (attempt decay)
- Give partial credit for near-correct orderings in Task 3
- Provide signal at every step so agents can learn continuously

---

## Task Descriptions

### Task 1 — Severity Classification (Easy)
The environment presents a CVE report including component name, description,
CVSS score, network accessibility, authentication requirements, and public
exploit availability. The agent must classify the severity as Critical, High,
Medium, or Low.

Partial credit is awarded for adjacent severity levels (e.g. responding High
when the correct answer is Critical).

### Task 2 — False Positive Detection (Medium)
The environment presents a scanner finding alongside additional context such
as the application stack, server configuration, and manual verification notes.
The agent must determine whether the finding is a real vulnerability or a
false positive.

This task requires the agent to reason beyond the raw scanner output and
consider contextual evidence — a key real-world skill.

### Task 3 — Remediation Prioritization (Hard)
The environment presents 5 vulnerabilities with different risk profiles
including CVSS score, authentication requirements, public exploit
availability, and business impact. The agent must produce a prioritized
remediation order from most to least urgent.

Partial credit is awarded based on correct pairwise orderings so agents
receive signal even for imperfect rankings.

---

## Episode Flow

```
reset()
  └── Returns Task 1, Scenario 1 observation

step(action)
  ├── Grades action → returns reward + feedback
  ├── If correct or max attempts reached → advances to next scenario
  ├── If wrong and attempts remain → returns same scenario with feedback
  └── After all 12 scenarios → done=True

Final score = total_rewards / 12.0  (normalized to 0.0 – 1.0)
```

---

## Setup Instructions

### Prerequisites
- Python 3.10+
- Docker Desktop
- HuggingFace account with API token

### Installation

```bash
# Clone the repository
git clone <your-repo-url>
cd web-vuln-triage

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install "openenv-core[cli]"
cd web_vuln_triage
pip install -e .
```

### Running the Environment Locally

```bash
# From project root
cd web-vuln-triage

# Start the environment server
uvicorn web_vuln_triage.server.app:app --host 0.0.0.0 --port 8000

# Visit the playground UI
# http://localhost:8000/web
```

### Running with Docker

```bash
# Build Docker image
docker build -t web_vuln_triage:latest web_vuln_triage/

# Run the environment server
docker run -p 8000:8000 web_vuln_triage:latest
```

### Running Inference

```bash
# From project root
cd web-vuln-triage

# Set environment variables
export HF_TOKEN=your_token_here
export MODEL_NAME=Qwen/Qwen2.5-72B-Instruct
export IMAGE_NAME=web_vuln_triage:latest

# Run inference
python inference.py
```

---

## Baseline Scores

Tested with `Qwen/Qwen2.5-72B-Instruct` via HuggingFace router:

| Task | Baseline Score |
|------|---------------|
| Task 1 — Severity Classification | ~0.80 |
| Task 2 — False Positive Detection | ~0.70 |
| Task 3 — Remediation Prioritization | ~0.60 |
| **Overall (normalized 0–1)** | **~0.55** |

---

## Environment API

```python
from web_vuln_triage.client import WebVulnTriageEnv

# Connect via Docker
env = await WebVulnTriageEnv.from_docker_image("web_vuln_triage:latest")

# Or connect to a running server
env = WebVulnTriageEnv(base_url="http://localhost:8000")

# Reset — start a new episode
result = await env.reset()
print(result.observation.task_description)
print(result.observation.vulnerability_data)

# Step — submit a triage decision
from web_vuln_triage.models import WebVulnTriageAction
result = await env.step(WebVulnTriageAction(response="Critical"))
print(result.reward)
print(result.observation.feedback)

# Close
await env.close()
```

---

## Tags
`security` `cybersecurity` `vulnerability-triage` `real-world` `openenv`