"""
Web Vulnerability Triage Environment Implementation.
"""

from uuid import uuid4
from openenv.core.env_server.interfaces import Environment
from openenv.core.env_server.types import State

try:
    from ..models import WebVulnTriageAction, WebVulnTriageObservation
except ImportError:
    try:
        from models import WebVulnTriageAction, WebVulnTriageObservation
    except ImportError:
        from web_vuln_triage.models import WebVulnTriageAction, WebVulnTriageObservation


# ---------------------------------------------------------------------------
# Task 1 Data: Severity Classification
# ---------------------------------------------------------------------------
TASK1_SCENARIOS = [
    {
        "vulnerability_data": (
            "CVE-2024-1001\n"
            "Component: Apache Struts 2.5.10\n"
            "Description: Remote Code Execution via OGNL injection in the file upload interceptor. "
            "An unauthenticated attacker can send a crafted HTTP request to execute arbitrary "
            "commands on the server with the privileges of the web application process.\n"
            "CVSS Score: 9.8\n"
            "Network accessible: Yes\n"
            "Authentication required: No\n"
            "Public exploit available: Yes"
        ),
        "correct_answer": "Critical",
        "explanation": "CVSS 9.8, unauthenticated RCE with public exploit = Critical"
    },
    {
        "vulnerability_data": (
            "CVE-2024-1002\n"
            "Component: jQuery 3.4.1\n"
            "Description: Cross-Site Scripting (XSS) vulnerability in the HTML parsing module. "
            "An attacker can inject malicious scripts through user-supplied input that is "
            "rendered without proper sanitization. Requires user interaction to exploit.\n"
            "CVSS Score: 6.1\n"
            "Network accessible: Yes\n"
            "Authentication required: No\n"
            "Public exploit available: Yes"
        ),
        "correct_answer": "Medium",
        "explanation": "CVSS 6.1, requires user interaction, no direct system compromise = Medium"
    },
    {
        "vulnerability_data": (
            "CVE-2024-1003\n"
            "Component: OpenSSL 3.0.1\n"
            "Description: SQL Injection in the user authentication endpoint /api/login. "
            "An unauthenticated attacker can bypass authentication or dump the entire "
            "user database by manipulating the username parameter.\n"
            "CVSS Score: 8.6\n"
            "Network accessible: Yes\n"
            "Authentication required: No\n"
            "Public exploit available: No"
        ),
        "correct_answer": "High",
        "explanation": "CVSS 8.6, auth bypass + data dump but no public exploit yet = High"
    },
    {
        "vulnerability_data": (
            "CVE-2024-1004\n"
            "Component: Nginx 1.18.0\n"
            "Description: Information disclosure vulnerability that exposes server version "
            "information in HTTP response headers. This allows attackers to fingerprint "
            "the server but does not directly enable exploitation.\n"
            "CVSS Score: 3.1\n"
            "Network accessible: Yes\n"
            "Authentication required: No\n"
            "Public exploit available: No"
        ),
        "correct_answer": "Low",
        "explanation": "CVSS 3.1, only information disclosure, no direct attack vector = Low"
    },
    {
        "vulnerability_data": (
            "CVE-2024-1005\n"
            "Component: Log4j 2.14.1\n"
            "Description: JNDI injection vulnerability (Log4Shell). An attacker can send "
            "a specially crafted log message that triggers an outbound LDAP request, "
            "leading to remote code execution. Affects any Java application using Log4j.\n"
            "CVSS Score: 10.0\n"
            "Network accessible: Yes\n"
            "Authentication required: No\n"
            "Public exploit available: Yes"
        ),
        "correct_answer": "Critical",
        "explanation": "CVSS 10.0, Log4Shell is the most critical known RCE = Critical"
    },
]


# ---------------------------------------------------------------------------
# Task 2 Data: False Positive Detection
# ---------------------------------------------------------------------------
TASK2_SCENARIOS = [
    {
        "vulnerability_data": (
            "Scanner: Nessus Automated Scan\n"
            "Finding: SQL Injection detected at /api/search?q=test\n"
            "Evidence: Scanner injected payload: ' OR '1'='1 and received HTTP 200 response.\n"
            "Additional context: The endpoint returns the same HTTP 200 for all inputs "
            "including invalid ones. Manual testing shows the query parameter is passed "
            "to a full-text search engine (Elasticsearch), not a SQL database. "
            "The application stack uses MongoDB (NoSQL) exclusively.\n"
            "Affected asset: Public search API"
        ),
        "correct_answer": "false_positive",
        "explanation": "App uses MongoDB/Elasticsearch, not SQL — scanner incorrectly flagged it"
    },
    {
        "vulnerability_data": (
            "Scanner: Burp Suite Pro\n"
            "Finding: Stored XSS in user profile bio field\n"
            "Evidence: Payload <script>alert(document.cookie)</script> was stored and "
            "executed when another user viewed the profile page. Session cookies were "
            "captured in the alert. The bio field has no input sanitization or CSP headers.\n"
            "Additional context: Manually verified by security researcher. "
            "Reproduced across Chrome, Firefox and Safari.\n"
            "Affected asset: User profile page (authenticated)"
        ),
        "correct_answer": "real",
        "explanation": "Manually verified, reproduced across browsers, cookies captured = real finding"
    },
    {
        "vulnerability_data": (
            "Scanner: OWASP ZAP\n"
            "Finding: Directory traversal at /api/files?path=../../etc/passwd\n"
            "Evidence: Scanner received HTTP 200 with response body 'File not found'.\n"
            "Additional context: The application returns HTTP 200 for all file requests "
            "regardless of outcome as per its API design spec. The files API is sandboxed "
            "to /var/app/uploads/ using chroot jail. Server runs on Windows (no /etc/passwd).\n"
            "Affected asset: File download API"
        ),
        "correct_answer": "false_positive",
        "explanation": "HTTP 200 is default behavior, chroot jail prevents traversal, wrong OS = false positive"
    },
    {
        "vulnerability_data": (
            "Scanner: Manual Pentest\n"
            "Finding: Insecure Direct Object Reference (IDOR) on /api/invoices/{id}\n"
            "Evidence: Authenticated as user A (ID: 1042), accessed /api/invoices/1043 "
            "and received full invoice data belonging to user B including name, address "
            "and payment details. No authorization check on invoice ownership.\n"
            "Additional context: Tested with 10 different invoice IDs, all accessible. "
            "Authorization logic confirmed missing in source code review.\n"
            "Affected asset: Invoice API (authenticated)"
        ),
        "correct_answer": "real",
        "explanation": "IDOR confirmed manually + source code review, multiple IDs accessed = real finding"
    },
    {
        "vulnerability_data": (
            "Scanner: Qualys SSL Labs\n"
            "Finding: SSL/TLS Birthday attack vulnerability (SWEET32) on port 443\n"
            "Evidence: Server supports 3DES cipher suite TLS_RSA_WITH_3DES_EDE_CBC_SHA.\n"
            "Additional context: The cipher is listed as supported but is never negotiated "
            "in practice — all modern clients negotiate AES-256. Traffic analysis confirms "
            "zero 3DES sessions in last 90 days of logs. Cipher cannot be removed due to "
            "legacy compliance requirement from a contracted third party.\n"
            "Affected asset: Main web application TLS"
        ),
        "correct_answer": "false_positive",
        "explanation": "Cipher supported but never used, zero sessions in 90 days = false positive in practice"
    },
]


# ---------------------------------------------------------------------------
# Task 3 Data: Remediation Prioritization
# ---------------------------------------------------------------------------
TASK3_SCENARIOS = [
    {
        "vulnerability_data": (
            "You are a security lead. Prioritize these 5 vulnerabilities for remediation "
            "(most urgent first). Consider CVSS score, exploitability, business impact, "
            "and whether a public exploit exists.\n\n"
            "V1: Cross-Site Scripting in admin dashboard comment field\n"
            "    CVSS: 5.4 | Auth required: Yes | Public exploit: No | Impact: Admin session theft\n\n"
            "V2: Remote Code Execution in public-facing API via deserialization flaw\n"
            "    CVSS: 9.8 | Auth required: No | Public exploit: Yes | Impact: Full server compromise\n\n"
            "V3: SQL Injection in internal reporting tool\n"
            "    CVSS: 8.1 | Auth required: Yes (employee only) | Public exploit: No | Impact: Internal DB dump\n\n"
            "V4: Missing rate limiting on login endpoint\n"
            "    CVSS: 5.3 | Auth required: No | Public exploit: No | Impact: Brute force attacks\n\n"
            "V5: Outdated SSL certificate expiring in 7 days\n"
            "    CVSS: 0.0 | Auth required: N/A | Public exploit: N/A | Impact: Service outage if expired\n\n"
            "Respond with ONLY a comma-separated list of IDs in priority order. Example: V2,V3,V1,V4,V5"
        ),
        "correct_answer": ["V2", "V3", "V5", "V1", "V4"],
        "explanation": (
            "V2 first: unauthenticated RCE with public exploit is highest risk. "
            "V3 second: SQLi with high CVSS even if internal. "
            "V5 third: cert expiry in 7 days causes imminent outage. "
            "V1 fourth: XSS but auth required limits exposure. "
            "V4 last: missing rate limit is lowest immediate risk."
        )
    },
    {
        "vulnerability_data": (
            "You are a security lead. Prioritize these 5 vulnerabilities for remediation "
            "(most urgent first). Consider CVSS score, exploitability, business impact, "
            "and whether a public exploit exists.\n\n"
            "V1: Path traversal in file download API, can read /etc/passwd\n"
            "    CVSS: 7.5 | Auth required: No | Public exploit: Yes | Impact: Sensitive file exposure\n\n"
            "V2: Weak password policy (min 6 chars, no complexity)\n"
            "    CVSS: 4.0 | Auth required: N/A | Public exploit: N/A | Impact: Account compromise\n\n"
            "V3: XML External Entity (XXE) injection in invoice parser\n"
            "    CVSS: 9.1 | Auth required: Yes | Public exploit: Yes | Impact: Internal network scan + file read\n\n"
            "V4: Open redirect on login page\n"
            "    CVSS: 3.1 | Auth required: No | Public exploit: No | Impact: Phishing\n\n"
            "V5: Hardcoded AWS credentials found in public GitHub repository\n"
            "    CVSS: 10.0 | Auth required: No | Public exploit: Yes | Impact: Full cloud infrastructure access\n\n"
            "Respond with ONLY a comma-separated list of IDs in priority order. Example: V2,V3,V1,V4,V5"
        ),
        "correct_answer": ["V5", "V3", "V1", "V2", "V4"],
        "explanation": (
            "V5 first: hardcoded cloud credentials are an active, critical breach risk. "
            "V3 second: XXE with CVSS 9.1 and public exploit. "
            "V1 third: path traversal, unauthenticated with public exploit. "
            "V2 fourth: weak passwords are serious but not immediately exploitable. "
            "V4 last: open redirect is lowest severity."
        )
    },
]


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

def _clamp(value: float) -> float:
    return round(max(0.1, min(0.9, value)), 3)


def _score_task1(response: str, correct: str) -> float:
    cleaned = response.strip().capitalize()
    if cleaned == correct:
        return _clamp(0.95)
    severity_order = ["Low", "Medium", "High", "Critical"]
    if cleaned in severity_order and correct in severity_order:
        distance = abs(severity_order.index(cleaned) - severity_order.index(correct))
        if distance == 1:
            return _clamp(0.4)
        if distance == 2:
            return _clamp(0.2)
    return _clamp(0.05)


def _score_task2(response: str, correct: str) -> float:
    cleaned = response.strip().lower().replace("-", "_")
    if cleaned == correct:
        return _clamp(0.95)
    return _clamp(0.1)


def _score_task3(response: str, correct_order: list) -> float:
    raw_ids = [v.strip().upper() for v in response.replace(" ", "").split(",")]
    valid_ids = [v for v in raw_ids if v in correct_order]

    if not valid_ids:
        return _clamp(0.05)

    if valid_ids == correct_order:
        return _clamp(0.95)

    total_pairs = 0
    correct_pairs = 0
    n = len(correct_order)
    for i in range(n):
        for j in range(i + 1, n):
            a, b = correct_order[i], correct_order[j]
            if a in valid_ids and b in valid_ids:
                total_pairs += 1
                if valid_ids.index(a) < valid_ids.index(b):
                    correct_pairs += 1

    if total_pairs == 0:
        return _clamp(0.05)

    raw = (correct_pairs / total_pairs) * 0.85
    return _clamp(raw)


# ---------------------------------------------------------------------------
# Main Environment Class
# ---------------------------------------------------------------------------

class WebVulnTriageEnvironment(Environment):
    """
    Web Vulnerability Triage Environment.

    Tasks:
    - task_easy:   Classify vulnerability severity
    - task_medium: Detect false positives
    - task_hard:   Prioritize vulnerabilities for remediation
    """

    SUPPORTS_CONCURRENT_SESSIONS: bool = True

    def __init__(self):
        self._state = State(episode_id=str(uuid4()), step_count=0)
        self._task_id: str = "task_easy"
        self._scenario_index: int = 0
        self._attempt: int = 0
        self._max_attempts: int = 3
        self._current_score: float = 0.0
        self._done: bool = False

    def reset(self) -> WebVulnTriageObservation:
        """Reset environment. Task is set via __set_task__ action before calling reset."""
        self._state = State(episode_id=str(uuid4()), step_count=0)
        self._scenario_index = 0
        self._attempt = 0
        self._current_score = 0.0
        self._done = False

        if self._task_id == "task_easy":
            scenario = TASK1_SCENARIOS[0]
            return WebVulnTriageObservation(
                task_id="task_easy",
                task_description=(
                    "TASK 1 - Severity Classification\n"
                    "Analyze the vulnerability report below and classify its severity.\n"
                    "Reply with exactly one word: Critical, High, Medium, or Low."
                ),
                vulnerability_data=scenario["vulnerability_data"],
                feedback="New episode started. Good luck!",
                current_score=0.0,
                attempt_number=0,
                done=False,
                reward=0.05,
            )
        elif self._task_id == "task_medium":
            scenario = TASK2_SCENARIOS[0]
            return WebVulnTriageObservation(
                task_id="task_medium",
                task_description=(
                    "TASK 2 - False Positive Detection\n"
                    "Analyze the finding below. Is it a real vulnerability or a false positive?\n"
                    "Reply with exactly one word: real or false_positive."
                ),
                vulnerability_data=scenario["vulnerability_data"],
                feedback="New episode started. Good luck!",
                current_score=0.0,
                attempt_number=0,
                done=False,
                reward=0.05,
            )
        else:  # task_hard
            scenario = TASK3_SCENARIOS[0]
            return WebVulnTriageObservation(
                task_id="task_hard",
                task_description=(
                    "TASK 3 - Remediation Prioritization\n"
                    "Prioritize the vulnerabilities below from most to least urgent.\n"
                    "Reply with ONLY a comma-separated list of IDs. Example: V2,V3,V1,V4,V5"
                ),
                vulnerability_data=scenario["vulnerability_data"],
                feedback="New episode started. Good luck!",
                current_score=0.0,
                attempt_number=0,
                done=False,
                reward=0.05,
            )

    def step(self, action: WebVulnTriageAction) -> WebVulnTriageObservation:
        """Process agent response and return next observation with reward."""

        # Handle special task-setting action
        if action.response.startswith("__set_task__:"):
            task_id = action.response.split(":")[1].strip()
            if task_id in ["task_easy", "task_medium", "task_hard"]:
                self._task_id = task_id
            return WebVulnTriageObservation(
                task_id=self._task_id,
                task_description="Task set. Call reset() to begin.",
                vulnerability_data="",
                feedback=f"Task set to {self._task_id}",
                current_score=0.0,
                attempt_number=0,
                done=False,
                reward=0.05,
            )

        self._state.step_count += 1
        self._attempt += 1

        if self._done:
            return WebVulnTriageObservation(
                task_id=self._task_id,
                task_description="Episode is complete.",
                vulnerability_data="",
                feedback="Episode already finished. Please call reset().",
                current_score=self._current_score,
                attempt_number=self._attempt,
                done=True,
                reward=0.05,
            )

        response = action.response.strip()
        raw_score = 0.1
        feedback = ""

        if self._task_id == "task_easy":
            scenario = TASK1_SCENARIOS[self._scenario_index]
            raw_score = _score_task1(response, scenario["correct_answer"])
            if raw_score >= 0.9:
                feedback = f"Correct! {scenario['explanation']}"
            elif raw_score >= 0.3:
                feedback = f"Partially correct. {scenario['explanation']}"
            else:
                feedback = f"Incorrect. {scenario['explanation']}"

        elif self._task_id == "task_medium":
            scenario = TASK2_SCENARIOS[self._scenario_index]
            raw_score = _score_task2(response, scenario["correct_answer"])
            if raw_score >= 0.9:
                feedback = f"Correct! {scenario['explanation']}"
            else:
                feedback = f"Incorrect. {scenario['explanation']}"

        elif self._task_id == "task_hard":
            scenario = TASK3_SCENARIOS[self._scenario_index]
            raw_score = _score_task3(response, scenario["correct_answer"])
            if raw_score >= 0.9:
                feedback = f"Perfect! {scenario['explanation']}"
            elif raw_score >= 0.3:
                feedback = f"Partial credit ({raw_score:.2f}). {scenario['explanation']}"
            else:
                feedback = f"Incorrect. {scenario['explanation']}"

        decay = max(0.4, 1.0 - (self._attempt - 1) * 0.3)
        reward = _clamp(raw_score * decay)
        self._current_score += reward

        advance = (raw_score >= 0.9) or (self._attempt >= self._max_attempts)

        if advance:
            self._attempt = 0
            next_obs = self._advance_scenario()
            next_obs.reward = reward
            next_obs.feedback = feedback + "\n" + next_obs.feedback
            next_obs.current_score = self._current_score
            return next_obs

        # Same scenario, try again
        if self._task_id == "task_easy":
            scenario = TASK1_SCENARIOS[self._scenario_index]
            desc = (
                "TASK 1 - Severity Classification\n"
                "Analyze the vulnerability report below and classify its severity.\n"
                "Reply with exactly one word: Critical, High, Medium, or Low."
            )
        elif self._task_id == "task_medium":
            scenario = TASK2_SCENARIOS[self._scenario_index]
            desc = (
                "TASK 2 - False Positive Detection\n"
                "Analyze the finding below. Is it a real vulnerability or a false positive?\n"
                "Reply with exactly one word: real or false_positive."
            )
        else:
            scenario = TASK3_SCENARIOS[self._scenario_index]
            desc = (
                "TASK 3 - Remediation Prioritization\n"
                "Prioritize the vulnerabilities below from most to least urgent.\n"
                "Reply with ONLY a comma-separated list of IDs. Example: V2,V3,V1,V4,V5"
            )

        return WebVulnTriageObservation(
            task_id=self._task_id,
            task_description=desc,
            vulnerability_data=scenario["vulnerability_data"],
            feedback=feedback,
            current_score=self._current_score,
            attempt_number=self._attempt,
            done=False,
            reward=reward,
        )

    def _advance_scenario(self) -> WebVulnTriageObservation:
        """Move to next scenario or end episode."""

        if self._task_id == "task_easy":
            self._scenario_index += 1
            if self._scenario_index < len(TASK1_SCENARIOS):
                scenario = TASK1_SCENARIOS[self._scenario_index]
                return WebVulnTriageObservation(
                    task_id="task_easy",
                    task_description=(
                        "TASK 1 - Severity Classification\n"
                        "Analyze the vulnerability report below and classify its severity.\n"
                        "Reply with exactly one word: Critical, High, Medium, or Low."
                    ),
                    vulnerability_data=scenario["vulnerability_data"],
                    feedback="Next scenario.",
                    current_score=self._current_score,
                    attempt_number=0,
                    done=False,
                    reward=0.05,
                )
            else:
                self._done = True
                return WebVulnTriageObservation(
                    task_id="task_easy",
                    task_description="Task complete!",
                    vulnerability_data="",
                    feedback=f"task_easy complete! Score: {self._current_score:.3f}",
                    current_score=self._current_score,
                    attempt_number=0,
                    done=True,
                    reward=0.05,
                )

        elif self._task_id == "task_medium":
            self._scenario_index += 1
            if self._scenario_index < len(TASK2_SCENARIOS):
                scenario = TASK2_SCENARIOS[self._scenario_index]
                return WebVulnTriageObservation(
                    task_id="task_medium",
                    task_description=(
                        "TASK 2 - False Positive Detection\n"
                        "Analyze the finding below. Is it a real vulnerability or a false positive?\n"
                        "Reply with exactly one word: real or false_positive."
                    ),
                    vulnerability_data=scenario["vulnerability_data"],
                    feedback="Next scenario.",
                    current_score=self._current_score,
                    attempt_number=0,
                    done=False,
                    reward=0.05,
                )
            else:
                self._done = True
                return WebVulnTriageObservation(
                    task_id="task_medium",
                    task_description="Task complete!",
                    vulnerability_data="",
                    feedback=f"task_medium complete! Score: {self._current_score:.3f}",
                    current_score=self._current_score,
                    attempt_number=0,
                    done=True,
                    reward=0.05,
                )

        else:  # task_hard
            self._scenario_index += 1
            if self._scenario_index < len(TASK3_SCENARIOS):
                scenario = TASK3_SCENARIOS[self._scenario_index]
                return WebVulnTriageObservation(
                    task_id="task_hard",
                    task_description=(
                        "TASK 3 - Remediation Prioritization\n"
                        "Prioritize the vulnerabilities below from most to least urgent.\n"
                        "Reply with ONLY a comma-separated list of IDs. Example: V2,V3,V1,V4,V5"
                    ),
                    vulnerability_data=scenario["vulnerability_data"],
                    feedback="Next scenario.",
                    current_score=self._current_score,
                    attempt_number=0,
                    done=False,
                    reward=0.05,
                )
            else:
                self._done = True
                return WebVulnTriageObservation(
                    task_id="task_hard",
                    task_description="Task complete!",
                    vulnerability_data="",
                    feedback=f"task_hard complete! Score: {self._current_score:.3f}",
                    current_score=self._current_score,
                    attempt_number=0,
                    done=True,
                    reward=0.05,
                )

    @property
    def state(self) -> State:
        return self._state
