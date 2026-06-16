# Project AIR + Auth0: Complete Installation Guide

This guide takes you from zero to a working human-in-the-loop AI agent containment system. Every command is copy-pasteable. Every step has a checkpoint so you know it worked before moving on.

**Time required:** 10 minutes
**What you will have at the end:** An AI agent that halts on sensitive actions, requires a human to authenticate through your Auth0 tenant, and records a signed, tamper-evident approval in a forensic chain.

---

## Prerequisites

- A terminal (Terminal on macOS, PowerShell on Windows, any shell on Linux)
- Python 3.12 or newer (**not** the macOS system Python, which is 3.9)
- An Auth0 account (free tier works: https://auth0.com/signup)

### Check your Python version

**macOS / Linux:**
```bash
python3 --version
```

**Windows (PowerShell):**
```powershell
python --version
```

You need **3.12 or higher**. If you see 3.9, 3.10, or 3.11, you need to install a newer version.

### Installing Python 3.12+ (if needed)

**macOS (recommended):**
```bash
brew install python@3.13
```
After install, use `python3.13` and `pip3.13` instead of `python3` and `pip3` for all commands in this guide.

If you do not have Homebrew, install it first: https://brew.sh

**macOS (alternative):** Download from https://www.python.org/downloads/ and run the installer. After install, use `python3.13` instead of `python3`.

**Windows:** Download from https://www.python.org/downloads/. During installation, **check "Add Python to PATH"**. After install, `python` and `pip` will work in PowerShell.

**Linux (Debian/Ubuntu):**
```bash
sudo apt update && sudo apt install python3.12 python3.12-venv python3-pip
```

### Checkpoint

After installing, verify:

```bash
python3.13 --version    # macOS with Homebrew
python3 --version       # Linux
python --version         # Windows
```

You should see `Python 3.12.x` or `Python 3.13.x`. If yes, continue.

---

## Step 1: Install Project AIR

**macOS (Homebrew Python):**
```bash
pip3.13 install projectair
```

**macOS (python.org Python):**
```bash
python3.13 -m pip install projectair
```

**Linux:**
```bash
pip3 install projectair
```

**Windows (PowerShell):**
```powershell
pip install projectair
```

> **If you see `command not found` or `No matching distribution`:** You are using a Python older than 3.12. Go back to the Prerequisites section and install Python 3.12+.

### Checkpoint

**macOS / Linux:**
```bash
air --version
```

**Windows:**
```powershell
air --version
```

You should see:

```
air 1.0.0
```

If you see `command not found` or `not recognized`, close and reopen your terminal and try again. If that still fails:

- **macOS / Linux:** `python3 -m projectair.cli --version`
- **Windows:** `python -m projectair.cli --version`

---

## Step 2: Run the basic demo (no Auth0 yet)

```bash
air demo
```

This works the same on all platforms. It generates a signed forensic chain, runs 16 detectors, and writes a `forensic-report.json` in your current directory.

### Checkpoint

You should see output ending with:

```
[DONE] 9/9 steps complete.
  forensic-report.json written (14 records, 8 findings).
```

If you see this, Project AIR is installed and working.

---

## Step 3: Configure your Auth0 tenant

You need three things from Auth0. Log into https://manage.auth0.com and follow these steps exactly.

### 3a: Create an Application

1. In the left sidebar, click **Applications > Applications**
2. Click **+ Create Application**
3. Name it **"Project AIR"**
4. Select **Native** as the application type
5. Click **Create**

> **Why Native?** The Device Authorization Grant (used by the CLI) requires the Native application type.

### 3b: Enable Device Authorization Grant

Without this, the CLI approval flow will fail with `unauthorized_client`.

1. On your new application's page, click the **Settings** tab
2. Scroll all the way down to **Advanced Settings** (click the arrow to expand)
3. Click the **Grant Types** tab inside Advanced Settings
4. Find **Device Code** in the list
5. Check the box next to it
6. Scroll down and click **Save Changes**

### 3c: Create an API

1. In the left sidebar, click **Applications > APIs**
2. Click **+ Create API**
3. Fill in:
   - **Name:** `Project AIR`
   - **Identifier:** `https://air.yourdomain.com` (any URI works; it does not need to exist as a real URL)
   - **Signing Algorithm:** RS256
4. Click **Create**

### 3d: Collect your three credentials

You need these three values for the next step. Find them in Auth0:

| Value | Where to find it |
|-------|-------------------|
| **Tenant Domain** | Application > Settings > Domain (e.g. `dev-abc123xy.us.auth0.com`) |
| **Client ID** | Application > Settings > Client ID (e.g. `GszbWqSkD65eUjv7FrRWYO4IkmGWdd4y`) |
| **API Identifier** | APIs > Your API > Identifier (e.g. `https://air.yourdomain.com`) |

### Checkpoint

Write down or copy all three values. You will paste them in the next step.

---

## Step 4: Create the demo agent

Create a new file called `demo_auth0.py`. You can use any text editor.

**macOS:** `open -e demo_auth0.py` (opens TextEdit)
**Windows:** `notepad demo_auth0.py`
**Linux:** `nano demo_auth0.py`

Paste this entire block into the file. Replace the three placeholder values on lines 9, 10, and 11 with your credentials from Step 3:

```python
from airsdk import AIRRecorder
from airsdk.containment import (
    Auth0Verifier,
    ContainmentPolicy,
    StepUpRequiredError,
)

# === PASTE YOUR THREE VALUES HERE ===
TENANT_DOMAIN = "YOUR_TENANT_DOMAIN"           # e.g. dev-abc123xy.us.auth0.com
CLIENT_ID     = "YOUR_CLIENT_ID"               # e.g. GszbWqSkD65eUjv7FrRWYO4IkmGWdd4y
API_AUDIENCE  = "YOUR_API_IDENTIFIER"           # e.g. https://air.yourdomain.com
# ====================================

policy = ContainmentPolicy(
    deny_tools=["shell_exec"],
    step_up_for_actions=[
        {"tool": "charge_card"},
        {"tool": "access_patient_records"},
    ],
)

verifier = Auth0Verifier(
    issuer=f"https://{TENANT_DOMAIN}/",
    audience=API_AUDIENCE,
)

recorder = AIRRecorder(
    "demo-chain.jsonl",
    user_intent="Process a refund for order #1234",
    containment=policy,
    auth0_verifier=verifier,
)

print("Starting agent...")
recorder.llm_start(prompt="Customer wants a refund for order #1234")
recorder.llm_end(response="I will process the refund now.")
print("Agent decided to charge the card. Checking containment policy...")

try:
    recorder.tool_start(
        tool_name="charge_card",
        tool_args={"amount": -49.99, "reason": "refund"},
    )
    print("Tool call was allowed.")
except StepUpRequiredError as e:
    print("")
    print("=" * 60)
    print("  AGENT HALTED - Human approval required")
    print("=" * 60)
    print("")
    print(f"  Challenge ID: {e.challenge_id}")
    print("")
    print("  To approve, open a NEW terminal window and run:")
    print("")
    print(f"  air approve \\")
    print(f"    --chain demo-chain.jsonl \\")
    print(f"    --challenge-id {e.challenge_id} \\")
    print(f"    --tenant {TENANT_DOMAIN} \\")
    print(f"    --audience {API_AUDIENCE} \\")
    print(f"    --client-id {CLIENT_ID} \\")
    print(f"    --device")
    print("")
    print("  The CLI will give you a URL and a code.")
    print("  Open the URL in any browser.")
    print("  Enter the code and log in.")
    print("  Come back here when done.")
    print("")
```

Save the file.

### Run the demo

**macOS / Linux:**
```bash
python3 demo_auth0.py
```

**Windows:**
```powershell
python demo_auth0.py
```

### Checkpoint

You should see:

```
Starting agent...
Agent decided to charge the card. Checking containment policy...

============================================================
  AGENT HALTED - Human approval required
============================================================

  Challenge ID: a1b2c3d4-e5f6-...

  To approve, open a NEW terminal window and run:

  air approve \
    --chain demo-chain.jsonl \
    --challenge-id a1b2c3d4-e5f6-... \
    --tenant dev-abc123xy.us.auth0.com \
    --audience https://air.yourdomain.com \
    --client-id GszbWqSkD65eUjv7FrRWYO4IkmGWdd4y \
    --device
```

If you see the `AGENT HALTED` message with the full `air approve` command, Step 4 is complete.

**Do not close this terminal window.** Open a new one for the next step.

> **If you see an error instead:** Check that you replaced all three placeholder values in the file and that there are no extra spaces or quotes around them.

---

## Step 5: Approve the action through Auth0

1. Open a **new terminal window** (Cmd+T on macOS, right-click taskbar on Windows)
2. Navigate to the same folder where you ran the demo
3. Copy the entire `air approve ...` command that was printed in Step 4
4. Paste it and press Enter

The CLI will print something like:

```
[AIR v1.0.0] Starting OAuth 2.0 Device Authorization Grant
  Auth0 tenant: dev-abc123xy.us.auth0.com

On any device, open:
  https://dev-abc123xy.us.auth0.com/activate

And enter user code:
  HXRV-GLNP

Polling for approval (timeout 300s)...
```

Now:

1. **Open the URL** in any web browser (the `https://...auth0.com/activate` link)
2. **Enter the user code** shown in the terminal (e.g. `HXRV-GLNP`)
3. Click **Confirm**
4. **Log in** with your Auth0 credentials (or sign up if this is your first time)
5. Click **Accept** if you see a consent screen

### Checkpoint

After you authenticate in the browser, go back to your terminal. You should see:

```
  Approved (after 12.3s).
  Verified token from you@example.com (https://dev-abc123xy.us.auth0.com/)
  HUMAN_APPROVAL appended to demo-chain.jsonl
```

If you see `HUMAN_APPROVAL appended`, the Auth0 integration is working. A cryptographically signed record proving your identity has been added to the forensic chain.

> **If you see `unauthorized_client`:** Go back to Step 3b and make sure Device Code is enabled in Grant Types.
>
> **If you see `Token verification failed`:** Check that `--audience` matches your API Identifier from Step 3c exactly.

---

## Step 6: Verify the chain

In either terminal, run:

```bash
air trace demo-chain.jsonl
```

### Checkpoint

You should see:

```
[Chain verified] 5 signatures valid.
```

The output includes the `HUMAN_APPROVAL` record showing who approved the action, when, and which Auth0 tenant verified their identity.

---

## What just happened

```
You ran demo_auth0.py
    |
The agent tried to call "charge_card"
    |
AIR checked the ContainmentPolicy
    |
The policy says "charge_card needs human approval"
    |
AIR HALTED the agent (it cannot proceed)
    |
You ran "air approve --device" in another terminal
    |
Auth0 authenticated you (you logged in via the browser)
    |
AIR verified the Auth0 token against your tenant's public keys
    |
AIR recorded a signed HUMAN_APPROVAL in the chain
    |
The chain now proves: who approved it, when, and what for
```

No one can alter this record after the fact. Not you, not Vindicara, not the agent. The proof is cryptographic.

---

## What gets recorded in the chain

| Field | What it means | Example |
|-------|--------------|---------|
| `approver_sub` | Who approved (Auth0 user ID) | `auth0\|664f3a...` |
| `approver_email` | Their email address | `you@example.com` |
| `issuer` | Which Auth0 tenant verified them | `https://dev-abc123xy.us.auth0.com/` |
| `audience` | Which API the token was for | `https://air.yourdomain.com` |
| `signed_token` | The original JWT | Can be re-verified offline against JWKS |

An auditor can re-verify any approval using just the chain file and your Auth0 tenant's public JWKS endpoint. No Vindicara account or API call needed.

---

## Troubleshooting reference

| Problem | Cause | Fix |
|---------|-------|-----|
| `command not found: pip3` | pip not on PATH | Use `python3 -m pip install projectair` |
| `command not found: air` | PATH not updated | Close and reopen terminal, or use `python3 -m projectair.cli` |
| `unauthorized_client` | Device Code grant not enabled | Step 3b: enable it in Advanced Settings > Grant Types |
| `Token verification failed` | Wrong audience | `--audience` must match your API Identifier from Step 3c exactly |
| `issuer mismatch` | Wrong tenant domain | `--tenant` must be just the domain, no `https://`, no trailing `/` |
| `connection refused` | Auth0 cannot reach device endpoint | Check your internet connection |

---

## Security properties

- **Fail-closed:** A forged or expired token leaves the action permanently halted
- **Deny overrides step-up:** If a tool is in both `deny_tools` and `step_up_for_actions`, deny always wins
- **Offline verifiable:** Any auditor can re-verify approvals using the JWT and your tenant's public JWKS
- **No phone-home:** Verification uses standard OIDC. No Vindicara API call required

---

## Compliance mapping

| Regulation | Requirement | How this satisfies it |
|-----------|-------------|----------------------|
| EU AI Act Article 14 | Human oversight of AI systems | Authenticated step-up before sensitive actions |
| GDPR Article 22 | Human intervention in automated decisions | Signed proof of who intervened and when |
| SOC 2 CC6 | Logical access controls | Identity-bound approval records |
| HIPAA 164.312 | Access controls for ePHI | Auth0-verified identity on every data access |

---

## Next steps

- **Instrument your real agent:** Replace the demo script with your actual agent code. Add tools to `step_up_for_actions` that you want to gate behind human approval.
- **View chains in the dashboard:** Visit https://cloud.vindicara.io to see your chains, findings, and approvals in a live dashboard.
- **Read the docs:** https://vindicara.io/blog/secure-ai-agents-5-minutes

---

## Support

- **Email:** support@vindicara.io
- **GitHub:** https://github.com/vindicara-inc/projectair
- **Website:** https://vindicara.io
