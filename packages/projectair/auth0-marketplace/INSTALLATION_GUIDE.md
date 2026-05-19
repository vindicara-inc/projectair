# Project AIR: Human-in-the-Loop Containment with Auth0

## Overview

Project AIR is an open-source SDK that gives AI agents a cryptographically signed chain of custody. When an agent attempts a sensitive action, AIR halts it and requires an authenticated human to approve through Auth0 before the agent can proceed.

This guide walks you through the complete setup: from install to a working demo where you see an AI agent get halted, authenticate through your Auth0 tenant, and resume with a signed approval record.

## Prerequisites

- Python 3.12+
- An Auth0 tenant (free tier works)
- 5 minutes

## Quick Start (under 60 seconds)

```bash
pip install projectair
air demo
```

This runs a self-contained demo showing signed capsules being written. To see the Auth0 containment flow, continue below.

## Step 1: Install the SDK

```bash
pip install projectair
```

This installs the `air` CLI and the `airsdk` Python library. No other dependencies.

## Step 2: Get Your Auth0 Credentials

1. Log into your Auth0 Dashboard
2. Go to **Applications > Applications**
3. Select your application (or create a new **Single Page Application**)
4. Copy your **Domain** (e.g. `your-tenant.us.auth0.com`)
5. Copy your **Client ID**

## Step 3: Run the Containment Demo

Save this as `demo_auth0.py`:

```python
from airsdk import AIRRecorder
from airsdk.containment import (
    Auth0Verifier,
    ContainmentPolicy,
    StepUpRequiredError,
)

# 1. Define which tools need human approval
policy = ContainmentPolicy(
    deny_tools=["shell_exec"],                    # always blocked
    step_up_for_actions=[
        {"tool": "charge_card"},                  # needs human approval
        {"tool": "access_patient_records"},        # needs human approval
    ],
)

# 2. Point at your Auth0 tenant
verifier = Auth0Verifier(
    issuer="https://YOUR_DOMAIN.us.auth0.com/",   # <-- replace
    audience="YOUR_CLIENT_ID",                     # <-- replace
)

# 3. Create a recorder with containment enabled
recorder = AIRRecorder(
    "demo-chain.jsonl",
    user_intent="Process a refund for order #1234",
    containment=policy,
    auth0_verifier=verifier,
)

# 4. Simulate an agent workflow
recorder.llm_start(prompt="Customer wants a refund for order #1234")
recorder.llm_end(response="I'll process the refund now.")

# 5. This tool is in the step-up list -- AIR halts the agent
try:
    recorder.tool_start(
        tool_name="charge_card",
        tool_args={"amount": -49.99, "reason": "refund"},
    )
except StepUpRequiredError as e:
    print(f"\nAgent HALTED. Approval required.")
    print(f"Challenge ID: {e.challenge_id}")
    print(f"\nAuthenticate with Auth0 to approve:")
    print(f"  air approve --device --client-id YOUR_CLIENT_ID")
    print(f"\nOr use a token directly:")
    print(f"  air approve --token <paste-jwt-here> --challenge {e.challenge_id}")
```

Run it:

```bash
python demo_auth0.py
```

The agent halts at `charge_card`. It cannot proceed until a human authenticates.

## Step 4: Approve via Auth0

Use the Device Authorization flow (works from any terminal):

```bash
air approve --device --client-id YOUR_CLIENT_ID --challenge CHALLENGE_ID
```

This prints a URL and a code. Open the URL in your browser, enter the code, and authenticate through your Auth0 Universal Login. Once authenticated, the CLI receives the token and submits the approval.

The chain now contains a `HUMAN_APPROVAL` record with:
- **Who** approved it (Auth0 `sub` and `email`)
- **When** they approved it (timestamp)
- **What** they approved (the halted tool call)
- **Proof** (the signed Auth0 JWT, verifiable offline against your tenant's JWKS)

## Step 5: Verify the Chain

```bash
air trace demo-chain.jsonl
```

This verifies every signature in the chain and shows the forensic report, including the human approval record.

## How It Works

```
Your AI agent runs normally
         |
    Agent calls a sensitive tool (charge_card, access_records, etc.)
         |
    AIR checks the ContainmentPolicy
         |
    Policy says: "This tool requires human approval"
         |
    AIR writes a BLOCKED record to the chain and raises StepUpRequiredError
         |
    Your app routes the human to Auth0 (device flow, redirect, or popup)
         |
    Human authenticates via Auth0 Universal Login
         |
    Your app calls recorder.approve(challenge_id, auth0_jwt)
         |
    AIR verifies the JWT against your tenant's JWKS (RS256/RS384/RS512)
         |
    AIR writes a HUMAN_APPROVAL record with the verified claims
         |
    Agent resumes. The tool call proceeds.
         |
    The chain is now court-grade evidence of who authorized what.
```

## What Gets Recorded

Every approval in the chain contains:

| Field | Source | Purpose |
|-------|--------|---------|
| `approver_sub` | Auth0 `sub` claim | Who approved |
| `approver_email` | Auth0 `email` claim | Human-readable identity |
| `issuer` | Auth0 tenant URL | Which identity provider |
| `audience` | Auth0 Client ID | Which application |
| `issued_at` | JWT `iat` | When the token was issued |
| `expires_at` | JWT `exp` | Token validity window |
| `signed_token` | Raw JWT | Offline re-verification against JWKS |

## Security Properties

- **Fail-closed**: A forged or expired token leaves the action permanently halted
- **Deny overrides step-up**: If a tool is in both `deny_tools` and `step_up_for_actions`, deny wins
- **Offline verifiable**: Any auditor can re-verify the approval using the JWT + your tenant's public JWKS
- **No phone-home**: Verification uses standard OIDC. No Vindicara API call required

## Compliance Mapping

| Regulation | Requirement | How AIR + Auth0 satisfies it |
|-----------|-------------|------------------------------|
| EU AI Act Article 14 | Human oversight of AI systems | Authenticated step-up before sensitive actions |
| GDPR Article 22 | Human intervention in automated decisions | Signed proof of who intervened |
| SOC 2 CC6 | Logical access controls | Identity-bound approval records |
| HIPAA 164.312 | Access controls for ePHI | Auth0-verified identity on every data access |

## Support

- **Docs**: [vindicara.io](https://vindicara.io)
- **Quickstart**: [Secure AI Agents in 5 Minutes](https://vindicara.io/blog/secure-ai-agents-5-minutes)
- **GitHub**: [github.com/vindicara-inc/projectair](https://github.com/vindicara-inc/projectair)
- **Email**: support@vindicara.io
