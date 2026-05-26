# Project AIR Identity Capture (Phase 1) Design

Date: 2026-05-25
Status: Approved
Tier: OSS (CLI surfaces) + Engine (backend routes)

## Problem

Vindicara has no visibility into who installs or uses Project AIR. On launch day, there is no way to know how many people tried `air demo`, what versions are active, or who to contact for feedback. The PyPI download counter and GitHub traffic are the only signals, and neither gives identity or engagement depth.

## Customer-facing value

"Know who's using AIR, reach them when it matters (security advisories, breaking changes), and see version distribution across the install base, all through consent-based surfaces that provide real value to the user."

## Decisions locked

- **Auth0 for CLI identity.** Same tenant (`dev-kilt2vkudvbu75ny.us.auth0.com`), new "Project AIR CLI" Native application. Reuse existing device flow code from `airsdk.containment.auth0_flows`.
- **Email-only first-run prompt.** One field, highest conversion. No role, no company. Asks once, ever.
- **Update checker is opt-in.** First-run prompt asks; user can disable via `air config set update_check false`.
- **Backend routes on existing Vindicara API.** Two new routes in `src/vindicara/api/`. Same Lambda, same API Gateway. No separate service.
- **All surfaces are consent-based.** No silent telemetry. OSS works fully offline if user skips everything.
- **Config at `~/.config/projectair/`.** Session, config, and marker files. Platform-appropriate via Python's `platformdirs` or manual `~/.config` on Unix, `%APPDATA%` on Windows.

## Architecture

### CLI surfaces (OSS, `packages/projectair/`)

#### `air login`

New CLI command. Auth0 device authorization flow.

```
$ air login

  Authenticating with Vindicara...

  On any device, open:
    https://dev-kilt2vkudvbu75ny.us.auth0.com/activate

  And enter user code:
    HXRV-GLNP

  Waiting for authentication...

  Logged in as kevin@sltrdigital.com
  Session saved to ~/.config/projectair/session.json
```

Implementation reuses `start_device_flow` and `poll_device_token` from `airsdk.containment.auth0_flows`. New Auth0 application client ID is configured as a constant in the CLI module (not user-configurable; this is the Vindicara-operated identity app).

Session file at `~/.config/projectair/session.json`:

```json
{
  "access_token": "eyJ...",
  "id_token": "eyJ...",
  "email": "kevin@sltrdigital.com",
  "sub": "auth0|664f3a...",
  "expires_at": "2026-06-01T12:00:00Z",
  "logged_in_at": "2026-05-25T12:00:00Z"
}
```

#### `air logout`

Deletes `~/.config/projectair/session.json`. Prints "Logged out."

#### `air whoami`

Reads session file. If valid and not expired: "Logged in as kevin@sltrdigital.com". If expired: "Session expired. Run `air login` to re-authenticate." If missing: "Not logged in. Run `air login`."

#### First-run email prompt

Triggers once on first invocation of `air demo` or `air trace` when:
1. No session file exists (user hasn't run `air login`)
2. No `~/.config/projectair/prompted` marker file exists

```
  Want security advisories and release notes for Project AIR?
  Email (or press Enter to skip): user@example.com

  Thanks! You'll get security advisories only. No spam.
```

Behavior:
- If email provided: POST to `/api/v1/identity/register` with `{"email": "...", "source": "first_run", "version": "1.0.1", "platform": "darwin"}`. Store email in `~/.config/projectair/config.toml`.
- If Enter pressed (skip): no POST.
- In both cases: create `~/.config/projectair/prompted` marker file so it never asks again.
- If stdin is not a TTY (CI, piped input): skip silently, create marker.

#### Update checker (opt-in)

Asked during first-run prompt, after the email question:

```
  Check for AIR updates automatically? [Y/n]: Y
  Update checks enabled. Disable anytime: air config set update_check false
```

When enabled (`update_check = true` in config):
- On any `air` command, check if 24 hours have passed since `last_check` timestamp in config.
- If yes: `GET /api/v1/telemetry/version-check?version=1.0.1&python=3.13&platform=darwin&session_id=<hash>`.
- `session_id` is BLAKE3 hash of `platform.node()` (machine hostname). Not the Auth0 identity. Anonymous.
- Response: `{"latest": "1.1.0", "update_available": true}`.
- If update available, print one line before normal output: `A newer version of AIR is available (1.1.0). Run: pip install --upgrade projectair`
- Update `last_check` in config.
- If the request fails (network error, timeout >2s), silently skip. Never block the user's command.

#### `air config`

```
air config set <key> <value>     Set a config value
air config get <key>             Get a config value
air config list                  Show all config
```

Config file at `~/.config/projectair/config.toml`:

```toml
[identity]
email = "kevin@example.com"

[telemetry]
update_check = true
last_check = "2026-05-25T12:00:00"
```

### Backend routes (Engine, `src/vindicara/api/`)

#### `POST /api/v1/identity/register`

Unauthenticated. Rate-limited by IP (10 req/min).

Request body:
```json
{
  "email": "user@example.com",
  "source": "first_run",
  "version": "1.0.1",
  "platform": "darwin"
}
```

Stores in DynamoDB `identity_registrations` table:
- Partition key: `email`
- Sort key: `registered_at` (ISO 8601)
- Attributes: `source`, `version`, `platform`, `ip_hash` (BLAKE3 of IP, not raw IP)
- Deduplicates by email (conditional put, only if email doesn't exist)

Response: `201 Created` with `{"status": "registered"}` or `200 OK` with `{"status": "already_registered"}`.

Validation: email must contain `@` and at least one `.` after `@`. No regex email validation (too many false negatives). Reject empty strings.

#### `GET /api/v1/telemetry/version-check`

Unauthenticated. Rate-limited by IP (30 req/min).

Query params:
- `version` (required): current AIR version
- `python` (optional): Python version
- `platform` (optional): OS platform
- `session_id` (optional): anonymous machine hash

Stores ping in DynamoDB `telemetry_pings` table:
- Partition key: `session_id` (or `anonymous` if not provided)
- Sort key: `timestamp` (ISO 8601)
- Attributes: `version`, `python`, `platform`
- TTL: 90 days (DynamoDB TTL attribute)

Response:
```json
{
  "latest": "1.1.0",
  "update_available": true,
  "release_url": "https://github.com/vindicara-inc/vindicara/releases/tag/v1.1.0"
}
```

The `latest` version is read from a config value or hardcoded constant, updated on each release. Not dynamically queried from PyPI (avoid PyPI as a runtime dependency for the API).

### CDK additions (`src/vindicara/infra/`)

New DynamoDB tables in `DataStack`:

**`identity_registrations`**
- Partition key: `email` (S)
- Sort key: `registered_at` (S)
- Billing mode: PAY_PER_REQUEST
- No TTL (retain indefinitely for CRM)

**`telemetry_pings`**
- Partition key: `session_id` (S)
- Sort key: `timestamp` (S)
- Billing mode: PAY_PER_REQUEST
- TTL attribute: `ttl` (90 days from timestamp)

Both tables follow the existing `DataStack` pattern (table name from environment variable, `VINDICARA_` prefix).

### Config directory structure

```
~/.config/projectair/
  session.json          # Auth0 login session (air login)
  config.toml           # User preferences (update_check, email)
  prompted              # Marker: first-run prompt shown (empty file)
  last_check            # Timestamp of last update check (legacy, moved to config.toml)
```

`~/.config/projectair/` is already used by the anchoring module for `anchoring_key.pem`. This is consistent.

## Privacy contract

Documented on the healthcare page FAQ and in `air login --help`:

- **No silent telemetry.** Every network call is opt-in. The OSS CLI works fully offline.
- **Email is voluntary.** First-run prompt can be skipped. No functionality is gated behind it.
- **Update checks are opt-in.** Disabled by default if user skips the first-run prompt. Enabled only with explicit "Y".
- **Session data stays local.** The Auth0 token is stored on disk, not sent to Vindicara. Only the email and sub are visible to us (through Auth0's user management dashboard).
- **Anonymous machine ID.** The update checker sends a BLAKE3 hash of the hostname, not the hostname itself. Used for deduplication only.
- **No IP storage.** The API stores `ip_hash` (BLAKE3 of IP), not the raw IP address.
- **90-day TTL on telemetry.** Ping data auto-expires. Identity registrations are retained for CRM.

## Test plan

### CLI tests (`packages/projectair/tests/`)

- `test_login.py`: mock Auth0 device flow, verify session file written, verify `air whoami` reads it, verify `air logout` deletes it, verify expired session detected
- `test_first_run.py`: mock stdin with email, verify POST called, verify marker created, verify skip creates marker without POST, verify non-TTY skips silently
- `test_update_check.py`: mock version-check endpoint, verify "update available" printed, verify 24h cache respected, verify network failure silently skipped, verify opt-out respected
- `test_config.py`: set/get/list operations on config.toml

### API tests (`tests/unit/api/` and `tests/integration/api/`)

- `test_identity_routes.py`: register with valid email, deduplicate existing email, reject empty email, rate limit
- `test_telemetry_routes.py`: version-check returns latest, stores ping, handles missing optional params

### CDK tests

- Verify tables created with correct key schema and TTL

## Dependencies

No new dependencies for the CLI surfaces. `tomli` / `tomllib` (stdlib in Python 3.11+) for config.toml parsing. `tomli-w` for writing TOML (add to dev deps or use a simpler format if this is too heavy; alternatively write config as simple key=value or JSON).

Auth0 device flow reuses existing `httpx` dependency.

## Versioning

Ships in the next `projectair` release (OSS). Backend routes ship with the next `vindicara` engine deploy.

## Future (Phase 2, not in this spec)

- **Telemetry dashboard** at `vindicara.io/admin` showing active installs, version distribution, registered emails
- **`air init`** interactive onboarding (guided first project setup with login prompt)
- **Integrity check** (opt-in startup signature verification against Sigstore Fulcio)
- **Pro trial signup** ("30-day free Pro trial, drop your email for a key")
- **Run telemetry for Pro+** (opt-in AgDR run metadata streaming to hosted dashboard)
