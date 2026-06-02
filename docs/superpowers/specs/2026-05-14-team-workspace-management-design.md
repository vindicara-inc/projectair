# Team-Tier Workspace Management

**Date:** 2026-05-14
**Status:** Draft
**Scope:** AIR Cloud dashboard (Team tier, $599/mo). Enterprise SSO/SAML/RBAC deferred to Q3.

## Problem

The AIR Cloud dashboard is single-workspace, single-user. The Team tier on the pricing page promises "shared keys + workspace roles." Team members need isolated views of their own agent chains, while workspace owners need cross-member visibility, compliance rollups, and analytics. Auth0 is integrated but not wired to workspace provisioning.

## Design Decisions

1. **Auth0 SSO auto-provisioning.** Teammates log in via Auth0, dashboard auto-mints their API key via `POST /v1/sso/login`. No manual key sharing.
2. **Role-gated views.** Members see only their own chains. Owner/admin sees everything plus 4 admin screens.
3. **SvelteKit routes.** Each screen is its own route under `/dashboard/`. Deep-linkable, browser-nav friendly, clean file separation.
4. **Left sidebar navigation.** Narrow rail with role-conditional items.
5. **Data isolation enforced server-side.** Members see only capsules ingested under their API key. Filtering is in backend middleware, never trusted from the frontend.

## Architecture

### Auth Flow

```
User hits /dashboard/
  -> Auth0 redirect (if no session)
  -> Auth0 callback with JWT
  -> Dashboard sends JWT to POST /v1/sso/login
  -> Backend verifies JWT against Auth0 JWKS
  -> Backend checks allowed_email_domains from SSO config
  -> Backend mints or retrieves stable API key (key_id = hash(workspace_id, issuer, sub))
  -> Returns API key + role + workspace metadata
  -> Dashboard stores in session store, renders role-appropriate view
```

Owner bootstraps workspace once (`POST /v1/workspaces`), then configures SSO (`PUT /v1/sso/config`) with the Auth0 tenant domain, audience, default role, and allowed email domains.

### Routes

```
/dashboard/                -> Forensic chain view (existing, refactored)
/dashboard/team            -> Team member management (owner/admin)
/dashboard/activity        -> Cross-member activity feed (owner/admin)
/dashboard/compliance      -> Aggregate compliance scores (owner/admin)
/dashboard/analytics       -> Workspace metrics (owner/admin)
```

### Shared Layout (`/dashboard/+layout.svelte`)

- Auth gate: redirect to Auth0 login if no session
- SSO auto-provision: exchange Auth0 token for workspace API key
- Left sidebar: role-conditional nav items
- Role guard: admin routes redirect to `/dashboard/` for member/viewer roles

### Left Sidebar

~56px collapsed (icons only), ~200px on hover/click.

Items (top to bottom):
- **Chain** (link icon) -- all roles
- **Team** (users icon) -- owner/admin only
- **Activity** (feed icon) -- owner/admin only
- **Compliance** (shield icon) -- owner/admin only
- **Analytics** (chart icon) -- owner/admin only

Bottom section:
- Workspace name
- User email (truncated)
- Role badge (owner/admin/member/viewer)
- Logout button

## Screens

### 1. Forensic Chain View (`/dashboard/`)

The existing dashboard, unchanged in functionality. Data scope depends on role:
- **Member/viewer:** capsules from their own API key only
- **Owner/admin:** all workspace capsules, with a member filter dropdown

### 2. Team Members (`/dashboard/team`)

**Member table columns:** email, role (badge), status (active/revoked), last active, key ID (truncated 8 chars).

**Invite form:** email input + role dropdown (member/admin) + "Invite" button.
- Calls `POST /v1/workspaces/me/members`
- On success: shows message "Invite sent. They can log in with Auth0 to access the workspace."
- With SSO configured, no key sharing needed; the teammate just logs in

**Row actions:**
- Change role: dropdown (member/admin). Owner calls `PATCH /v1/keys/{key_id}` with new role.
- Revoke: confirmation dialog, calls `DELETE /v1/keys/{key_id}`

**Constraints:**
- Owner cannot be removed or demoted
- Admin can invite members but not other admins (owner-only privilege)
- Viewer is read-only, cannot export or generate reports

### 3. Activity Overview (`/dashboard/activity`)

Reverse-chronological feed of capsule events across all workspace members.

**Each row:** timestamp, member email, agent name, step kind (badge), finding count (red if >0).

**Filters:** member (dropdown), date range (picker), severity (dropdown: all/critical/high/medium/low).

**Data source:** `GET /v1/capsules` without key-scope filter (admin privilege). Backend returns `api_key_name` field on each capsule for attribution.

### 4. Compliance Dashboard (`/dashboard/compliance`)

Four framework cards in a 2x2 grid:
- EU AI Act Article 72
- HIPAA Security Rule (2026 NPRM)
- NIST AI RMF
- SOC 2 AI

**Each card:** framework name, control count, evidence coverage % (controls with sufficient evidence / total controls), last evidence timestamp, status badge (compliant/partial/insufficient).

**Card expand:** click to see control-level detail. Each control row: control ID, name, evidence count vs. `min_evidence_count`, status (met/unmet).

**New backend endpoint:** `GET /v1/compliance/summary`
- Returns per-framework scores aggregated across all workspace capsules
- Requires `READ_CAPSULES` capability (owner/admin)

### 5. Analytics (`/dashboard/analytics`)

**Headline stats (4 cards):** total capsules (all time), capsules this week, unique agents, active members.

**Detector trigger chart:** horizontal bar chart, one bar per detector (ASI01-ASI10, AIR-01 to AIR-06). Count of findings. Sorted by frequency.

**Chain health:** pie/donut chart. Verified vs. tampered vs. broken-link capsules as percentages.

**Ingestion rate:** sparkline or area chart. Capsules per day over the last 30 days.

**New backend endpoint:** `GET /v1/analytics/summary`
- Returns aggregated metrics across all workspace capsules
- Requires `READ_CAPSULES` capability (owner/admin)

## Security Model

Every boundary is server-enforced. The frontend is untrusted display.

### Authentication

- **Auth0 JWT verification:** backend verifies every JWT against Auth0's JWKS endpoint using RS256/RS384/RS512. No symmetric secrets. Token expiry enforced. `iss` and `aud` claims validated against SSO config.
- **API key hashing:** API keys stored as BLAKE3 hashes in DynamoDB, never plaintext. Lookup is hash-based. The raw key is returned exactly once at creation and never stored.
- **Zero local storage.** Nothing written to localStorage, sessionStorage, IndexedDB, or cookies by the dashboard. All state is in-memory only. Page refresh or tab close = full re-authentication.
- **Auth0 handles session.** Auth0 SDK configured with `cacheLocation: 'memory'` and `useRefreshTokens: true`. Session lives in Auth0's servers. Silent re-auth via Auth0's `/authorize` iframe (no client-side token persistence). If the Auth0 session expires, user logs in again.
- **Short-lived session tokens from backend.** On Auth0 callback, dashboard sends the Auth0 JWT to `POST /v1/sso/login`. Backend verifies against Auth0 JWKS, returns a short-lived session token (15-minute expiry, signed JWT with `workspace_id`, `role`, `sub`). Dashboard holds this in memory as the Bearer token for all API calls. On expiry, silent Auth0 re-auth + fresh token exchange. No long-lived credentials on the client, ever.
- **All durable state lives server-side.** Workspace metadata, capsules, keys, roles, SSO config: all in DynamoDB behind the API. The browser is a stateless view layer.

### Authorization

- **Server-side role enforcement:** every API route checks `request.state.role` against the capability matrix before executing. The frontend hides UI elements by role, but the backend enforces independently.
- **Capability matrix (from existing `roles.py`):**

| Capability | Owner | Admin | Member | Viewer |
|---|---|---|---|---|
| READ_WORKSPACE | yes | yes | yes | yes |
| READ_CAPSULES | yes | yes | yes (own key) | yes (own key) |
| WRITE_CAPSULES | yes | yes | yes | no |
| LIST_KEYS | yes | yes | no | no |
| ISSUE_KEY | yes | yes (member only) | no | no |
| REVOKE_KEY | yes | yes (member only) | no | no |
| INVITE_MEMBER | yes | yes (member only) | no | no |
| DELETE_WORKSPACE | yes | no | no | no |

- **Privilege escalation prevention:** admin cannot invite with role=admin or role=owner. Backend validates `role` field on invite against the caller's own role. Owner is the only role that can mint admin keys.
- **Self-demotion prevention:** owner cannot change their own role or revoke their own key.

### Data Isolation

- **Capsule scoping:** middleware injects `api_key_id` into every query. For member/viewer roles, the capsule store filters by `api_key_id`. For owner/admin, no filter (full workspace view). This is NOT a query parameter the client can override; it is derived from the authenticated key server-side.
- **No cross-workspace access:** API keys are workspace-scoped. There is no endpoint that accepts a `workspace_id` parameter; it is always derived from the authenticated key. A key from workspace A cannot read workspace B's data.
- **Admin endpoints reject non-admin roles:** `/v1/compliance/summary`, `/v1/analytics/summary`, `/v1/workspaces/me/members` all require `LIST_KEYS` capability (owner/admin only). 403 Forbidden otherwise.

### Transport Security

- **HTTPS only:** `cloud.vindicara.io` enforces TLS 1.2+. No plaintext HTTP.
- **CORS:** origin whitelist, no wildcard. Dashboard origin only.
- **Security headers:** `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy` with restrictive `script-src`.
- **Rate limiting:** per-key rate limits on all endpoints. Prevents brute-force key enumeration.

### Input Validation

- **Email validation:** `MemberInvite.email` validated as RFC 5322 email format via Pydantic `EmailStr`. Domain checked against `allowed_email_domains` from SSO config.
- **Role validation:** `MemberInvite.role` validated against `{"member", "admin"}` enum. No arbitrary strings.
- **Pagination bounds:** `limit` parameter clamped to [1, 1000]. `offset` must be non-negative.
- **No dynamic queries:** all database access uses parameterized queries (DynamoDB expressions). No string interpolation into queries.

### Revocation

- **Immediate effect:** revoking a key sets `revoked_at` timestamp. `ApiKeyStore.lookup()` returns `None` for revoked keys. Next API call with that key gets 401.
- **SSE stream termination:** when a key is revoked, any active SSE stream for that key is closed server-side within the next heartbeat interval (5 seconds).
- **No cached access:** API key validation happens on every request. No token caching window where a revoked key still works.

### Audit

- **Key lifecycle events:** key creation, role changes, and revocations are logged to the workspace's AgDR chain as `ADMIN_ACTION` step kinds. These are signed and anchored like any other capsule.
- **Auth failures:** failed JWT verification, invalid API keys, and privilege violations are logged server-side with source IP and timestamp. Not exposed to the caller (prevents enumeration).

## New Backend Endpoints

### `GET /v1/compliance/summary`

Returns per-framework compliance scores for the workspace.

```json
{
  "frameworks": [
    {
      "framework_id": "hipaa-security",
      "name": "HIPAA Security Rule (2026 NPRM)",
      "total_controls": 8,
      "met_controls": 6,
      "coverage_pct": 75.0,
      "last_evidence_at": "2026-05-14T20:30:00Z",
      "controls": [
        {
          "control_id": "HIPAA-1",
          "control_name": "Access Control",
          "evidence_count": 12,
          "required": 1,
          "met": true
        }
      ]
    }
  ]
}
```

Requires: `READ_CAPSULES` capability (owner/admin).

### `GET /v1/analytics/summary`

Returns aggregated workspace metrics.

```json
{
  "total_capsules": 14523,
  "capsules_this_week": 892,
  "unique_agents": 5,
  "active_members": 3,
  "detector_counts": {
    "ASI01": 12,
    "ASI02": 45,
    "AIR-04": 3
  },
  "chain_health": {
    "verified": 14510,
    "tampered": 2,
    "broken_link": 11
  },
  "daily_ingestion": [
    {"date": "2026-05-14", "count": 234},
    {"date": "2026-05-13", "count": 198}
  ]
}
```

Requires: `READ_CAPSULES` capability (owner/admin).

### `PATCH /v1/keys/{key_id}`

Updates the role on an existing API key.

```json
{"role": "admin"}
```

Requires: `ISSUE_KEY` capability. Owner-only for promoting to admin. Returns 403 if caller tries to set a role >= their own (except owner setting admin).

## Frontend Components

### New Files

```
src/routes/dashboard/+layout.svelte        -- sidebar + auth gate + role guard
src/routes/dashboard/+page.svelte          -- forensic chain (refactored from current root)
src/routes/dashboard/team/+page.svelte     -- team member management
src/routes/dashboard/activity/+page.svelte -- activity feed
src/routes/dashboard/compliance/+page.svelte -- compliance dashboard
src/routes/dashboard/analytics/+page.svelte  -- analytics
src/lib/panels/Sidebar.svelte             -- left sidebar nav
src/lib/panels/TeamTable.svelte           -- member table + invite form
src/lib/panels/ComplianceCard.svelte      -- single framework card
src/lib/panels/AnalyticsCards.svelte      -- headline stat cards
src/lib/stores/team.svelte.ts             -- team member state
src/lib/stores/role.svelte.ts             -- current user role state
```

### Modified Files

```
src/routes/+layout.svelte                 -- remove auth gate (moved to dashboard layout)
src/routes/+page.svelte                   -- redirect to /dashboard/
src/lib/stores/cloud_session.svelte.ts    -- replace localStorage persistence with memory-only, add SSO login flow, role field
src/lib/transport/air_cloud_client.ts     -- add compliance, analytics, member, key endpoints
```

## Testing

- **Role guard tests:** verify member/viewer cannot access admin routes (server returns 403)
- **Data isolation tests:** verify member API key returns only own capsules
- **Privilege escalation tests:** verify admin cannot invite with role=owner, member cannot invite at all
- **SSO flow tests:** verify Auth0 JWT exchange mints correct role key
- **Revocation tests:** verify revoked key returns 401 immediately
- **Component tests (Vitest):** sidebar renders correct items per role, team table invite flow, compliance card rendering
- **Bundle budget:** verify new routes stay within 350KB JS budget

## Out of Scope

- Enterprise SSO (SAML, Okta, Entra) -- Q3
- Billing/seat enforcement -- requires Stripe integration, separate feature
- Email notifications for invites -- SSO auto-provision eliminates the need
- Multi-workspace switching -- Team tier is single workspace; Enterprise gets multi-workspace
- Workspace deletion UI -- owner-only, rare operation, keep as API-only for now
