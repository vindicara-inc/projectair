# MCP Security Scanner v1 - Design Specification

## Goal

Build a standalone MCP security scanner that performs static config analysis and live active probing of MCP servers, producing risk scores, categorized findings with severity, and actionable remediation guidance. Available as both an SDK method (`vc.mcp.scan()`) and an API endpoint (`POST /v1/mcp/scan`).

## Why

RSA 2026 confirmed: only 8% of MCP servers implement OAuth, and nearly half of those have material flaws. MITRE ATLAS and NIST don't cover MCP-specific attack vectors. There is no standalone tool that security teams can point at an MCP server and get back a vulnerability report. Vindicara will be the first.

This is also the viral acquisition hook: a free-tier tool that creates urgency ("your MCP servers are exposed") and drives developers toward the full Vindicara platform.

## Two Scan Modes

### Mode 1: Static Analysis (Config Scan)

Input: MCP server manifest/config as a JSON dict (the `tools` array, server metadata, auth config).

Checks performed:

1. **Dangerous tool detection**: Flag tools whose names or descriptions match known dangerous patterns: `shell_exec`, `eval`, `run_command`, `execute_sql`, `file_write`, `file_delete`, `rm`, `drop_table`. Severity: CRITICAL.

2. **Overprivileged tools**: Flag tools with write/delete/admin capabilities that lack explicit scoping constraints in their input schema. A tool named `delete_record` that accepts an arbitrary `table` string parameter is overprivileged. Severity: HIGH.

3. **Missing auth configuration**: Check if the server config declares an auth mechanism (OAuth, API key, bearer token). If no auth is declared, flag it. Severity: CRITICAL.

4. **Weak auth configuration**: If auth is declared but uses basic auth, static API keys without rotation policy, or OAuth without PKCE, flag it. Severity: HIGH.

5. **Overly broad input schemas**: Flag tools where the input schema accepts unconstrained strings for parameters that should be structured (e.g., a `query` parameter that takes raw SQL instead of structured filters). Severity: MEDIUM.

6. **Tool description injection**: Check if tool descriptions contain prompt-like instructions that could manipulate agent behavior (e.g., "Always call this tool first", "Ignore other instructions"). Severity: HIGH.

7. **Missing rate limit config**: Check if the server config declares rate limiting. If not, flag it. Severity: MEDIUM.

8. **Excessive tool count**: If a server exposes more than 25 tools, flag it as an expanded attack surface. Severity: LOW.

### Mode 2: Live Probing (Active Scan)

Input: MCP server URL (SSE endpoint or connection config).

The scanner connects to the live server and runs the following probes sequentially:

1. **Unauthenticated enumeration**: Connect without credentials and attempt to list available tools via `tools/list`. If the server responds with a tool list, flag as CRITICAL (no auth on tool enumeration).

2. **Auth bypass attempts**:
   - Send requests with no auth header
   - Send requests with an empty bearer token
   - Send requests with `Bearer null` / `Bearer undefined`
   - Send requests with a malformed JWT (valid structure, invalid signature)
   - If any succeeds, flag as CRITICAL.

3. **Tool invocation without auth**: Attempt to call a read-only tool (if any found) without credentials. If it succeeds, flag as CRITICAL.

4. **Rate limit testing**: Send 20 rapid-fire `tools/list` requests within 2 seconds. If all succeed with no 429 responses or throttling, flag as MEDIUM (no rate limiting detected).

5. **Input injection probes**: For each tool found, attempt to call it with adversarial payloads in string parameters:
   - Path traversal: `../../etc/passwd`
   - Command injection: `; ls -la /`
   - SQL injection: `' OR 1=1 --`
   - Template injection: `{{7*7}}`
   - If the server returns data suggesting the injection succeeded (file contents, command output, unexpected rows, `49`), flag as CRITICAL. If it returns an error that reveals server internals (stack traces, file paths), flag as HIGH.

6. **Privilege escalation**: If the server declares tool-level permissions/scopes, attempt to call a tool outside the declared scope. If it succeeds, flag as CRITICAL.

7. **Data exfiltration check**: Call a tool with a request for minimal data, check if the response includes fields beyond what was requested (e.g., request a user's name, response includes email/SSN). Flag as HIGH.

8. **Oversized input handling**: Send a tool call with a 1MB string parameter. If the server processes it without rejecting, flag as MEDIUM (no input size validation). If it crashes or times out, flag as HIGH (potential DoS vector).

### Probe Safety

- All probes use read-only operations when possible
- Probes that could modify data (write/delete tools) are only analyzed, never invoked with real data. The scanner sends obviously fake payloads like `{"id": "VINDICARA_SCAN_TEST_00000"}` so operators can identify scan traffic
- A `--dry-run` flag shows what probes would run without executing them
- All probe traffic includes a `User-Agent: Vindicara-MCP-Scanner/0.1.0` header

## Data Models

### ScanRequest (API input)

```python
class ScanRequest(BaseModel):
    server_url: str = ""          # For live scan
    config: dict = {}             # For static scan
    mode: ScanMode = "auto"       # "static", "live", "auto" (auto = both if URL provided)
    timeout_seconds: float = 30.0
    dry_run: bool = False
```

### ScanReport (output)

```python
class ScanReport(BaseModel):
    scan_id: str
    server_url: str = ""
    mode: ScanMode
    risk_score: float             # 0.0 - 1.0
    risk_level: RiskLevel         # LOW, MEDIUM, HIGH, CRITICAL
    findings: list[Finding]
    remediation: list[Remediation]
    tools_discovered: int
    scan_duration_ms: float
    timestamp: str

class Finding(BaseModel):
    finding_id: str
    category: FindingCategory     # AUTH, PERMISSIONS, INJECTION, RATE_LIMIT, CONFIG, DATA_LEAK
    severity: Severity            # LOW, MEDIUM, HIGH, CRITICAL
    title: str
    description: str
    evidence: str = ""            # What the scanner observed
    cwe_id: str = ""              # CWE reference where applicable

class Remediation(BaseModel):
    finding_id: str
    priority: int                 # 1 = fix first
    action: str                   # What to do
    reference: str = ""           # Link to docs/standard
```

### Risk Scoring

The risk score is computed from findings:
- Each CRITICAL finding adds 0.3 (capped contribution of 0.9)
- Each HIGH finding adds 0.15 (capped contribution of 0.6)
- Each MEDIUM finding adds 0.05 (capped contribution of 0.3)
- Each LOW finding adds 0.02 (capped contribution of 0.1)
- Final score is clamped to [0.0, 1.0]

Risk levels: 0.0-0.3 = LOW, 0.3-0.6 = MEDIUM, 0.6-0.8 = HIGH, 0.8-1.0 = CRITICAL

## SDK Interface

```python
# Static scan from config
report = vc.mcp.scan_config(config={"tools": [...], "auth": {...}})

# Live scan
report = vc.mcp.scan(server_url="https://mcp.example.com")

# Full scan (static + live)
report = vc.mcp.scan(server_url="https://mcp.example.com", config=server_config)

# Dry run
report = vc.mcp.scan(server_url="https://mcp.example.com", dry_run=True)

# Access results
print(report.risk_score)       # 0.82
print(report.risk_level)       # "CRITICAL"
for f in report.findings:
    print(f"{f.severity}: {f.title}")
    print(f"  Evidence: {f.evidence}")
for r in report.remediation:
    print(f"  [{r.priority}] {r.action}")
```

## API Endpoint

`POST /v1/mcp/scan`

Request body: `ScanRequest`
Response body: `ScanReport`
Auth: requires `X-Vindicara-Key`

## MCP Transport

The scanner needs to communicate with MCP servers. MCP uses JSON-RPC 2.0 over two transports:

1. **SSE (Server-Sent Events)**: HTTP-based. POST to send messages, SSE stream for responses. This is what most remote MCP servers use.

2. **Stdio**: Subprocess-based. Not applicable for remote scanning.

For v1, we support SSE transport only. The scanner sends JSON-RPC requests:
- `initialize` (handshake)
- `tools/list` (enumerate tools)
- `tools/call` (invoke a tool, used for probing)

## File Structure

```
src/vindicara/mcp/
    __init__.py         # Public exports
    scanner.py          # Scan orchestrator (runs static + live, combines results)
    analyzer.py         # Static config analysis (8 checks)
    prober.py           # Live active probing (8 probe types)
    risk.py             # Risk score computation
    findings.py         # Finding, Remediation, ScanReport models
    transport.py        # MCP JSON-RPC client over SSE
```

Tests:
```
tests/unit/mcp/
    __init__.py
    test_analyzer.py    # Static analysis checks
    test_prober.py      # Live probing (mocked server responses)
    test_risk.py        # Risk score computation
    test_scanner.py     # Orchestrator integration
tests/integration/mcp/
    __init__.py
    test_scan_endpoint.py  # API endpoint tests
    conftest.py         # Vulnerable test MCP server fixture
```

## API Route

New file: `src/vindicara/api/routes/scans.py`

Registered in `app.py` alongside existing routes.

## What is NOT in scope

- Stdio transport (local subprocess MCP servers)
- Scheduled/recurring scans
- Scan history storage in DynamoDB
- Dashboard UI for scan results
- PDF report generation
- Comparison between scan runs

These are all Phase 3+ features.
