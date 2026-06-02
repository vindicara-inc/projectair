# Vindicara Engineering Standards

Full engineering standards. For operational context (commands, repo layout, current state), see `CLAUDE.md` at the repo root. For product context (vision, pricing, GTM), see `docs/SPEC.md`.

---

## Stack

- **Language**: Python 3.12+
- **API Framework**: FastAPI (async, auto-generated OpenAPI docs, Pydantic validation)
- **Validation**: Pydantic v2 (all external data boundaries)
- **HTTP Client**: httpx (async-native)
- **Logging**: structlog (structured, context-bound)
- **Testing**: pytest + pytest-asyncio + pytest-cov + hypothesis
- **Linting**: ruff (replaces flake8, isort, pyupgrade)
- **Formatting**: ruff format (black-compatible)
- **Type Checking**: mypy --strict
- **Frontend**: SvelteKit (marketing site + dashboard)
- **Infrastructure**: AWS serverless-first
- **Lambda Runtime**: Python 3.12 via Mangum
- **IaC**: CDK (Python)
- **Database**: DynamoDB (structured data, policy state, agent registry)
- **Object Storage**: S3 (raw payloads, compliance artifacts, audit archives)
- **Queue**: SQS (async policy evaluation, compliance report generation)
- **Events**: EventBridge (real-time alerts, drift notifications)
- **Tracing**: X-Ray
- **SDK Distribution**: PyPI

---

## Code Quality (Non-Negotiable)

- Write production code. Every commit is deployable. No "we will fix this later."
- No `print()` in production paths. structlog with context-bound loggers only.
- Full type hints on every function signature. `mypy --strict` is the bar.
- No `Any` type. Ever. If you reach for `Any`, you do not understand the data yet. Stop and think.
- No bare `except:` or `except Exception:` without re-raising or specific handling.
- No `TODO` comments without a linked issue or explicit timeline.
- Functions do one thing. If you need "and" to describe it, split it.
- Error handling is not optional. Every async operation has explicit error handling with meaningful, actionable messages.
- No magic numbers or strings. Constants are named and co-located.
- Pydantic models for ALL external data boundaries: API requests, API responses, SDK inputs, SDK outputs, configuration, policy definitions.
- `async def` by default for I/O-bound operations. Sync only for pure computation.
- Imports are absolute, sorted (ruff handles this). No star imports. Ever.
- No ORM magic. If you do not know what query is being generated, you do not own it.
- No God objects. No God files. 300 lines max per file. Justify or split.
- Naming: `snake_case` for functions/variables, `PascalCase` for classes, `SCREAMING_SNAKE` for constants. Be explicit. `validate_policy_input` not `check` or `process`.

---

## SDK Design Principles

The SDK is the product. It must feel like a first-party tool in the developer's stack.

```python
# Minimal integration -- 3 lines to get runtime protection
import vindicara
vc = vindicara.Client(api_key="vnd_...")
result = vc.guard(input="user prompt", output="model response", policy="content-safety")

# Async interface
result = await vc.async_guard(input=prompt, output=response, policy="content-safety")

# Decorator pattern for wrapping existing functions
@vindicara.guard(policy="content-safety")
async def generate_response(prompt: str) -> str:
    return await openai.chat(prompt)

# MCP inspection
risk_report = vc.mcp.scan(server_url="https://mcp.example.com")

# Agent registration
agent = vc.agents.register(
    name="sales-assistant",
    permitted_tools=["crm_read", "email_send"],
    data_scope=["accounts.sales_pipeline"],
    behavioral_limits={"max_actions_per_minute": 60}
)

# Compliance report generation
report = vc.compliance.generate(
    framework="eu-ai-act-article-72",
    system_id="sales-assistant-v2",
    period="2026-Q3"
)
```

- Zero required configuration beyond an API key.
- Sync and async interfaces for every operation.
- Every method returns typed response objects. Never raw dicts.
- SDK errors are typed exceptions with actionable messages: `VindicaraPolicyViolation`, `VindicaraAuthError`, `VindicaraRateLimited`, `VindicaraMCPRiskDetected`, `VindicaraAgentSuspended`.
- SDK footprint stays minimal. No transitive dependency on torch, numpy, or anything heavy.
- The SDK works offline (local policy evaluation) and online (cloud-connected for ML detection and compliance).

---

## FastAPI Patterns

- Every route uses dependency injection for auth, rate limiting, and request validation.
- Response models are explicit Pydantic schemas. No returning raw dicts.
- Background tasks via FastAPI BackgroundTasks or SQS for non-blocking work.
- Health check (`/health`) and readiness (`/ready`) endpoints from day one.
- CORS, security headers, and request ID middleware are non-negotiable.
- OpenAPI schema is the source of truth for API documentation.
- Versioned API paths (`/v1/...`) from the start.

---

## Testing Standards

- Unit tests for business logic. Integration tests for API contracts. E2E tests for critical user paths.
- Tests are not afterthoughts. If the logic is worth writing, it is worth testing.
- Test failure modes, not just happy paths. What happens when the model API is down? When the policy engine times out? When input is 10x expected size? When a malicious actor sends adversarial payloads?
- Use pytest fixtures for shared setup. No test inheritance hierarchies.
- Use `httpx.AsyncClient` with FastAPI's `TestClient` for API testing.
- Mocking via `unittest.mock` or `pytest-mock`. Mocking everything is a test that tests nothing.
- Coverage target: 80%+ on core engine and SDK. 100% on security-critical paths (policy evaluation, MCP inspection, agent authorization).
- Property-based testing (hypothesis) for input validation and policy evaluation edge cases. This is a security product. Edge cases ARE the product.
- Every security-critical function gets adversarial test cases. Think: "How would I break this if I were trying to bypass it?"

---

## Security Architecture

Vindicara is a security product. Its own security posture must be beyond reproach.

- **Assume every input is adversarial.** Prompts, API requests, MCP payloads, webhook data, configuration files. All of it.
- **Defense in depth.** No single point of failure in the security chain. Multiple independent validation layers.
- **Least privilege everywhere.** IAM policies, agent permissions, SDK capabilities. Grant the minimum required and nothing more.
- **Secrets management.** No secrets in code, config files, or environment variables on disk. AWS Secrets Manager or Parameter Store only.
- **Encryption.** TLS 1.3 in transit. AES-256 at rest. Customer data encrypted with per-tenant keys.
- **Audit everything.** Every policy evaluation, every agent action, every configuration change, every access event. Immutable audit logs.
- **Supply chain security.** Pin all dependencies with exact versions. Audit before adding. Every new dependency is attack surface. Run `pip-audit` in CI.
- **No eval(), no exec(), no pickle, no yaml.safe_load() on untrusted input.** This is non-negotiable for a security product.

---

## Performance Targets

- Deterministic policy evaluation: <2ms per check
- ML-based policy evaluation: <50ms per check
- Full guard() pipeline (input + output): <100ms end-to-end
- MCP server scan: <5 seconds per server
- API response time (p99): <200ms
- SDK import time: <100ms (no heavy initialization on import)
- Zero allocation in hot paths where possible

---

## AWS Infrastructure

- Serverless-first: Lambda (Python 3.12), API Gateway, DynamoDB, SQS, EventBridge
- Lambda layers for shared dependencies. Keep deployment packages lean.
- Mangum for FastAPI on Lambda behind API Gateway.
- CDK (Python) for all infrastructure. No manual console changes. Ever.
- Least privilege IAM policies. No wildcard permissions.
- Multi-region readiness in architecture even if single-region initially.
- CloudWatch alarms on every critical path. If it is not monitored, it is not production.
- X-Ray tracing for latency debugging across Lambda invocations.
- DynamoDB single-table design for policy state and agent registry. Optimize for read-heavy access patterns.
- S3 lifecycle policies for audit log tiering (hot -> warm -> cold).
- EventBridge for decoupled event processing (drift alerts, compliance triggers, incident notifications).

---

## Incident Response Posture

- Every production error is assumed to be a symptom of a deeper issue until proven otherwise.
- Fixes include BOTH the immediate resolution AND prevention of recurrence.
- Post-incident, the question is always: "What systemic change prevents this entire class of error?"
- Root cause fixes only. No band-aids. No "let's just restart it." Find the real problem.

---

## Hard Rules (Apply to ALL Code and Content)

1. Never use em dashes in any output. Use commas, semicolons, colons, or separate sentences.
2. Never suggest or recommend Stripe. Square is the payment processor for Vindicara.
3. Never mention Y Combinator or YC. Period.
4. Never mention Emirates Airlines.
5. Root cause fixes only. No band-aids, no workarounds, no "temporary" patches.
6. Security-first in every decision. If there is a tradeoff between convenience and security, security wins.
7. No `Any` types. No bare exceptions. No print(). No eval().
8. Every public API change gets a changelog entry.
9. Every breaking SDK change requires a migration guide.
10. Documentation is not optional. If it is not documented, it does not exist.
