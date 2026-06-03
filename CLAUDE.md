# CLAUDE.md

Project AIR by Vindicara: forensic accountability SDK for AI agents. MIT CLI (`air`) + library (`airsdk`) on PyPI as `projectair`. Five-layer architecture: detection, anchoring, causal reasoning, containment, cross-agent trust, data governance.

## Brand hierarchy

- Company: Vindicara
- Flagship initiative (external-facing): Project AIR
- Product tiers (developer-facing): AIR SDK, AIR Cloud, AIR Enterprise
- Technical artifacts: `air`, `airsdk`, `vindicara`

Use "Project AIR" on hero pages, pitch decks, whitepapers, legal, press, investor materials. Use "AIR" in code, docs, CLI, and technical copy.

## Current state

- `projectair` **1.0.0** on PyPI (2026-05-18). **1.0.1 in-flight** (relaxed `cryptography` dep, conditional ML-DSA imports, `betterproto`).
- `vindicara` 0.2.0 live (server-side engine behind AIR Cloud).
- AgDR schema **v0.6**. "Signed Intent Capsule" is the public-facing term for AgDR records.
- Working venv: `.venv-air/` (Python 3.13).

## Claims discipline (enforced on every response)

- Detector count: **"10 OWASP Agentic + 3 OWASP LLM + 3 AIR-native = 16 total."** Never "14" or "8 of 10."
- ASI10 is **declared-scope Zero-Trust enforcement**, NOT anomaly detection. Learned-baseline variant is roadmap, not shipped.
- AIR-04 (chain-integrity gap) is NOT ASI10 coverage. Do not conflate.
- Every public claim must be grounded in an actual source document, not plausible-sounding generalization.
- HF0 pitch + Hacker News launch imminent. Diligence sensitivity is high.

## Repo map

- `packages/projectair/` -- public MIT package (`air` CLI + `airsdk` library). The product.
- `packages/projectair-pro/` -- commercial tier (`airsdk_pro`). SIEM, governance, premium detectors/reports. Not on PyPI.
- `packages/air-dashboard/` -- AIR Cloud dashboard (SvelteKit 2, Svelte 5, Tailwind 4, Three.js, Vitest).
- `site/` -- marketing site (SvelteKit 2, Svelte 5, Tailwind 4). Day/night theme; day palette is peachy lilac (`#f0e6ef`).
- `src/vindicara/` -- Apache-2.0 engine substrate.
- `tests/` -- pytest for `src/vindicara/`. Separate from `packages/projectair/tests/`.
- Pitch the split as **Snyk-style: MIT CLI + SDK top-of-funnel, commercial pro tier + engine behind the cloud**.
- When the user says "the dashboard," confirm which one (air-dashboard vs site vs legacy `src/vindicara/dashboard/`).

## Commands

```bash
# Install
pip install -e ".[api,dev]"
pip install -e "packages/projectair[dev]"

# Test (projectair)
pytest packages/projectair/tests
air demo

# Test (engine, 80% coverage floor)
./scripts/test.sh

# Lint + type check (src/vindicara + tests/ only)
./scripts/lint.sh

# Common pytest
pytest tests/unit/engine/test_policy.py
pytest -k "guard and not adversarial"
pytest -m adversarial

# FastAPI local
uvicorn vindicara.api.app:create_app --factory --reload

# CDK
./scripts/build-lambda.sh
VINDICARA_AWS_ACCOUNT_ID=... cdk synth
VINDICARA_AWS_ACCOUNT_ID=... cdk deploy VindicaraData VindicaraEvents VindicaraAPI

# Marketing site
cd site && npm install && npm run dev
cd site && npm run check    # lint bar; failures block deploy
cd site && npm run build

# AIR Cloud dashboard
cd packages/air-dashboard && npm install
cd packages/air-dashboard && npm run ci   # check + test + build + bundle:check

# Publish (always cd packages/projectair first)
rm -f dist/*.whl dist/*.tar.gz && python -m build && python -m twine check dist/* && python -m twine upload dist/projectair-<ver>*
```

Site deploy: auto on push to `main` when `site/**` changes via `.github/workflows/deploy-site.yml`. Manual: `scripts/deploy-site.sh`.

CI: `ci-projectair.yml` (ruff + pytest, Python 3.12/3.13) gates the OSS package. `deploy-site.yml` auto-deploys the site.

E2E demos (after `pip install -e "packages/projectair[dev]"`):

```bash
python packages/projectair/scripts/e2e_layer1.py [--live-tsa --live-rekor]
python packages/projectair/scripts/e2e_layer3.py
python packages/projectair/scripts/e2e_layer4.py [--live-rekor]
```

## Hard rules

- Never use em dashes in any output. Use commas, semicolons, colons, or separate sentences.
- Never mention Emirates Airlines.
- No `Any` types, no bare `except`, no `print` in production paths. `mypy --strict` is the bar.
- No dynamic code evaluation (`eval`, `exec`, `pickle`, unsafe YAML) on untrusted input.
- 300 lines max per file. If you need "and" to describe a function, split it.
- Root cause fixes only. No band-aids, no "temporary" patches.

## Quality gates (every roadmap item)

1. **End-to-End Proof** -- runnable demo under 60 seconds.
2. **Test Coverage Proof** -- 80% floor enforced by `./scripts/test.sh`.
3. **Deployment / Readiness Boundary** -- `experimental` / `beta` / `production` label.
4. **Customer-Facing Value** -- one-sentence customer-language description before engineering starts.

## Context

**AWS account migration in flight.** SLTR `335741630084` (us-east-1) to Vindicara C-Corp `399827112476` (us-west-2). Three hardcoded locations: `data_stack.py`, `deploy-site.sh`, GitHub Actions workflow. See `MIGRATION_PLAN.md` and `project_aws_migration.md` in memory.

## Detailed docs (read when working in the relevant area)

- `docs/DETECTORS.md` -- full detector taxonomy (ASI01-10, AIR-01..06, NemoGuard, framing discipline, AIR-04 vs ASI10). Read before editing detectors or public copy.
- `docs/ARCHITECTURE.md` -- layered spine (Layers 0-5), crypto trust contracts, PyPI release details, framework integrations, ops chain, detailed code location, architecture cross-cutting notes, roadmap. Read before adding layers, integrations, or navigating unfamiliar modules.
- `docs/STANDARDS.md` -- engineering standards, SDK design, FastAPI patterns, testing, security architecture, performance targets, AWS infra, quality gates.
- `docs/SPEC.md` -- product vision, competitive landscape, pricing, GTM, fundraise context. Read for product decisions or external content.

Memory: `/Users/KMiI/.claude/projects/-Users-KMiI-Desktop-vindicara/memory/MEMORY.md`.
