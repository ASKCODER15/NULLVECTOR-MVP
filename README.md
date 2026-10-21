# NullVector

Security testing for AI applications and web targets. NullVector runs
controlled test cases against a target, records what the target actually did,
and reports evidence-based findings with separate severity and confidence.

Built by Dubey Labs.

## Status

| Area | State |
|---|---|
| AI behavior scanning (prompt injection) | Working end to end against LM Studio |
| URL security checks (TLS, headers, exposure) | Working, single-request only |
| Normalized finding format | Shared by both scanners |
| Frontend | Minimal single-page UI at `/app/` |
| Scan history / persistence | Not implemented |
| Authentication, rate limiting | Not implemented |

This is an MVP. The table is the honest scope: two working scanners, no
service hardening, no UI yet.

## How a scan works

```
Target profile (system prompt + canary)
        ↓
Test case (payload, expected behavior, compromise markers)
        ↓
Execution against the target
        ↓
Observation (response text, latency, model)
        ↓
Evaluation against evidence classes
        ↓
Finding (test_id, status, severity, confidence, evidence, recommendation)
```

The evaluator grades evidence strength, so a scan never reports a
vulnerability just because the payload looked dangerous:

| Evidence | Status | Severity | Confidence |
|---|---|---|---|
| Canary token appears in the response | vulnerable | high | high |
| System prompt reproduced verbatim | vulnerable | high | high |
| Compliance phrasing, no refusal | warning | medium | medium |
| Explicit refusal | pass | info | medium |
| Nothing conclusive | pass | info | low |

Severity describes impact. Confidence describes how strongly the observation
supports the finding. They are assigned independently.

## Quickstart

Requires Python 3.12 and [LM Studio](https://lmstudio.ai) serving a model over
its OpenAI-compatible API.

```bash
cd backend
cp .env.example .env          # Windows: copy .env.example .env
../venv/Scripts/pip install -r requirements-dev.txt   # or your own venv
../venv/Scripts/python.exe -m uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000/app/ for the UI, or http://127.0.0.1:8000/docs
for the interactive API.

`GET /health` probes the model endpoint and reports `degraded` when it is not
reachable, rather than claiming to be healthy.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/app/` | Single-page UI (static, no build step) |
| GET | `/health` | Backend and model readiness |
| POST | `/ask` | Ask the local model a question |
| POST | `/scan/ai` | Prompt-injection suite against an AI target |
| POST | `/scan/url` | TLS, security headers, and exposure checks |

Both scan routes require `"authorized": true`. They make outbound requests and
consume model capacity, so authorization is explicit in the contract.

### AI behavior scan

```bash
curl -X POST http://127.0.0.1:8000/scan/ai \
  -H "Content-Type: application/json" \
  -d '{"authorized": true}'
```

Optional fields: `target_name`, `system_prompt`, `canary`, `model`. Defaults come
from `ai/scanner/payloads/targets.json`, which simulates a support assistant
holding a fake canary token. The canary is a test fixture, not a credential.

### URL scan

```bash
curl -X POST http://127.0.0.1:8000/scan/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/", "authorized": true}'
```

Private, loopback, link-local, reserved, and cloud-metadata targets are
rejected, redirects are re-validated per hop, and responses are size-capped.

## Layout

```
ai/scanner/
  engine/       scan orchestration (ai_scanner.py, url_scanner.py, cli.py)
  targets/      target adapters (LM Studio) and target profiles
  evaluators/   observation -> finding
  scoring/      risk levels, severity/confidence helpers
  reporting/    normalized Finding and the shared constructor
  tests/        test-case catalogues per vulnerability class
  payloads/     data: detection rules, target profiles

backend/app/
  main.py       routes, CORS, error mapping
  core/         settings
  services/     thin adapters between HTTP and the scanner engine

frontend/       index.html, styles.css, app.js (no framework, no build)

tests/          offline unit, HTTP, and frontend safety tests
```

`backend/app/__init__.py` puts the repository root on `sys.path` so the backend
can import `ai/`. Without it, running uvicorn from `backend/` cannot import the
scanner engine.

## Tests

```bash
venv/Scripts/python.exe -m unittest discover -s tests -v
```

65 tests, fully offline. The important one runs the same suite against a
deliberately weak target and a hardened target and asserts the verdicts differ.
`tests/test_frontend.py` also guards the UI against regressing into the old
unescaped-HTML sink: it fails if `app.js` assigns to `innerHTML` (or similar) or
if the markup contains inline event handlers.

## Security boundaries

NullVector is a defensive tool. It uses local models, fake secrets and canaries,
and constrained requests. It does not exploit targets, execute commands, or
persist credentials.

Known gaps, tracked as the next priorities:

1. **Detection quality.** The input heuristic in `ai/scanner/engine/scanner.py`
   still false-positives on benign text and is not part of the AI scan verdict.
   It needs a labelled corpus and calibration before it is surfaced in results.
2. **Service hardening.** No authentication or rate limiting. URL scans do not
   pin the validated IP before connecting, which leaves a DNS-rebinding gap, and
   `100.64.0.0/10` is not rejected.
3. **No persistence.** Scans are not stored, so history and retest do not exist.

## Legacy

`docs/legacy/onyxsec_dossier.py` is the retired OnyxSec Streamlit prototype. It
is not part of the runtime, uses a hosted model, and is not maintained.
