# NULLVECTOR — PROJECT CONTEXT & ENGINEERING INSTRUCTIONS

> This is the living idea document for NullVector. It is updated whenever the
> product concept, architecture, or engineering structure changes. Keep it in
> sync with the codebase.

You are working on NullVector, an AI security platform being developed by Dubey Labs.

## 1. What NullVector is

NullVector is an AI security testing and protection platform.

The goal is to help developers and organizations test AI/LLM applications for security vulnerabilities before those vulnerabilities become real problems.

NullVector should eventually be able to:

- test AI applications against known AI security attack patterns
- detect vulnerabilities
- execute controlled security test cases
- evaluate model/application behavior
- collect evidence
- assign severity and confidence
- generate clear security findings
- provide remediation recommendations
- maintain scan history
- eventually support agentic AI security testing

NullVector is NOT simply a chatbot.

It is intended to become an AI security testing/assessment engine.

## 2. Current project architecture

Current development architecture:

Frontend
    ↓
FastAPI Backend
    ↓
Security Scanner Engine
    ↓
Local LLM / LM Studio
    ↓
Qwen3-8B

Development agents such as OpenCode are development tools only.

They are NOT part of the NullVector runtime architecture.

Current local development environment:

Project:
C:\AI\Projects\NullVector

Backend:
C:\AI\Projects\NullVector\backend

Frontend:
C:\AI\Projects\NullVector\frontend

Python virtual environment:
C:\AI\Projects\NullVector\venv

Backend:
http://127.0.0.1:8000

LM Studio:
http://127.0.0.1:1234

Current local model:
qwen/qwen3-8b

GitHub repository:
ASKCODER15/NULLVECTOR-MVP

Default branch:
main

## 3. Existing product functionality

The backend is built using FastAPI.

Current important endpoints include:

GET /health
POST /ask
POST /scan

The frontend contains the main product areas:

- Dashboard
- Scanner
- Assistant
- History
- Settings

The frontend communicates with the FastAPI backend.

The backend communicates with the local LLM through LM Studio.

CORS has already been configured so the frontend can communicate with the backend.

Do NOT unnecessarily rewrite working architecture.

Preserve existing functionality unless a change is required.

## 4. Main security vision

NullVector will eventually cover multiple AI security categories.

The initial Tier 1 priorities are:

1. Prompt Injection
2. Sensitive Information Disclosure
3. System Prompt Leakage

Later stages can include:

4. Improper Output Handling
5. Unbounded Consumption
6. Agent Goal Hijacking
7. Tool Misuse / Exploitation
8. Excessive Agency
9. Identity and Privilege Abuse
10. Memory / Context Poisoning

Do not attempt to implement all categories at once.

Build the scanner as a modular security testing framework so new vulnerability classes can be added without rewriting the entire scanner.

## 5. Scanner philosophy

The scanner must NOT simply send a prompt to a model and guess whether it is vulnerable.

A scanner is a controlled security experiment.

Conceptually:

Target
  ↓
Test Selection
  ↓
Test Case
  ↓
Execution
  ↓
Observation
  ↓
Evaluation
  ↓
Evidence
  ↓
Severity + Confidence
  ↓
Finding
  ↓
Report

Every test should answer:

- What vulnerability are we testing?
- What attack/test case was used?
- What behavior was expected?
- What behavior actually happened?
- What evidence supports the finding?
- How severe is the issue?
- How confident are we?
- How should the developer fix it?

## 6. Normalized security finding format

Use a consistent internal finding structure.

Example:

{
  "test_id": "PI-001",
  "category": "Prompt Injection",
  "status": "vulnerable",
  "severity": "high",
  "confidence": "high",
  "summary": "The application followed attacker-controlled instructions that conflicted with the intended system behavior.",
  "evidence": "...",
  "recommendation": "...",
  "timestamp": "..."
}

Severity and confidence are DIFFERENT.

Severity = how dangerous the vulnerability could be.

Confidence = how certain we are that the test actually demonstrated the vulnerability.

An attack attempt does NOT automatically mean the target is vulnerable.

## 7. First scanner implementation

The immediate engineering goal is:

Scanner Engine
    ↓
Prompt Injection Test
    ↓
Test Cases
    ↓
Target/Model Execution
    ↓
Response
    ↓
Evaluator
    ↓
Normalized Finding

Build Prompt Injection first.

Do not add every vulnerability category before the first scanner flow works end-to-end.

The scanner should eventually have a structure similar to (currently rooted at `ai/`):

ai/
    scanner/
        engine/                # test execution entry points (scan, CLI)
        tests/                 # vulnerability test-case catalogues
            prompt_injection/
        payloads/              # attack signatures / payload data
        evaluators/            # turn observations into findings
        scoring/               # risk level, severity, confidence
        reporting/             # normalized security findings

The backend (`backend/`) imports the scanner engine from `ai/`. Keep the exact
folder structure modular so every category can be added without rewriting the
whole scanner.

## 8. Prompt Injection testing

Prompt Injection testing should use controlled security test cases.

A test case should have information such as:

- test ID
- vulnerability category
- attack prompt
- expected safe behavior
- evaluation criteria

Example concept:

{
  "test_id": "PI-001",
  "category": "Prompt Injection",
  "payload": "...",
  "expected_behavior": "...",
  "evaluation": "..."
}

The evaluator should inspect the target response and determine whether the application's intended instructions were bypassed or manipulated.

Do not mark something vulnerable merely because the model responded strangely.

Use evidence-based evaluation.

## 9. Security boundaries

NullVector is a defensive security product.

All security testing should be controlled and safe.

Use:
- local models
- sandbox environments
- fake secrets/canary values
- mock tools
- test credentials
- controlled targets

Never introduce real credentials, destructive commands, unauthorized external actions, or real-world attack infrastructure into the project.

Agent/tool security testing should eventually happen inside a sandbox.

## 10. Engineering principles

You are acting as a senior software engineer helping develop this project.

Before modifying files:

1. Inspect the existing repository.
2. Understand the current architecture.
3. Find existing implementations before creating duplicates.
4. Make the smallest clean change that solves the problem.
5. Preserve working functionality.
6. Keep frontend, backend, scanner, and model responsibilities separated.
7. Avoid unnecessary dependencies.
8. Prefer clear, maintainable code over clever code.
9. Add error handling.
10. Add tests for important scanner behavior.
11. Never silently break an existing endpoint.
12. Do not rewrite the entire project when a targeted change is sufficient.

When changing architecture, explain WHY the change is necessary.

## 11. Error handling

The scanner should eventually handle:

- empty input
- invalid input
- very long input
- backend unavailable
- model unavailable
- timeout
- malformed model response
- invalid JSON
- HTTP 4xx/5xx
- unexpected evaluator failures

Errors should be presented clearly to the user and should not crash the application.

## 12. Development workflow

For every significant change:

Inspect
→ Plan
→ Implement
→ Test
→ Review
→ Report

After modifying code:

- tell me which files changed
- explain what changed
- explain why
- tell me how it was tested
- mention anything still unfinished

Do not claim something works unless it was actually tested.

## 13. Git discipline

The GitHub repository is:

ASKCODER15/NULLVECTOR-MVP

Do not perform destructive Git operations without explicit approval.

Do not delete working functionality simply to simplify the code.

Keep commits logically organized when commits are requested.

## 14. Product identity

Product:
NullVector

Company:
Dubey Labs

Never use the old product name OnyxSec in new user-facing UI, documentation, variable names, comments, or branding unless referring specifically to historical migration context.

## 15. Long-term vision

NullVector should evolve from a simple scanner into a serious AI security platform.

Long-term architecture may include:

AI application scanning
    ↓
Security test orchestration
    ↓
Multiple vulnerability modules
    ↓
LLM/Agent behavioral evaluation
    ↓
Evidence engine
    ↓
Risk scoring
    ↓
Security reports
    ↓
Remediation guidance

Later capabilities may include:

- RAG security testing
- memory poisoning testing
- agent security
- tool-use security
- privilege/identity testing
- automated regression security tests
- scan history
- project/workspace management
- API access
- CI/CD security testing
- security dashboards
- multi-model testing
- deployment/cloud integrations

Do not build all of this now.

Build the core correctly first.

## 16. Current priority

CURRENT PRIORITY:

Make the Prompt Injection scanner work end-to-end.

The desired flow is:

User enters target/input
→ frontend sends request
→ FastAPI receives request
→ scanner selects Prompt Injection test
→ test executes
→ model/target responds
→ evaluator analyzes response
→ normalized security finding is generated
→ frontend displays the finding

After this is reliable, move to:

Sensitive Information Disclosure

then:

System Prompt Leakage

Only then expand the scanner framework further.