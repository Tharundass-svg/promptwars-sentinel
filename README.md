# ⚔️ PromptWars Sentinel – AI Prompt Security & Battle Arena

[![CI](https://github.com/YOUR_USER/YOUR_REPO/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USER/YOUR_REPO/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Cloud Run Ready](https://img.shields.io/badge/Google%20Cloud-Run%20Ready-blue.svg)](https://cloud.google.com/run)
[![WCAG 2.1 AA](https://img.shields.io/badge/accessibility-WCAG%202.1%20AA-success.svg)]()

> A deterministic, rule-based prompt quality analyzer, red-team scenario simulator, and prompt hardening assistant built for the **PromptWars – AI Prompt Challenge**. It does not call an LLM by default; results are heuristic estimates, not proof that a prompt is secure.

---

## 1. Chosen Challenge Vertical

* **Challenge Vertical**: `PromptWars – AI Prompt Challenge`
* **Assistant Persona**: **PromptWars Sentinel & Optimization Assistant**
  An elite AI cybersecurity and prompt engineering assistant that analyzes prompts, runs simulated adversarial red-team battle rounds (against DAN jailbreaks, system prompt leakage, delimiter collisions, and privilege escalation), dynamically scores resilience based on user context, and refactors vulnerable prompts into production-grade fortified prompts.

---

## 2. Approach and Core Logic

### Architecture Overview
PromptWars Sentinel uses a zero-external-dependency, modular Python architecture with in-memory static assets, gzip + ETag caching and a fully tested HTTP layer:

```
┌─────────────────────────────────────────────────────────────┐
│                       Web Browser UI                        │
│   (Semantic WCAG 2.1 AA HTML5 + Live Announcers + Grid SPA) │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTP REST API (Port 8080)
┌──────────────────────────────▼──────────────────────────────┐
│                    PromptWars Server                         │
│  (Bounded-thread HTTP/1.1, rate limiting, gzip/ETag cache)  │
├──────────────────────────────┬──────────────────────────────┤
│ Core Engine                  │ Functions                    │
├──────────────────────────────┼──────────────────────────────┤
│ 1. `core.security`           │ Regex Threat Signatures, XSS │
│                              │ Sanitization, Guardrails     │
│ 2. `core.analyzer`           │ Clarity, Constraints,        │
│                              │ Context-Weighted Elo Engine  │
│ 3. `core.adversary`          │ 5-Round Battle Arena Suite   │
│                              │ (DAN, Leaks, Sudo, Escapes)  │
│ 4. `core.optimizer`          │ Immutable Identity Lock, XML │
│                              │ Delimiters, Hardened Output  │
└─────────────────────────────────────────────────────────────┘
```

### Context-Aware Scoring Algorithm
The assistant adapts its evaluation weights depending on the active user persona:
* **Application Developer Persona**: Focuses on structural clarity, deterministic schemas, and system privacy (`30% Security`, `25% Clarity`, `30% Robustness`, `15% Efficiency`).
* **Red Team Security Auditor Persona**: Prioritizes attack penetration defense, privilege isolation, and anti-tampering (`50% Security`, `15% Clarity`, `25% Robustness`, `10% Efficiency`).
* **Business / Content Creator Persona**: Maximizes output fidelity, brand guardrails, and hallucination reduction (`20% Security`, `40% Clarity`, `20% Robustness`, `20% Efficiency`).

Calculates a normalized **Sentinel Elo Rating** (800 - 2200 Elo) and tier classification (*Grandmaster Sentinel S+*, *Elite Architect A*, *Combatant Engineer B*, *Vulnerable Novice C-*).

---

## 3. How the Solution Works

1. **Input & Sanitization**: User submits an AI system prompt or instruction via the UI or REST endpoint (`/api/analyze`). Inputs are sanitized against null bytes, oversized payloads, and malicious injection vectors.
2. **Threat Pattern Scanning**: The input is evaluated against threat signatures (`jailbreak_personas`, `system_prompt_leakage`, `delimiter_collision`, `privilege_escalation`, `direct_instruction_override`). Defensive negative assertions are checked within their local clause so an earlier safety rule does not suppress a later attack.
3. **Adversarial Battle Arena (`/api/battle`)**:
   Pits the prompt against 5 specialized adversarial red-team attack rounds:
   * **Round 1**: *Jailbreak Siege (DAN Protocol)*
   * **Round 2**: *System Leak Infiltration*
   * **Round 3**: *Delimiter Collision Assault*
   * **Round 4**: *Privilege Escalation Strike (Sudo / Admin override)*
   * **Round 5**: *Context Poisoning Inversion*
   Computes defense HP (0-100), rounds won, and victory status (*Immune*, *Hardened*, *Vulnerable*, or *Compromised*).
4. **Automated Hardening & Optimization (`/api/optimize`)**:
   Refactors raw prompts into enterprise-grade defense wrappers:
   * Injects immutable identity anchoring.
   * Enforces system prompt privacy rules.
   * Isolates untrusted dynamic user queries inside structured XML boundaries (`<user_input>...</user_input>`).
   * Provides deterministic fallback responses when adversarial payloads are detected.

---

## 4. Detection Limits and Responsible Use

- The scanner uses normalized regular-expression signatures and local-clause negation handling. It can produce false positives and false negatives, especially for novel, multilingual, encoded, or context-dependent attacks.
- The battle arena is a **deterministic simulation**: it checks for defensive prompt features against a fixed five-attack suite. It does not execute attacks against a real language model and must not be presented as a penetration-test result.
- The analyzer's clarity, robustness, efficiency, and Elo-like values are explainable heuristic scores, not empirically calibrated model-performance measurements.
- XML tags and other delimiters help organize untrusted content; they are not security boundaries. Enforce authorization, tool permissions, data isolation, and output validation in the application runtime.
- No claim of immunity or production security is made. Validate changes against the actual model, tools, data sources, and threat model before deployment.

## 5. Assumptions Made

1. **Zero External Dependency Guarantee**: To ensure judges and evaluation sandboxes can run the project without dependency resolution or network timeout errors, the backend relies strictly on the Python standard library.
2. **Small Footprint**: Source, assets, tests and docs are kept deliberately small to stay well within the hackathon's repository size limit.
3. **Cloud Run Native**: Built to read `PORT` from the environment (defaulting to 8080) with a non-root Linux container user conforming to Google Cloud Run standards.
4. **Deterministic Heuristics + Extensibility**: Evaluates prompt safety and quality deterministically through heuristic rule engines and syntactic parsing, with an architectural interface ready to connect to live LLM APIs (Gemini/OpenAI) when API keys are supplied.

---

## 6. Evaluation Focus Areas Alignment

| Focus Area | Implementation Detail |
|---|---|
| **Code Quality** | Modular design (`core/`, `tests/`, `static/`, `server.py`), route-table dispatch, `logging` module, constants instead of magic values, type hints and docstrings. Linted with `ruff` and checked in GitHub Actions CI. |
| **Security** | Input sanitization and strict schema validation (type, length, persona format), 64 KB body cap, per-IP token-bucket rate limiting, no filesystem lookups for static paths (assets are preloaded, so traversal is impossible), generic 500s with no stack traces, same-origin CORS by default (`ALLOWED_ORIGIN` to opt in), and `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP headers. Container runs as a non-root user. |
| **Efficiency** | Static assets preloaded once into memory with precomputed gzip and ETag (304 support), on-the-fly gzip for JSON, HTTP/1.1 keep-alive, bounded worker threads, zero external dependencies. |
| **Testing** | Automated unit tests for the core engines plus HTTP integration tests (routing, validation, size limits, rate limiting, gzip/ETag, path traversal, error handling) that run against a real server on an ephemeral port. Run in CI on Python 3.9, 3.11 and 3.12. |
| **Accessibility** | WCAG 2.1 AA compliant semantic HTML5, high-contrast dark theme, ARIA attributes (`aria-live`, `aria-label`, `role="status"`), full keyboard navigation. |
| **Alignment** | Directly built for the **PromptWars – AI Prompt Challenge** vertical with interactive prompt duel arena, Elo ratings, and dynamic hardening. |

---

## 6. Setup & Running Locally

### Prerequisites
* Python 3.9+ (or Node.js / Docker)

### Run with 1 Command:
```bash
python server.py
```
Open **`http://localhost:8080`** in your browser.

### Configuration (optional environment variables)
`PORT` (8080), `LOG_LEVEL` (INFO), `ALLOWED_ORIGIN` (unset = same-origin only), `RATE_LIMIT_PER_SEC` (5), `RATE_LIMIT_BURST` (20), `MAX_THREADS` (64).

### Run Automated Tests:
```bash
python -m unittest discover tests
```
Tests also run automatically on every push via GitHub Actions.

---

## 7. Deployment to Google Cloud Run

### Option A: 1-Click CLI Deployment (Recommended)
```bash
# Authenticate and configure project
gcloud auth login
gcloud config set project YOUR_PROJECT_ID

# Deploy directly from source to Cloud Run
gcloud run deploy promptwars-sentinel \
  --source . \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated
```

### Option B: Deploy via Docker
```bash
docker build -t promptwars-sentinel .
docker run -p 8080:8080 promptwars-sentinel
```

### Option C: Instant Free Cloud Hosting (Render / Railway / Vercel)
* **Render**: Connect your GitHub repository, choose **Web Service**, runtime **Python**, start command `python server.py`.
* **Railway**: Connect GitHub repo; it will automatically detect the Dockerfile and deploy.

---

## 8. License
MIT License. Built for the PromptWars AI Hackathon Challenge.
