# VerifyFirst — Development Roadmap

## Roadmap Principles

This roadmap follows the project's core development principle:

> Build the smallest correct system first, then improve it based on actual requirements.

Each phase must be completed and verified before moving to the next.

Do not implement a later phase unless explicitly requested.

---

## Phase 0 — Project Foundation

**Goal:** Establish the development environment and project skeleton.

Deliverables:

* Project directory structure (extension, backend)
* Chrome extension manifest (Manifest V3)
* Backend application skeleton
* Development environment configuration
* Git initialization and `.gitignore`
* Basic `README.md`

**Exit criteria:** The extension loads in Chrome without errors. The backend starts and responds to a health check.

---

## Phase 1 — Backend MVP

**Goal:** Build a working API that accepts a URL and returns a basic risk assessment.

Deliverables:

* `POST /api/v1/analyze` endpoint
* URL input validation
* Basic rule-based URL analysis
* Standardized API response format
* Error handling
* Basic rate limiting
* CORS configuration

**Exit criteria:** The API accepts a URL, runs basic analysis, and returns a valid risk assessment. Invalid input is rejected with appropriate error responses.

---

## Phase 2 — Extension MVP

**Goal:** Build a working Chrome extension that sends URLs to the backend and displays results.

Deliverables:

* Popup UI with branding, domain display, risk classification, and risk score
* Background service worker for API communication
* API integration with the backend
* Loading state
* Error state handling (backend unavailable, timeout, invalid URL)
* Environment-based API URL configuration

**Exit criteria:** The extension obtains the current tab URL, sends it to the backend, and displays SAFE / SUSPICIOUS / DANGEROUS with a short explanation.

---

## Phase 3 — Detection Rules

**Goal:** Build a meaningful rule-based detection engine.

Deliverables:

* URL feature extraction (length, depth, special characters, IP usage, etc.)
* Multiple detection rules with individual scoring
* Score aggregation and threshold-based classification
* Detection reason generation
* Central threshold configuration
* Unit tests for detection rules

**Exit criteria:** The system correctly identifies known-suspicious URL patterns and produces explainable risk assessments.

---

## Phase 4 — Details Page

**Goal:** Provide users with a detailed analysis view.

Deliverables:

* Details page UI accessible from the popup
* Display of individual detection indicators
* Display of risk score breakdown
* Display of detection reasons
* Clean, non-technical presentation

**Exit criteria:** Users can view detailed analysis results that explain why a URL was classified as it was.

---

## Phase 5 — Polish and Testing

**Goal:** Harden the system for demonstration readiness.

Deliverables:

* End-to-end testing of the full flow
* Edge case handling (unusual URLs, empty tabs, `chrome://` pages)
* UI polish and responsive design
* Error message improvements
* Performance review
* Security review against `04_SECURITY_RULES.md`
* Documentation updates

**Exit criteria:** The system handles all common cases gracefully and is ready for demonstration.

---

## Phase 6 — Machine Learning (Optional)

**Goal:** Add ML-based detection to complement rule-based analysis.

**Prerequisites:** Phases 0–5 must be complete and stable.

Deliverables:

* Feature extraction pipeline
* Trained phishing-detection model
* Model integration into the detection engine
* Score aggregation between rules and ML
* ML performance evaluation against rule-only baseline

**Exit criteria:** ML predictions measurably improve detection accuracy compared to rules alone.

**Note:** Do not implement this phase unless the rule-based system is working and the ML improvement can be demonstrated.

---

## Phase 7 — Reputation Integration (Optional)

**Goal:** Integrate external reputation or threat-intelligence data.

**Prerequisites:** Phases 0–5 must be complete and stable.

Deliverables:

* Reputation provider integration
* Fallback handling when the external service is unavailable
* Score aggregation with reputation data
* API key/credential management for external services

**Exit criteria:** Reputation data provides additional detection value without making the system dependent on external availability.

**Note:** Do not make the core detection engine dependent on an external service.

---

## Phase 8 — Page Warning (Optional)

**Goal:** Display a lightweight warning on high-risk webpages.

**Prerequisites:** The core extension flow (Phases 0–5) must be stable.

Deliverables:

* Content script for page-warning injection
* Non-intrusive warning UI
* Trigger logic based on risk classification
* User dismissal handling

**Exit criteria:** High-risk pages display a visible but non-blocking warning to the user.

**Note:** This phase introduces content scripts and additional extension permissions. Do not implement until justified.

---

## Phase Ordering Rules

1. Phases are sequential. Complete the current phase before starting the next.
2. Phases 0–5 constitute the core project.
3. Phases 6–8 are optional enhancements.
4. Do not skip phases.
5. Do not combine multiple phases into a single implementation step.
6. Each phase should be independently demonstrable.
7. If a phase reveals problems in an earlier phase, fix the earlier phase first.
