# VerifyFirst — System Architecture

## 1. Architecture Goal

VerifyFirst should use a simple client-server architecture.

The Chrome extension acts as the client, while the backend provides the analysis API and coordinates the detection engine.

The architecture must remain lightweight and modular without introducing unnecessary services.

---

## 2. High-Level Architecture

```text
                         USER
                          │
                          ▼
                  ┌───────────────┐
                  │ Chrome Browser│
                  └───────┬───────┘
                          │
                          ▼
                ┌───────────────────┐
                │ VerifyFirst       │
                │ Chrome Extension  │
                └─────────┬─────────┘
                          │
                     HTTPS / REST
                          │
                          ▼
                ┌───────────────────┐
                │ VerifyFirst API   │
                │ Backend           │
                └─────────┬─────────┘
                          │
                          ▼
                ┌───────────────────┐
                │ Detection Engine  │
                ├───────────────────┤
                │ URL Analysis      │
                │ Security Rules    │
                │ ML Analysis       │
                │ Reputation        │
                └─────────┬─────────┘
                          │
                          ▼
                ┌───────────────────┐
                │ Analysis Result   │
                └─────────┬─────────┘
                          │
                          ▼
                Chrome Extension UI
```

---

## 3. Component Responsibilities

### 3.1 Chrome Extension

The extension is responsible for the user-facing browser experience.

The extension uses Chrome Manifest V3.

Responsibilities:

* Obtain the current tab URL.
* Request website analysis.
* Display analysis status.
* Display SAFE, SUSPICIOUS, or DANGEROUS results.
* Display a concise explanation.
* Provide access to detailed analysis.
* Display appropriate error states.
* Optionally display high-risk page warnings.

The extension should not contain the primary security-detection logic.

---

### 3.2 Backend API

The backend is the communication and orchestration layer.

Responsibilities:

* Receive requests from the extension.
* Validate incoming data.
* Authenticate requests if authentication is introduced.
* Call the detection engine.
* Normalize detection results.
* Return a stable API response.
* Apply rate limiting and other API security controls.
* Handle errors safely.

The backend should not duplicate detection logic that belongs in the detection engine.

---

### 3.3 Detection Engine

The detection engine contains the actual website-analysis logic.

Responsibilities:

* Parse URLs.
* Extract security-relevant features.
* Apply deterministic security rules.
* Run ML inference when enabled.
* Perform reputation checks when enabled.
* Calculate the final risk assessment.
* Generate meaningful detection reasons.

The detection engine should be usable independently from the Chrome extension.

---

### 3.4 Database

A database is optional during the initial implementation.

If introduced, it should be responsible for persistent information such as:

* Analysis history
* User preferences
* Feedback
* Detection records

The database must not become part of every request unless persistence is actually required.

---

## 4. Request Flow

### Standard analysis

```text
1. User visits a website
        ↓
2. Extension obtains current URL
        ↓
3. Extension sends API request
        ↓
4. Backend validates request
        ↓
5. Backend calls Detection Engine
        ↓
6. Detection Engine analyzes URL
        ↓
7. Detection Engine returns result
        ↓
8. Backend returns standardized response
        ↓
9. Extension displays result
```

---

## 5. API Boundary

The extension communicates with the backend through a REST API.

Initial endpoint:

```text
POST /api/v1/analyze
```

Example request:

```json
{
  "url": "https://example.com"
}
```

Example response:

```json
{
  "status": "SUSPICIOUS",
  "risk_score": 72,
  "confidence": 87,
  "reasons": [
    "Suspicious URL structure",
    "Unusual domain characteristics"
  ]
}
```

The exact response schema should be finalized during the API implementation phase.

---

## 6. Detection Pipeline

The detection engine should follow a predictable pipeline.

```text
URL
 │
 ▼
Input Validation
 │
 ▼
URL Parsing
 │
 ▼
Feature Extraction
 │
 ▼
Rule Analysis
 │
 ├──────────────┐
 ▼              ▼
ML Analysis   Reputation
 │              │
 └───────┬──────┘
         ▼
   Result Aggregation
         │
         ▼
    Risk Assessment
         │
         ▼
      Response
```

Not every stage must execute for every request.

The implementation should avoid expensive processing when it provides no additional value.

---

## 7. Rule Engine

Rules should be responsible for identifying known suspicious characteristics.

Examples may include:

* IP address used instead of a domain.
* Excessive URL length.
* Suspicious URL patterns.
* Suspicious keywords.
* Unusual subdomain structure.
* Abnormal use of special characters.
* Other validated phishing indicators.

Rules should be:

* Easy to understand.
* Testable.
* Independently maintainable.
* Configurable where appropriate.

Rules must not be randomly added without evidence or justification.

---

## 8. Machine Learning Layer (Later Phase)

The ML layer is optional and should not be implemented until the baseline rule-based detection system is complete, tested, and stable.

This corresponds to Phase 6 of the development roadmap.

If ML is used:

```text
URL
 ↓
Feature Extraction
 ↓
Feature Vector
 ↓
ML Model
 ↓
Prediction + Confidence
```

The model should remain on the backend.

The Chrome extension should receive only the required result.

The model implementation should be replaceable without changing the extension API unnecessarily.

---

## 9. Reputation Layer (Later Phase)

External reputation or threat-intelligence services may be introduced in a later phase after the core detection system is stable.

This corresponds to Phase 7 of the development roadmap.

Architecture:

```text
Detection Engine
      │
      ├── Local Rules
      ├── ML
      └── Reputation Provider
```

External services must not become mandatory dependencies unless their value justifies:

* Network latency
* API limits
* Availability risks
* Credential management
* Operational complexity

---

## 10. Frontend Architecture

The Chrome extension uses Manifest V3 and should have three primary UI surfaces.

### Popup

Purpose:

Provide the immediate security decision.

```text
VerifyFirst
────────────────
example.com

🟢 SAFE

Risk: Low

No significant
threat indicators.

[ View Details ]
```

### Details Page

Purpose:

Provide deeper analysis.

```text
Website
example.com

Risk Assessment
🟡 SUSPICIOUS

Risk Score
72 / 100

Indicators
✓ HTTPS
⚠ URL Structure
⚠ Domain Pattern
✓ Certificate
```

### Page Warning

Purpose:

Warn users about high-risk websites.

This is optional and should be implemented only after the basic extension is stable.

---

## 11. Extension-to-Backend Communication

Development:

```text
Chrome Extension
       │
       ▼
localhost backend
       │
       ▼
Local Detection Engine
```

Production:

```text
Chrome Extension
       │
       ▼
HTTPS
       │
       ▼
Deployed Backend
       │
       ▼
Detection Engine
```

The extension must never depend on the developer's personal computer in production.

---

## 12. Environment Configuration

Environment-specific configuration must be separated.

Example:

```text
Development
API_BASE_URL=http://localhost:8000

Production
API_BASE_URL=https://api.example.com
```

Production secrets must never be embedded into the extension.

---

## 13. Project Structure

The initial project should remain simple.

```text
VerifyFirst/
│
├── extension/
│   ├── manifest.json
│   ├── background/
│   ├── popup/
│   ├── details/
│   └── assets/
│
├── backend/
│   ├── api/
│   ├── detection/
│   │   ├── rules/
│   │   ├── features/
│   │   └── engine/
│   ├── config/
│   └── main.py
│
├── tests/
│
└── docs/
```

The detection engine is a module inside the backend, not a separate application.

The extension does not include a `content/` directory until the page-warning feature (Phase 8) is implemented.

The exact internal structure may change if implementation evidence shows a simpler structure is better.

Do not create empty folders or placeholder abstractions without a current requirement.

---

## 14. Monolith vs Microservices

The initial system uses a modular monolithic backend.

```text
Backend
├── API
├── Detection
│   ├── Rules
│   ├── Features
│   └── Engine
└── Config
```

The detection engine runs as part of the backend application, not as a separate service.

Do not introduce microservices unless there is a demonstrated technical requirement.

---

## 15. Data Flow Principle

The extension should send only the information required for analysis.

Preferred:

```text
{
  "url": "https://example.com"
}
```

Avoid sending unnecessary browsing information, page content, cookies, credentials, or unrelated user data.

Privacy should be treated as an architectural requirement.

---

## 16. Error Handling

The extension must handle:

```text
Backend unavailable
        ↓
"Unable to analyze this website."
```

Other cases:

```text
Invalid URL
API timeout
Rate limit
Server error
Analysis unavailable
Unsupported URL
```

The extension must never expose raw backend errors or stack traces to users.

---

## 17. Performance Principles

The architecture should minimize:

* Network requests
* Duplicate analysis
* Heavy browser-side processing
* Large extension bundles
* Unnecessary external API calls

Caching may be introduced when measurements demonstrate that it improves performance.

---

## 18. Security Principles

### Extension

* Request minimum permissions.
* Validate extension messages.
* Avoid unnecessary content-script access.
* Do not store sensitive information unnecessarily.

### Backend

* Validate all input.
* Rate-limit API requests.
* Use HTTPS in production.
* Secure secrets.
* Configure CORS appropriately.
* Return safe error messages.

### Detection

* Treat all incoming URLs as untrusted input.
* Do not execute submitted URLs merely to analyze them unless explicitly required and safely sandboxed.
* Prevent analysis logic from becoming an SSRF or command-execution pathway.

---

## 19. Architecture Decision Rules

Before adding a component, ask:

1. What problem does it solve?
2. Is the problem real?
3. Can the existing architecture solve it?
4. Does the new component introduce more complexity than value?
5. Does it improve security, reliability, performance, or maintainability?
6. Is it necessary for the current project scope?

If the answer is unclear, do not add the component yet.

---

## 20. Core Architecture Decision

The initial VerifyFirst architecture is:

```text
                    ┌─────────────────┐
                    │ Chrome Browser  │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Chrome          │
                    │ Extension       │
                    └────────┬────────┘
                             │
                         HTTPS/REST
                             │
                             ▼
                    ┌─────────────────┐
                    │ Backend API     │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Detection       │
                    │ Engine          │
                    └────────┬────────┘
                             │
                  ┌──────────┼──────────┐
                  ▼          ▼          ▼
                Rules       ML      Reputation
                  │          │          │
                  └──────────┼──────────┘
                             ▼
                       Risk Result
                             │
                             ▼
                    Extension UI
```

This architecture should remain the baseline unless a concrete requirement justifies changing it.

---

## 21. Technology Stack

```text
Chrome Extension
Manifest V3
TypeScript + HTML/CSS
        │
        │ HTTPS / REST
        ▼
FastAPI Backend (Python)
        │
        └── Detection Engine (Python)
             ├── URL Analysis
             ├── Feature Extraction
             ├── Security Rules
             └── ML (later phase)
```

The technology stack is documented in `01_PROJECT_SPEC.md`.
