# VerifyFirst — Security Rules

## 1. General Principle

VerifyFirst is a security product.

Its own implementation must follow secure development practices.

A security tool with security vulnerabilities is worse than no tool at all.

---

## 2. Input Validation

### All External Input Is Untrusted

The following must always be validated before processing:

* URLs submitted for analysis
* API request bodies
* Query parameters
* HTTP headers
* External API responses

### URL Validation

* Only `http` and `https` schemes are accepted.
* URLs must be valid and parseable.
* Maximum URL length: 2048 characters.
* Reject URLs that contain control characters or null bytes.
* Do not attempt to resolve or fetch submitted URLs unless explicitly required and safely implemented.

### API Request Validation

* Reject requests with missing or malformed required fields.
* Reject unexpected content types.
* Apply size limits to request bodies.
* Return clear, safe error messages for invalid input.

---

## 3. Rate Limiting

### API Rate Limiting

* Apply rate limiting to all public API endpoints.
* Rate limit by client IP address.
* Return HTTP 429 with a clear message when the limit is exceeded.
* Do not expose internal rate-limit implementation details in error responses.

### Recommended Initial Limits

* Analysis endpoint: 30 requests per minute per IP.
* Adjust based on measured usage patterns.

### Rate Limiting Is Not Authentication

Rate limiting restricts abuse but does not identify or authenticate clients.

Authentication should only be introduced when a feature genuinely requires user identity.

---

## 4. CORS Configuration

* In development, allow requests from the Chrome extension origin.
* In production, restrict CORS to the extension's origin only.
* Do not use wildcard (`*`) CORS origins in production.
* Do not allow unnecessary HTTP methods or headers.

---

## 5. HTTPS

* The backend must use HTTPS in production.
* During development, HTTP on localhost is acceptable.
* The extension must be configured to use the correct protocol per environment.

---

## 6. Chrome Extension Security

### Manifest V3

* The extension must use Chrome Manifest V3.
* Use a service worker for the background script (Manifest V3 requirement).

### Permissions

Use the minimum permissions required. Every permission must have a functional justification.

#### Initial Required Permissions

| Permission | Justification |
|---|---|
| `activeTab` | Obtain the URL of the current tab when the user activates the extension |

#### Permissions That May Be Required Later

| Permission | Justification | When |
|---|---|---|
| `scripting` | Inject page-warning content script | Phase 8 (Page Warning) |
| `host_permissions` | Content script access to web pages | Phase 8 (Page Warning) |

Do not request permissions for features that have not been implemented.

### Extension Content Security

* Do not embed backend secrets, API keys, or credentials inside the extension.
* Assume that everything shipped inside the extension can be inspected by the user.
* Do not use `eval()`, `Function()`, or inline scripts.
* Use the Content Security Policy enforced by Manifest V3.

### Extension Message Validation

* Validate all messages received by the background service worker.
* Do not trust messages from content scripts without validation.
* Do not pass unsanitized external data into the DOM.

---

## 7. Backend Security

### Error Handling

* Do not expose raw stack traces, file paths, or internal error details to clients.
* Return safe, user-friendly error messages.
* Log detailed errors server-side only.

### Secrets Management

* Use environment variables for secrets and configuration.
* Never hard-code secrets in source code.
* Add secret files to `.gitignore`.
* Do not commit `.env` files to version control.

### Dependency Security

* Keep dependencies to the minimum required set.
* Avoid dependencies with known vulnerabilities.
* Prefer well-maintained, widely-used libraries for security-critical functionality.

---

## 8. SSRF Protection

### Policy

The initial backend does **not** fetch or visit submitted URLs.

The analysis operates on the URL string, not on the content of the webpage.

### If Server-Side Fetching Is Introduced Later

If a future phase requires the backend to fetch a submitted URL:

* Block requests to private/internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, ::1, etc.).
* Block requests to link-local addresses.
* Limit the number of redirects followed.
* Set strict timeouts on outgoing requests.
* Validate the resolved IP address after DNS resolution (DNS rebinding protection).
* Restrict allowed protocols to HTTP and HTTPS.
* Do not allow the backend to make arbitrary requests on behalf of the user.

---

## 9. Detection Integrity

### No Fabricated Results

* Do not generate fake or arbitrary risk scores.
* Do not claim a website is safe merely because an external service failed to respond.
* If analysis cannot be completed, return `ANALYSIS_UNAVAILABLE` — never `SAFE`.

### Classification Must Be Server-Side

* The backend and detection engine calculate the final risk classification.
* The extension displays the result but does not determine it.
* Scoring thresholds and classification logic must be defined centrally in the backend.

### Detection States

```text
SAFE                    — No significant suspicious characteristics identified
SUSPICIOUS              — One or more characteristics require caution
DANGEROUS               — Strong evidence of significant security risk
ANALYSIS_UNAVAILABLE    — Analysis could not be completed
```

`ANALYSIS_UNAVAILABLE` must never be treated as `SAFE`.

---

## 10. Privacy and Data Minimization

* Collect and process only what is required for analysis.
* The extension sends only the URL — not cookies, passwords, page content, or browsing history.
* Do not log submitted URLs with user-identifying information unless there is a documented requirement.
* Do not store analysis results indefinitely without a retention policy.
* If a database is introduced, define data retention limits.

---

## 11. Authentication

### Current Policy

The initial system does not require authentication.

The API is protected by:

* HTTPS (production)
* Input validation
* Rate limiting
* CORS restrictions

### Future Authentication

If user accounts or authenticated features are introduced in a later phase:

* Use established authentication standards (e.g., OAuth 2.0, JWT).
* Do not build custom authentication schemes.
* Store credentials securely (hashed, salted).
* Implement proper session management.

Do not add authentication merely for resume value. Add it when a feature genuinely requires user identity.

---

## 12. Security Testing

Before considering a phase complete, verify:

* [ ] Input validation rejects malformed input.
* [ ] Rate limiting triggers correctly.
* [ ] Error responses do not expose internal details.
* [ ] Extension permissions match the documented minimum.
* [ ] No secrets are embedded in the extension.
* [ ] CORS is configured correctly.
* [ ] `ANALYSIS_UNAVAILABLE` is not treated as `SAFE`.

---

## 13. Security Decision Rule

When making a security-related implementation decision:

1. Identify the threat.
2. Check this document.
3. Implement the smallest safe solution.
4. Test the security behavior.
5. Report any remaining limitations.

Do not disable security controls to make something work.

Do not disable security controls to pass tests.
