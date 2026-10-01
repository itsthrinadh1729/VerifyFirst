# Phase 4E — Security Boundary Audit

## 1. Extension ↔ WhatsApp Boundary
* **Content Script Scope:** The `manifest.json` correctly scopes the content scripts strictly to `https://web.whatsapp.com/*` (and `https://example.com/*` for testing). It does not scan arbitrary pages.
* **XSS in Overlay:** The injection of the security overlay (`verifyFirstOverlay.ts`) uses `document.createElement()` and `textContent` for dynamic values (`urlBox.textContent = record.url`, `statusTitle.textContent`, `scoreVal.textContent`), safely preventing DOM-based XSS from malicious URLs, filenames, or messages.

## 2. Content Script ↔ Service Worker Boundary
* **IPC Validation:** The Service Worker (`service-worker.ts`) thoroughly validates incoming IPC messages. It verifies `typeof message.url === "string"`, requires non-empty strings, and validates `tabId`.
* **State/Generation Validation:** It safely drops stale asynchronous responses using a `generation` counter (`capturedGeneration`), ensuring that rapid chat switching doesn't result in cross-contamination of results.
* **Cross-Tab Isolation:** Results are explicitly pushed via `chrome.tabs.sendMessage` to the specific `tabId` that originated the request, preventing cross-tab leakage.

## 3. Service Worker ↔ Backend Boundary
* **Request Validation:** SW uses `fetch` and strictly formats payloads. 
* **Response Validation:** The SW checks `typeof data.status === "string"`, `typeof data.risk_score === "number"`, and validates `reasons` as an Array, discarding malformed JSON or backend timeout errors securely as `ANALYSIS_UNAVAILABLE`.
* **Timeout Behavior:** A strict `AbortController` handles backend timeouts, defaulting securely to safe/unavailable without crashing.

## 4. Backend API Boundary
* **Schema Validation:** Pydantic models (`AnalyzeRequest`, `FileAnalyzeRequest`, `MessageAnalysisInput`) strictly enforce string lengths, bounds, and actively reject ASCII control characters (0-31, 127) and null bytes.
* **Regex / Parsing Pathologies:** Regex patterns in `rules.py` are bounded and avoid catastrophic backtracking.
* **Exception Handling:** Unhandled exceptions in `ThreatIntelService` are cleanly caught and returned as `ThreatIntelResult.unavailable()`, preventing tracebacks from leaking.

## 5. Threat Intelligence Boundary
* **Asset Isolation:** `analyze_file` and `analyze_message` do **not** invoke `ThreatIntelService`. Only URLs are sent to external threat intelligence providers.
* **Privacy-Preserving Normalization:** Only the extracted hostname or URL candidate is queried. 

## 6. Event & Storage Integrity
* **State Tampering:** Local storage (`chrome.storage.local` and `.session`) is used. If an external local process modifies the storage, the UI could theoretically load tampered history. However, `historyStore.ts` safely parses the array. 

## 7. UI Security Boundary (Security Center)
* **XSS Vulnerabilities in UI Rendering:** The `securityCenter.ts` heavily relies on template strings and `innerHTML` for DOM construction. 
* **Unescaped Values:** `ev.hostname`, `ev.reasons[].rule`, `ev.reasons[].message`, and `ev.threatContext.*` are injected directly into HTML without sanitization. 
  * Examples: `<span title="${host}">${host}</span>` and `data-clipboard="${ev.hostname}"`.
  * If the backend returns a payload containing HTML elements or quotes, it could result in XSS execution within the extension context.
* **Asset Rendering Oversight:** The UI completely ignores `ev.assetType` (URL vs File vs Message). As a result, file and message events have an empty hostname, which renders as `"unknown"`. Their actual `filename` and `messagePreview` properties are completely invisible to the user.

## 8. Findings

### PASS
- **Extension boundary:** Content script is accurately scoped. Overlay correctly uses `textContent` to prevent DOM XSS.
- **IPC/message validation:** SW properly validates all incoming IPC payloads.
- **Cross-tab isolation:** Responses strictly mapped via `tabId` and `generation`.
- **Backend boundary:** Pydantic strict schemas reject control characters and enforce size bounds.
- **Threat-intelligence boundary:** API is safely abstracted and only triggers on URLs.

### REVIEW
- **Storage integrity:** History relies on `chrome.storage.local`. While adequate for an extension, tampering by other local system processes could inject events.

### FIX REQUIRED
- **DOM/XSS boundary:** `securityCenter.ts` is vulnerable to DOM-based XSS due to unescaped injection of `hostname`, `reasons`, and `threatContext` via `innerHTML`.
- **Event integrity / Asset Isolation UI:** `securityCenter.ts` fails to properly display `file` and `message` assets, completely omitting `ev.filename` and `ev.messagePreview` in favor of an "unknown" hostname.

## 9. Next Steps
Before proceeding to Phase 4F, we must implement fixes for the UI Security Boundary:
1. Implement a robust HTML escaping utility in `securityCenter.ts`.
2. Wrap all injected dynamic properties (hostname, rule, message, context summaries) in the escaping utility.
3. Update `renderHostnameHtml` and `renderEventRows` to correctly interrogate `ev.assetType` and display `ev.filename` or `ev.messagePreview` when appropriate.
