# Phase 4D — Privacy & Data-Flow Audit

## 1. Data Flow
The VerifyFirst extension extracts data directly from the WhatsApp DOM (`whatsappScanner.ts`), dispatches it via Chrome IPC to the background Service Worker (`service-worker.ts`), which then deduplicates and transmits it to the Python backend via `/api/v1/analyze`, `/analyze-file`, or `/analyze-message`. Results are stored temporarily in the active tab state and persistently in the `historyStore`. Only a preview is displayed in the Security Center.

## 2. URL Data
- **Input:** URL candidates discovered via regex from message text or `href` attributes.
- **Transformation:** The raw candidate string is sent via IPC to the Service Worker.
- **Data transmitted:** Sent to the backend via POST `/api/v1/analyze`.
- **External:** The backend may perform external lookups (e.g., Google Safe Browsing) for the URL.

## 3. File Data
- **Input:** File metadata (filename).
- **Transformation:** Extracted from DOM. No actual file content is read or sent.
- **Data transmitted:** Sent to backend via POST `/api/v1/analyze-file`.

## 4. Message Data
- **Input:** Extracted from incoming message bubbles (`.message-in .selectable-text`).
- **Transformation:** Headers, footers, and hidden elements are excluded. Text is whitespace-normalized (`replace(/\s+/g, ' ')`) and truncated to `MAX_MESSAGE_LENGTH`.
- **Data transmitted:** The processed message string is sent to the backend `/api/v1/analyze-message`.
- **Exclusions:** Sender phone numbers, contact names, chat titles, and timestamps are **not** extracted or transmitted.

## 5. Service Worker
- **Logging:** Message content is not inadvertently logged. Log statements are sanitized (e.g., `console.log("[VerifyFirst] Message analysis requested")`).
- **State Management:** Uses `chrome.storage.session` with a fallback to `chrome.storage.local` to store `TabScanState`.
- **Data Leakage:** `MessageAnalysisRecord` retains the raw message text and stores it in the `TabScanState` map to deduplicate analyses.

## 6. Backend
- **Endpoint:** `/api/v1/analyze-message` accepts the raw message via POST body.
- **Logging:** The backend does not explicitly log request bodies for messages. Unhandled exceptions tracebacks are standard but are not exposed to the user.
- **Processing:** Analyzes content in-memory using deterministic regex rules (no external provider). Returns the risk score and reasons without echoing the full message back.

## 7. External Services

| Destination   | Asset   | Data sent            | Purpose             |
| ------------- | ------- | -------------------- | ------------------- |
| Backend       | URL     | URL string           | Heuristic Analysis  |
| Backend       | File    | Filename metadata    | Heuristic Analysis  |
| Backend       | Message | Message content      | Heuristic Analysis  |
| Safe Browsing | URL     | URL (Server-side)    | Threat intelligence |

Safe Browsing credentials and lookups are strictly server-side. Messages are analyzed strictly locally on the backend.

## 8. Persistent Storage
- **History Store (`historyStore.ts`):** Uses `chrome.storage.local`. Safely transforms messages into `SecurityEvent` objects with `assetType = message` and `messagePreview = message.slice(0, 100)`. It **does not** store the full message.
- **Tab State (`service-worker.ts`):** Uses `chrome.storage.session` but falls back to `chrome.storage.local`. **FINDING:** The `TabScanState` caches the full message under the `messages` dictionary as `MessageAnalysisRecord`. Since there is no `chrome.tabs.onRemoved` cleanup, if it falls back to `.local`, raw message content remains persistently on disk even after the tab is closed.

## 9. Security Center
- **Exposure:** The UI only displays the `messagePreview` string, which is strictly capped at 100 characters.

## 10. Logging & Error Handling
- **Service Worker Error Handling:** If the backend is unreachable, the fallback handler in `requestMessageAnalysis` does not log the raw message.
- **Backend Error Handling:** Standard 500 errors do not purposefully leak the raw message content back to the client.

## 11. Findings

### PASS
- **WhatsApp Extraction Boundary:** Scopes exactly to the incoming message text (`.message-in .selectable-text`), excluding sender identity, phone numbers, and chat titles.
- **Service-worker Data Flow:** Deduplicates successfully, console logs are properly sanitized, no message content leakage to external logs.
- **Backend Request Boundary:** Validates via schemas, does not persist messages to databases, does not leak to external APIs.
- **Security Center Exposure:** Message preview strictly limited to 100 characters, no raw messages shown.

### REVIEW
- **Service Worker Cache Key:** In `handleAnalyzeMessage`, `inFlightMessageAnalyses.has(cacheKey)` uses the raw message text in the Map key. This remains in-memory and is inherently transient, but should be noted.

### FIX REQUIRED
- **Persistent Tab State Message Leak:** The `TabScanState` stores the full message text in `MessageAnalysisRecord`. Due to the fallback to `chrome.storage.local` and lack of tab cleanup (`chrome.tabs.onRemoved`), full incoming WhatsApp messages can be persisted permanently in Chrome's local storage. This violates the privacy boundary that raw messages should not be stored.

## 12. Final Assessment
The core WhatsApp DOM extraction cleanly isolates message content from sender PII, meeting the primary privacy objectives. However, a significant data-flow issue exists in the Service Worker where full messages are cached in `TabScanState` and potentially saved persistently to `chrome.storage.local` without a cleanup mechanism. A targeted fix must be implemented to ensure `TabScanState` only retains message hashes or safely truncates message cache entries, and/or guarantees proper cleanup on tab closure.
