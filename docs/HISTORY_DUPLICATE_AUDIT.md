# VerifyFirst History Duplicate Audit

## 1. Observed Problem

The Security Center displays repeated history entries for the same URL/host. Specifically:

- **Host:** `192.168.1.1`
- **Status:** Dangerous
- **Risk Score:** 77
- **Protection Action:** BLOCK

The Overview shows:
- **Total Analyzed:** 312
- **Unique Hosts:** 31

The History page contains many repeated entries for `192.168.1.1`, each with an identical hostname, status, risk score, and protection action—but with **different event IDs and timestamps**. This means the events are distinct objects in `chrome.storage.local`, not rendering duplicates.

---

## 2. Complete Data Flow

```
WhatsApp Scanner (whatsappScanner.ts)
  │
  │  MutationObserver fires → scheduleScan() → scanActiveChatForUrls()
  │  discoverUrlsInContainer() finds URLs in DOM
  │  URL checked against discoveredUrls Set → if new, dispatched
  │
  ├─ ANALYZE_URL message ──────────────────────────────────────────┐
  │                                                                 │
  │                                                                 ▼
  │                                              Service Worker (service-worker.ts)
  │                                                │
  │                                                │  handleAnalyzeUrl()
  │                                                │   1. Check tab-state URL cache
  │                                                │   2. Check inFlightAnalyses Map
  │                                                │   3. requestBackendAnalysis() → POST /api/v1/analyze
  │                                                │
  │                                                │  Backend returns analysis result
  │                                                │
  │                                                │  createSecurityEvent() (event.ts)
  │                                                │   → generates crypto.randomUUID()
  │                                                │   → sanitizeUrlToHostname() → stores hostname only
  │                                                │   → NO dedup check
  │                                                │
  │                                                │  recordHistory(secEvent) (historyStore.ts)
  │                                                │   → getAll() → events.push(event) → set()
  │                                                │   → NO duplicate check before push
  │                                                │
  │                                                │  sendResponse({ success: true, record })
  │                                                │  + chrome.tabs.sendMessage(ANALYSIS_RESULT)
  │                                                │
  ◄────────────────────────────────────────────────┘
  │
  │  Scanner receives result via:
  │    (a) sendResponse callback in safeSendMessage
  │    (b) ANALYSIS_RESULT listener (chrome.runtime.onMessage)
  │
  │  Overlay displayed if non-SAFE
  │
  ▼
Security Center (securityCenter.ts)
  │
  │  telemetry.fetchHistory() → QUERY_SECURITY_HISTORY
  │    → querySecurityHistory() (historyQuery.ts)
  │      → getAll() from historyStore
  │      → filter/sort/paginate
  │      → returns SecurityEvent[]
  │
  │  renderEventRows(events) — renders one <tr> per event
  │  No deduplication in query or render layer
  │
  ▼
UI displays every stored event as a separate row
```

---

## 3. Duplicate Entry Creation Points

### Point A — Scanner Re-Discovery on DOM Mutation

| Field | Value |
|---|---|
| **File** | `whatsappScanner.ts` |
| **Function** | `attachChatObserver()` (lines 1178–1221) |
| **Behavior** | The `bodyObserver` (line 1160) watches `document.body` with `childList: true, subtree: true`. When ANY child DOM change occurs anywhere in the body, it checks if the chat container element reference has changed. If it has (e.g., WhatsApp re-renders the `#main` element), `attachChatObserver()` is called, which **clears `discoveredUrls` entirely** (line 1184) and triggers a fresh `scanActiveChatForUrls(true)` (line 1205). |
| **Evidence** | Line 1184: `discoveredUrls.clear()` — this wipes the in-memory dedup Set. Line 1205: `scanActiveChatForUrls(true)` — this immediately rescans the same chat. Since `discoveredUrls` was just cleared, every URL in the DOM is treated as "newly discovered" and dispatched again via `ANALYZE_URL`. |

### Point B — Scanner Re-Discovery on Chat "Switch" to Same Chat

| Field | Value |
|---|---|
| **File** | `whatsappScanner.ts` |
| **Function** | `scanActiveChatForUrls()` (lines 620–642) |
| **Behavior** | Chat identity is derived from the header contact title via `getActiveChatIdentifier()`. If the header is temporarily unavailable during a DOM re-render (returns `""` or `"active_chat"` as fallback), this can trigger a false "chat switch" detection. Lines 625-626: `discoveredUrls.clear(); currentChatRecords = {};`. Then on the next scan when the header reappears, another "switch" occurs, clearing `discoveredUrls` again. Each false switch causes all URLs to be re-submitted. |
| **Evidence** | Lines 622-626: `if (activeChatId !== currentChatId) { ... discoveredUrls.clear(); }` — the chat ID comparison is based on header text extraction, which can flicker during WhatsApp DOM mutations. |

### Point C — Delayed Scans After Chat Switch

| Field | Value |
|---|---|
| **File** | `whatsappScanner.ts` |
| **Function** | `scanActiveChatForUrls()` (lines 640-641) |
| **Behavior** | After each chat switch detection, two delayed scans are scheduled: `scheduleDelayedScan(500)` and `scheduleDelayedScan(1500)`. These are **not cancellable** (they use raw `setTimeout`, not the debounce timer). If the scanner already processed URLs in the immediate scan, but `discoveredUrls` was cleared by a subsequent `attachChatObserver` call between the immediate scan and the delayed scan, the delayed scans will re-discover and re-submit the same URLs. |
| **Evidence** | Lines 640-641: `scheduleDelayedScan(500); scheduleDelayedScan(1500);` — these fire independently of any state changes. |

### Point D — Service Worker Creates a New Event Every Time

| Field | Value |
|---|---|
| **File** | `service-worker.ts` |
| **Function** | `handleAnalyzeUrl()` (lines 207-292) |
| **Behavior** | The service worker has a **tab-scoped URL cache** (`currentState.urls[trimmed]`, line 234) and an **in-flight dedup Map** (`inFlightAnalyses`, lines 202, 240). These provide deduplication **within a single chat generation**. However, when a chat "switch" occurs (even a false one — Point B above), `handleChatSwitched()` (line 109) increments `generation` and creates a fresh `urls: {}` cache. Subsequent ANALYZE_URL requests for the same URL will **not** find them in cache (line 234) and will **create a new SecurityEvent** (line 260) and **record it to history** (line 264). |
| **Evidence** | Line 234: `if (currentState.urls[trimmed])` — this check passes only within the same generation. Line 260-264: `createSecurityEvent(record, trimmed)` followed by `recordHistory(secEvent)` — unconditionally creates and persists a new event. |

### Point E — History Store Blindly Appends

| Field | Value |
|---|---|
| **File** | `historyStore.ts` |
| **Function** | `record()` (lines 44-67) |
| **Behavior** | The `record()` function performs a simple `events.push(event)` (line 53) with **zero deduplication**. It does not check whether an event with the same hostname, URL, status, or any other field already exists. Every call to `record()` unconditionally appends a new entry. |
| **Evidence** | Line 53: `events.push(event)` — no `find()`, `filter()`, `some()`, or any duplicate-checking logic precedes this call. The only guard is the `MAX_HISTORY_EVENTS` cap (line 55), which evicts the oldest events when the array exceeds 1000. |

### Point F — Event ID Is Always Unique (By Design)

| Field | Value |
|---|---|
| **File** | `event.ts` |
| **Function** | `createSecurityEvent()` (line 45) |
| **Behavior** | Every event gets `id: crypto.randomUUID()` — a new UUID is generated for every call. There is **no deduplication key** based on hostname, URL, analysis content, or temporal proximity. Two events for the same `192.168.1.1` at nearly the same time are indistinguishable structurally (same hostname, status, risk_score) but have different IDs and timestamps. |
| **Evidence** | Line 45: `id: crypto.randomUUID()` — guarantees uniqueness by design, making dedup impossible at the store level without additional fields. |

---

## 4. Scanner Deduplication

### How URL Deduplication Currently Works

The scanner uses an in-memory `Set<string>` called `discoveredUrls` (line 4):

```typescript
const discoveredUrls: Set<string> = new Set<string>();
```

**Dedup mechanism:**

In `scanActiveChatForUrls()` (lines 653-661), each URL from `discoverUrlsInContainer()` is checked against `discoveredUrls`:

```typescript
for (const normalized of allUrls) {
  if (!discoveredUrls.has(normalized)) {
    discoveredUrls.add(normalized);
    newCandidates.push(normalized);
  }
}
```

Only URLs **not already in the Set** are dispatched via `ANALYZE_URL`.

### When `discoveredUrls` is Cleared

`discoveredUrls.clear()` is called in **three** places:

1. **`scanActiveChatForUrls()`** line 625 — when `activeChatId !== currentChatId` (chat switch detected)
2. **`scanActiveChatForUrls()`** line 604 — when no chat container is found (reset state)
3. **`attachChatObserver()`** line 1184 — when the body observer detects a new/different chat container element

### Critical Problem: Container Reference Changes

The `bodyObserver` (line 1160) fires on **any** `childList` change in `document.body` (with `subtree: true`). It compares `chatContainer !== currentObservedContainer` by **object reference**. WhatsApp Web frequently re-renders parts of the DOM, which can cause `document.getElementById("main")` to return a **different element reference** even though the user has not switched chats. When this happens:

1. `attachChatObserver(newContainer)` is called
2. `discoveredUrls.clear()` wipes all dedup state
3. `scanActiveChatForUrls(true)` re-discovers all URLs
4. All URLs are dispatched to the service worker as "new" analysis requests

### Whether the Same URL Can Be Submitted Again

**Yes.** Every time `discoveredUrls` is cleared (which can happen multiple times per conversation due to DOM re-renders), every URL visible in the chat is re-dispatched. The service worker's tab-state cache is also invalidated on "chat switch" (generation increment), so the backend is called again, a new SecurityEvent is created, and a new history entry is appended.

### Whether MutationObserver Can Rediscover the Same URL

**Yes.** The mutation-triggered `scheduleScan()` (line 1207-1209) calls `scanActiveChatForUrls(false)`. While `discoveredUrls` prevents re-dispatch during *normal* mutations, if a container reference change triggers `attachChatObserver()` first (clearing `discoveredUrls`), subsequent mutation-triggered scans will rediscover everything.

---

## 5. History Deduplication

**`historyStore.ts` performs NO deduplication whatsoever.**

The `record()` function (lines 44-67) is a pure append:

```typescript
export function record(event: SecurityEvent): Promise<void> {
  const nextLock = writeLock.then(async () => {
    // ...
    let events = Array.isArray(result[HISTORY_KEY]) ? result[HISTORY_KEY] : [];
    events.push(event);           // ← No dedup check
    if (events.length > MAX_HISTORY_EVENTS) {
      events = events.slice(events.length - MAX_HISTORY_EVENTS);
    }
    await chrome.storage.local.set({ [HISTORY_KEY]: events });
  });
}
```

There is:
- ❌ No check for existing event with same hostname
- ❌ No check for existing event with same URL
- ❌ No check for existing event within a time window
- ❌ No content-based dedup key
- ❌ No idempotency mechanism

Every call to `record()` creates a new persistent entry.

---

## 6. UI Deduplication

**The Security Center does NOT duplicate records during rendering.**

### Evidence:

1. **`renderEventRows()`** (securityCenter.ts lines 370-391) iterates over the `events` array exactly once with `events.forEach()` and generates exactly one `<tr>` per event. There is no multiplication or expansion.

2. **`renderHistory()`** (securityCenter.ts lines 580-685) fetches history via `telemetry.fetchHistory()`, stores it in `historyEvents`, applies filters, and passes `filteredHistoryEvents` to `renderEventRows()`. No duplication occurs.

3. **`querySecurityHistory()`** (historyQuery.ts lines 8-83) retrieves events from `getAll()`, filters them, sorts them, and applies pagination. It does not join, repeat, or multiply events.

4. **`calculateStatistics()`** (statistics.ts lines 8-79) iterates once over the events array with a single `for` loop. `totalEvents` is `events.length`, which accurately reflects the number of stored events (including duplicates).

**Conclusion:** If there are N events in `chrome.storage.local`, the UI displays exactly N rows. The duplication is in the stored data, not in the rendering.

---

## 7. Root Cause

### Classification: **G — Multiple layers contribute to duplication**

Specifically, a combination of **A** (Scanner sends duplicate analysis requests) and **D** (History store blindly appends repeated equivalent events).

### Causal Chain:

```
1. WhatsApp DOM mutation (e.g., message render, scroll, typing indicator)
   │
2. bodyObserver fires (subtree: true on document.body)
   │
3. getActiveChatContainer() returns a new element reference
   (same chat, but WhatsApp re-created the #main element)
   │
4. attachChatObserver() called:
   → discoveredUrls.clear()    ← scanner dedup wiped
   → CHAT_SWITCHED sent        ← service worker generation incremented
   → scanActiveChatForUrls(true) ← immediate rescan
   │
5. All URLs in the chat are "rediscovered"
   → Each dispatched via ANALYZE_URL
   │
6. Service worker handleAnalyzeUrl():
   → Tab URL cache is empty (new generation)
   → Backend called again
   → createSecurityEvent() → new UUID
   → recordHistory() → appended to storage
   │
7. Repeat steps 1-6 for every DOM mutation that changes the container reference
```

This means a single URL like `http://192.168.1.1` could produce **dozens** of history entries during a single browsing session, each with the same hostname/status/score but different UUIDs and timestamps.

---

## 8. Recommended Fix

The smallest correct architectural fix involves **two changes** (not implementing here, just describing):

### Fix 1: History Store Deduplication (Primary)

Add a deduplication check to `historyStore.record()` that prevents appending an event if an event with the **same hostname + same status + same riskScore** already exists **within a configurable time window** (e.g., 60 seconds). This is the safety net that prevents duplicate entries regardless of upstream behavior.

```
Pseudocode:
  const isDuplicate = events.some(existing =>
    existing.hostname === event.hostname &&
    existing.status === event.status &&
    existing.riskScore === event.riskScore &&
    Math.abs(existing.timestamp - event.timestamp) < DEDUP_WINDOW_MS
  );
  if (!isDuplicate) events.push(event);
```

### Fix 2: Stabilize Scanner Container Detection (Secondary)

Change `bodyObserver` to compare containers by a **stable identifier** (e.g., `data-testid` or element tag+class combination) rather than object reference equality. This prevents false "chat switch" detections when WhatsApp re-renders the same chat's DOM tree.

### Why Both:

- Fix 1 alone is correct but doesn't address the unnecessary backend calls caused by redundant ANALYZE_URL dispatches.
- Fix 2 alone reduces duplicates but doesn't provide a guarantee — there are other paths (e.g., actual chat switch back to the same chat, delayed scans, page reload) that can still produce duplicate events.
- Together, they form a defense-in-depth strategy.

---

## 9. Important Behavioral Decision

### Should repeated encounters with the same URL create separate history events?

**Yes — but only for genuinely separate encounters.**

The correct behavior is:

| Scenario | Expected Behavior |
|---|---|
| Same URL in same chat, same browsing session, same DOM scan cycle | **One event** (deduplicate) |
| Same URL in same chat, re-sent due to DOM re-render within seconds | **One event** (deduplicate — this is the bug) |
| Same URL in a **different** chat/conversation | **Separate event** (distinct encounter, different context) |
| Same URL in the same chat, but sent again **hours/days later** | **Separate event** (new temporal encounter) |
| Same URL sent by a **different contact** in a group chat | **Separate event** (different source) |

### What identifier should distinguish encounters?

The system currently lacks a proper **encounter identifier**. The recommended approach:

1. **Composite dedup key**: `hostname + status + riskScore` (content-based identity)
2. **Time-window deduplication**: Events within N seconds (e.g., 60s) of each other with the same dedup key are considered the same encounter
3. **Future enhancement**: If chat context or message-level identifiers become available in the SecurityEvent, add `chatId` or `messageId` to the dedup key for finer-grained distinction

The current `crypto.randomUUID()` event ID is **not** suitable as a dedup key — it guarantees uniqueness by design. The dedup key must be **content-based**, not identity-based.

### What should NOT be done:

- ❌ "Keep only one record per hostname" — This would collapse genuinely separate encounters
- ❌ "Deduplicate by URL" — The system correctly stores `hostname` (not full URL) for privacy; different URLs can map to the same hostname
- ❌ "Deduplicate globally across all time" — A URL blocked today and seen again next week is a meaningful separate event

---

## 10. Safety

| Metric | Count |
|---|---|
| **Files modified** | 0 |
| **Files deleted** | 0 |
| **Files moved** | 0 |
| **Files renamed** | 0 |
| **Files created** | 1 (this audit document) |
