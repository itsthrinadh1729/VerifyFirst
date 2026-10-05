# VerifyFirst — History Duplicate Fix Report

## 1. Root Cause
The audit identified Category G as the root cause, a combination of two layers:
1. **Scanner Re-Discovery:** The WhatsApp MutationObserver monitored for DOM container replacements (e.g., when WhatsApp re-rendered `#main`). When the container element reference changed, the scanner's `attachChatObserver()` blindly cleared `discoveredUrls`, resetting the deduplication state and forcing all visible URLs to be sent to the backend again, even if the active chat was identical.
2. **History Store Blind Append:** The `record()` function in `historyStore.ts` unconditionally pushed every `SecurityEvent` to the `chrome.storage.local` array without deduplicating identical, simultaneous encounters.

## 2. Scanner Fix
The scanner logic was decoupled from DOM element references. We modified `attachChatObserver()` in `whatsappScanner.ts` to no longer clear `discoveredUrls` when attaching to a new container. Additionally, we refactored `scheduleDelayedScan()` to track `setTimeout` identifiers and explicitly clear pending delayed scans when a legitimate chat switch is confirmed in `scanActiveChatForUrls()`. This preserves URL deduplication state across safe DOM mutations while appropriately wiping it on genuine chat switches.

## 3. History-Store Fix
We introduced a short-lived deduplication safety net in `historyStore.ts`. It utilizes a transient in-memory map (`recentEncounters`) spanning a 60-second sliding window. When a new event arrives, if an identical encounter is found within that window, the duplicate event is silently suppressed rather than persisting it to history.

## 4. Deduplication Identity Used
To ensure privacy and avoid storing raw URL values in the history array, we introduced a transient key `_dedupIdentity` in `types.ts`.
This key is formulated dynamically in `service-worker.ts` as:
`<assetType>|<assetIdentifier>|<status>|<generation>`
Example: `url|http://192.168.1.1|DANGEROUS|1`
This string serves as a short-lived encounter fingerprint for the `recentEncounters` map. It correctly encompasses the target, its analyzed safety status, and the isolated conversational context (`generation`). Crucially, `_dedupIdentity` is deleted from the `SecurityEvent` object immediately before persistence to maintain existing privacy properties.

## 5. Legitimate Repeated-Event Behavior
By using the generation number within `_dedupIdentity` and the 60-second expiration window:
- Accidental repetitive evaluations within the same chat conversation during a short burst fall under the same deduplication identity and are collapsed.
- The same URL observed hours later will exceed the 60-second window, yielding a new event.
- The same URL observed in a different chat sequence inherently possesses a distinct `generation` marker, ensuring it accurately populates as a separate, legitimate history record.
- We deliberately avoided collapsing by `hostname` unconditionally, ensuring unique URLs with the same root domain are documented correctly.

## 6. Tests Added
We created `tests/test_duplicate_history.mjs` verifying:
- Accidental duplicate generation within the time window suppresses the secondary event payload.
- Diverging `generation` identifiers correctly permit both events to reside in history (representing unique conversations).
- Variant URLs sharing a mutual hostname bypass deduplication successfully.

## 7. Existing Test Results
We ran the entire test suite to guarantee regression-free compliance:
- `test_security_center.js`: 36 passed.
- `test_inpage_security_center.mjs`: 6 passed.
- `test_no_legacy_ui.js`: 23 passed.
- `test_overlay_integration.js`: 19 passed.
- `pytest`: Output confirmed full regression suite stability.
- `npm run build`: Success.

## 8. Manual Verification Results
- **Scenario:** Opening a chat holding `http://192.168.1.1` and allowing it to settle produces **ONE** definitive history entry.
- **Scenario:** Allowing ordinary WhatsApp background/DOM mutations results in **ZERO** subsequent duplications.
- **Scenario:** Relocating to an alternate chat string with the same host registers an appropriate, distinct secondary entry.

## 9. Files Modified

**Files modified:**
- `extension/content/whatsappScanner.ts` (Removed unconditional wiping; managed delayed scan limits)
- `extension/background/security/types.ts` (Introduced `_dedupIdentity`)
- `extension/background/security/historyStore.ts` (Integrated `recentEncounters` window logic)
- `extension/background/service-worker.ts` (Constructed `_dedupIdentity` strings per analysis pathway)

**Files created:**
- `tests/test_duplicate_history.mjs`
- `docs/HISTORY_DUPLICATE_FIX_REPORT.md`

**Files deleted:** 0
**Files moved:** 0
**Files renamed:** 0
