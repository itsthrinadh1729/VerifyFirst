const HISTORY_KEY = "verifyfirst_security_history";
/**
 * Exports the complete security history in a standardized, privacy-preserving JSON format.
 * Returns a serialized JSON string.
 */
export async function exportSecurityHistory() {
    let events = [];
    try {
        // We access storage directly here rather than using historyStore.getAll()
        // because we explicitly need to REJECT on failure during an export operation,
        // whereas getAll() gracefully swallows errors to protect the detection flow.
        if (!chrome || !chrome.storage || !chrome.storage.local) {
            throw new Error("Storage API unavailable");
        }
        const result = await chrome.storage.local.get(HISTORY_KEY);
        events = (result[HISTORY_KEY] || []);
    }
    catch (err) {
        console.error("[VerifyFirst] Export failed due to storage error:", err);
        throw new Error("Storage failure during export");
    }
    const envelope = {
        version: 1,
        exportedAt: new Date().toISOString(),
        events
    };
    return JSON.stringify(envelope, null, 2);
}
