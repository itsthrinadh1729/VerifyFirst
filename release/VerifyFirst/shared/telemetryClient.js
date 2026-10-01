/**
 * Sends a message to the Background Service Worker and wraps it in a strongly-typed Promise.
 */
function sendMessage(message) {
    return new Promise((resolve, reject) => {
        chrome.runtime.sendMessage(message, (response) => {
            if (chrome.runtime.lastError) {
                return reject(new Error(chrome.runtime.lastError.message));
            }
            if (!response) {
                return reject(new Error("No response from background script."));
            }
            if (response.success) {
                resolve(response.data);
            }
            else {
                reject(new Error(response.error || "Unknown telemetry error"));
            }
        });
    });
}
/**
 * Fetches the aggregated security statistics.
 */
export async function fetchStatistics() {
    return sendMessage({ type: "GET_SECURITY_STATISTICS" });
}
/**
 * Queries the security history store with optional filters.
 */
export async function fetchHistory(query) {
    return sendMessage({ type: "QUERY_SECURITY_HISTORY", query });
}
/**
 * Triggers an export of the full security history.
 * Returns the serialized JSON string.
 */
export async function triggerExport() {
    return sendMessage({ type: "EXPORT_SECURITY_HISTORY" });
}
/**
 * Wipes the security history permanently.
 */
export async function wipeHistory() {
    return sendMessage({ type: "CLEAR_SECURITY_HISTORY" });
}
