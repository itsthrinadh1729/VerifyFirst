const HISTORY_KEY = "verifyfirst_security_history";
export const MAX_HISTORY_EVENTS = 1000;
// Used to serialize concurrent writes
let writeLock = Promise.resolve();
// Transient cache for deduplicating identical recent encounters (e.g., from DOM rescans)
const recentEncounters = new Map();
const DEDUP_WINDOW_MS = 60 * 1000; // 60 seconds
/**
 * Retrieves all security events from history, ordered oldest to newest.
 */
export async function getAll() {
    try {
        if (!chrome || !chrome.storage || !chrome.storage.local) {
            return [];
        }
        const result = await chrome.storage.local.get(HISTORY_KEY);
        const events = result[HISTORY_KEY];
        if (Array.isArray(events)) {
            return events;
        }
    }
    catch (err) {
        // Ignore storage failures
    }
    return [];
}
/**
 * Retrieves the most recent `limit` events, ordered newest to oldest.
 */
export async function getRecent(limit) {
    if (limit <= 0)
        return [];
    const events = await getAll();
    // Reverse to get newest first, then slice
    return [...events].reverse().slice(0, limit);
}
/**
 * Records a new SecurityEvent, maintaining the maximum history limit.
 * Concurrency is handled by chaining writes.
 */
export function record(event) {
    const nextLock = writeLock.then(async () => {
        try {
            const now = Date.now();
            // Deduplication check
            if (event._dedupIdentity) {
                const lastSeen = recentEncounters.get(event._dedupIdentity);
                if (lastSeen && (now - lastSeen) < DEDUP_WINDOW_MS) {
                    console.log(`[VerifyFirst] Suppressing duplicate history event for encounter: ${event._dedupIdentity}`);
                    return;
                }
                recentEncounters.set(event._dedupIdentity, now);
                // Cleanup old entries
                for (const [key, timestamp] of recentEncounters.entries()) {
                    if (now - timestamp >= DEDUP_WINDOW_MS) {
                        recentEncounters.delete(key);
                    }
                }
            }
            // Strip transient identity before persistence to maintain privacy
            const eventToStore = { ...event };
            delete eventToStore._dedupIdentity;
            if (!chrome || !chrome.storage || !chrome.storage.local) {
                return;
            }
            const result = await chrome.storage.local.get(HISTORY_KEY);
            let events = Array.isArray(result[HISTORY_KEY]) ? result[HISTORY_KEY] : [];
            events.push(eventToStore);
            if (events.length > MAX_HISTORY_EVENTS) {
                events = events.slice(events.length - MAX_HISTORY_EVENTS);
            }
            await chrome.storage.local.set({ [HISTORY_KEY]: events });
        }
        catch (err) {
            console.error("[VerifyFirst] History storage failed:", err);
        }
    });
    writeLock = nextLock;
    return nextLock;
}
/**
 * Clears all security event history.
 */
export function clear() {
    const nextLock = writeLock.then(async () => {
        try {
            if (!chrome || !chrome.storage || !chrome.storage.local) {
                return;
            }
            await chrome.storage.local.remove(HISTORY_KEY);
        }
        catch (err) {
            console.error("[VerifyFirst] History clear failed:", err);
        }
    });
    writeLock = nextLock;
    return nextLock;
}
