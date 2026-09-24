import { SecurityEvent } from "./types.js";

declare var chrome: any;

const HISTORY_KEY = "verifyfirst_security_history";
export const MAX_HISTORY_EVENTS = 1000;

// Used to serialize concurrent writes
let writeLock: Promise<void> = Promise.resolve();

/**
 * Retrieves all security events from history, ordered oldest to newest.
 */
export async function getAll(): Promise<SecurityEvent[]> {
  try {
    if (!chrome || !chrome.storage || !chrome.storage.local) {
      return [];
    }
    const result = await chrome.storage.local.get(HISTORY_KEY);
    const events = result[HISTORY_KEY];
    if (Array.isArray(events)) {
      return events as SecurityEvent[];
    }
  } catch (err) {
    // Ignore storage failures
  }
  return [];
}

/**
 * Retrieves the most recent `limit` events, ordered newest to oldest.
 */
export async function getRecent(limit: number): Promise<SecurityEvent[]> {
  if (limit <= 0) return [];
  const events = await getAll();
  // Reverse to get newest first, then slice
  return [...events].reverse().slice(0, limit);
}

/**
 * Records a new SecurityEvent, maintaining the maximum history limit.
 * Concurrency is handled by chaining writes.
 */
export function record(event: SecurityEvent): Promise<void> {
  const nextLock = writeLock.then(async () => {
    try {
      if (!chrome || !chrome.storage || !chrome.storage.local) {
        return;
      }
      const result = await chrome.storage.local.get(HISTORY_KEY);
      let events: SecurityEvent[] = Array.isArray(result[HISTORY_KEY]) ? result[HISTORY_KEY] : [];
      
      events.push(event);

      if (events.length > MAX_HISTORY_EVENTS) {
        events = events.slice(events.length - MAX_HISTORY_EVENTS);
      }

      await chrome.storage.local.set({ [HISTORY_KEY]: events });
    } catch (err) {
      console.error("[VerifyFirst] History storage failed:", err);
    }
  });
  
  writeLock = nextLock;
  return nextLock;
}

/**
 * Clears all security event history.
 */
export function clear(): Promise<void> {
  const nextLock = writeLock.then(async () => {
    try {
      if (!chrome || !chrome.storage || !chrome.storage.local) {
        return;
      }
      await chrome.storage.local.remove(HISTORY_KEY);
    } catch (err) {
      console.error("[VerifyFirst] History clear failed:", err);
    }
  });
  writeLock = nextLock;
  return nextLock;
}
