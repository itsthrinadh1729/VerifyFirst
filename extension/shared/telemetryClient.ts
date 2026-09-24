import type { SecurityEvent, SecurityStatistics, SecurityHistoryQuery, TelemetryResponse } from "../background/security/types.js";

/**
 * Sends a message to the Background Service Worker and wraps it in a strongly-typed Promise.
 */
function sendMessage<T>(message: any): Promise<T> {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response: TelemetryResponse<T>) => {
      if (chrome.runtime.lastError) {
        return reject(new Error(chrome.runtime.lastError.message));
      }
      
      if (!response) {
        return reject(new Error("No response from background script."));
      }

      if (response.success) {
        resolve(response.data);
      } else {
        reject(new Error(response.error || "Unknown telemetry error"));
      }
    });
  });
}

/**
 * Fetches the aggregated security statistics.
 */
export async function fetchStatistics(): Promise<SecurityStatistics> {
  return sendMessage<SecurityStatistics>({ type: "GET_SECURITY_STATISTICS" });
}

/**
 * Queries the security history store with optional filters.
 */
export async function fetchHistory(query?: SecurityHistoryQuery): Promise<SecurityEvent[]> {
  return sendMessage<SecurityEvent[]>({ type: "QUERY_SECURITY_HISTORY", query });
}

/**
 * Triggers an export of the full security history.
 * Returns the serialized JSON string.
 */
export async function triggerExport(): Promise<string> {
  return sendMessage<string>({ type: "EXPORT_SECURITY_HISTORY" });
}

/**
 * Wipes the security history permanently.
 */
export async function wipeHistory(): Promise<void> {
  return sendMessage<void>({ type: "CLEAR_SECURITY_HISTORY" });
}
