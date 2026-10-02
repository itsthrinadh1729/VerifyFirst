/**
 * VerifyFirst — Background Service Worker (Manifest V3)
 * 
 * Responsibilities:
 * 1. Validate messages received from the content script.
 * 2. Dispatch URL analysis requests to FastAPI backend (POST /api/v1/analyze).
 * 3. Safely map errors to ANALYSIS_UNAVAILABLE (never SAFE).
 * 4. Store per-tab/per-chat analysis results for the popup interface.
 * 5. Handle chat context isolation on conversation switch.
 */

import { createSecurityEvent, createFileSecurityEvent, createMessageSecurityEvent } from "./security/event.js";
import { record as recordHistory, clear as clearHistory } from "./security/historyStore.js";
import { getSecurityStatistics } from "./security/statistics.js";
import { querySecurityHistory } from "./security/historyQuery.js";
import { exportSecurityHistory } from "./security/export.js";

interface DetectionReason {
  rule: string;
  message: string;
}

interface AnalysisRecord {
  url: string;
  status: "SAFE" | "SUSPICIOUS" | "DANGEROUS" | "ANALYSIS_UNAVAILABLE";
  risk_score: number | null;
  reasons: DetectionReason[];
  timestamp: number;
  eventId?: string;
}

interface FileAnalysisRecord {
  filename: string;
  status: "SAFE" | "SUSPICIOUS" | "DANGEROUS";
  risk_score: number | null;
  reasons: DetectionReason[];
  timestamp: number;
  eventId?: string;
  asset_type: string;
}

interface MessageAnalysisRecord {
  status: "SAFE" | "SUSPICIOUS" | "DANGEROUS";
  risk_score: number | null;
  reasons: DetectionReason[];
  timestamp: number;
  eventId?: string;
  asset_type: string;
}

interface TabScanState {
  chatId: string;
  generation: number;
  urls: Record<string, AnalysisRecord>;
  files: Record<string, FileAnalysisRecord>;
  messages: Record<string, MessageAnalysisRecord>;
  lastUpdated: number;
}

const BACKEND_API_URL = "http://localhost:8000/api/v1/analyze";
const BACKEND_FILE_API_URL = "http://localhost:8000/api/v1/analyze-file";
const BACKEND_MESSAGE_API_URL = "http://localhost:8000/api/v1/analyze-message";
const REQUEST_TIMEOUT_MS = 5000;

/**
 * Storage accessor helper that prefers chrome.storage.session
 * with fallback to chrome.storage.local.
 */
function getStorageArea(): any {
  if (chrome.storage && chrome.storage.session) {
    return chrome.storage.session;
  }
  return chrome.storage.local;
}

/**
 * Retrieves the current scan state for a specific tab.
 */
async function getTabState(tabId: number): Promise<TabScanState> {
  const key = `tab_${tabId}`;
  const storage = getStorageArea();
  const result = await storage.get(key);
  if (result && result[key]) {
    return result[key] as TabScanState;
  }
  return {
    chatId: "",
    generation: 0,
    urls: {},
    files: {},
    messages: {},
    lastUpdated: Date.now(),
  };
}

/**
 * Persists the scan state for a specific tab.
 */
async function saveTabState(tabId: number, state: TabScanState): Promise<void> {
  const key = `tab_${tabId}`;
  const storage = getStorageArea();
  state.lastUpdated = Date.now();
  await storage.set({ [key]: state });
}

/**
 * Resets or updates state when switching chats in a tab.
 */
async function handleChatSwitched(tabId: number, chatId: string): Promise<void> {
  const oldState = await getTabState(tabId);
  const newGeneration = (oldState.generation || 0) + 1;
  const state: TabScanState = {
    chatId: chatId,
    generation: newGeneration,
    urls: {},
    files: {},
    messages: {},
    lastUpdated: Date.now(),
  };
  await saveTabState(tabId, state);
  console.log(`[VerifyFirst] Chat switched → generation=${newGeneration}, chatId="${chatId}"`);
}

/**
 * Sends a URL to the FastAPI detection backend.
 * Safely handles timeouts, network failures, and invalid responses.
 */
async function requestBackendAnalysis(url: string): Promise<AnalysisRecord> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(BACKEND_API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      return {
        url,
        status: "ANALYSIS_UNAVAILABLE",
        risk_score: null,
        reasons: [
          {
            rule: "BACKEND_ERROR",
            message: `Backend returned status ${response.status}. Security analysis could not be completed.`,
          },
        ],
        timestamp: Date.now(),
      };
    }

    const data = await response.json();
    
    // 11C: Malformed backend data handling
    if (
      !data ||
      typeof data.status !== "string" ||
      typeof data.risk_score !== "number" ||
      !Array.isArray(data.reasons)
    ) {
      return {
        url,
        status: "ANALYSIS_UNAVAILABLE",
        risk_score: null,
        reasons: [{ rule: "INVALID_RESPONSE", message: "Backend returned a malformed response." }],
        timestamp: Date.now(),
      };
    }

    return {
      url,
      status: data.status as "SAFE" | "SUSPICIOUS" | "DANGEROUS" | "ANALYSIS_UNAVAILABLE",
      risk_score: data.risk_score,
      reasons: data.reasons,
      timestamp: Date.now(),
    };
  } catch (error: any) {
    clearTimeout(timeoutId);
    return {
      url,
      status: "ANALYSIS_UNAVAILABLE",
      risk_score: null,
      reasons: [
        {
          rule: "ANALYSIS_UNAVAILABLE",
          message: "The backend detection service is unavailable. The security analysis could not be completed.",
        },
      ],
      timestamp: Date.now(),
    };
  }
}

// In-flight request tracker to deduplicate concurrent scans (6B)
const inFlightAnalyses = new Map<string, Promise<AnalysisRecord>>();

/**
 * Handles incoming URL analysis requests from content scripts.
 */
async function handleAnalyzeUrl(tabId: number, url: string): Promise<AnalysisRecord> {
  // Input validation
  if (!url || typeof url !== "string" || url.length > 2048) {
    return {
      url: url || "",
      status: "ANALYSIS_UNAVAILABLE",
      risk_score: null,
      reasons: [{ rule: "INVALID_URL", message: "Malformed or excessively long URL candidate." }],
      timestamp: Date.now(),
    };
  }

  const trimmed = url.trim();
  if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
    return {
      url: trimmed,
      status: "ANALYSIS_UNAVAILABLE",
      risk_score: null,
      reasons: [{ rule: "INVALID_SCHEME", message: "Only HTTP and HTTPS URLs are supported." }],
      timestamp: Date.now(),
    };
  }

  const currentState = await getTabState(tabId);
  const capturedGeneration = currentState.generation || 0;

  // Check if URL is already analyzed for this chat session
  if (currentState.urls[trimmed]) {
    console.log(`[VerifyFirst] URL already analyzed (cached): ${trimmed}`);
    return currentState.urls[trimmed];
  }

  const cacheKey = `${tabId}_${capturedGeneration}_${trimmed}`;
  if (inFlightAnalyses.has(cacheKey)) {
    console.log(`[VerifyFirst] Deduplicating concurrent request for: ${trimmed}`);
    return inFlightAnalyses.get(cacheKey)!;
  }

  console.log(`[VerifyFirst] Backend analysis requested: ${trimmed} (generation=${capturedGeneration})`);

  const analysisPromise = (async () => {
    try {
      try {
        const u = new URL(trimmed);
        console.log(`[VerifyFirst][SW] Backend analysis started for hostname=${u.hostname}`);
      } catch { }
      // Request backend analysis
      const record = await requestBackendAnalysis(trimmed);

      console.log(`[VerifyFirst] Backend response: status=${record.status}, risk_score=${record.risk_score}`);

      // Create and record SecurityEvent for history
      try {
        const secEvent = createSecurityEvent(record, trimmed);
        if (secEvent) {
          record.eventId = secEvent.id;
          // Fire and forget, don't block protection flow
          recordHistory(secEvent).catch(e => console.error("[VerifyFirst] Deferred history error:", e));
        }
      } catch (e) {
        console.error("[VerifyFirst] Error dispatching security event", e);
      }

      // Re-fetch to ensure fresh state — check generation to prevent cross-chat contamination
      const freshState = await getTabState(tabId);
      if ((freshState.generation || 0) !== capturedGeneration) {
        // Chat switched during analysis — discard result to prevent leaking into new chat
        console.log(`[VerifyFirst] DISCARDED stale result: generation ${capturedGeneration} → ${freshState.generation}`);
        return record;
      }

      // Do not cache UNAVAILABLE results so they can be retried automatically (Test 6)
      if (record.status !== "ANALYSIS_UNAVAILABLE") {
        freshState.urls[trimmed] = record;
        await saveTabState(tabId, freshState);
      }

      return record;
    } finally {
      inFlightAnalyses.delete(cacheKey);
    }
  })();

  inFlightAnalyses.set(cacheKey, analysisPromise);
  return analysisPromise;
}

// ── File Analysis Pipeline (Phase 2) ────────────────────────────────────

/**
 * Sends a filename to the FastAPI file detection backend.
 * Safely handles timeouts, network failures, and invalid responses.
 */
async function requestFileAnalysis(filename: string): Promise<FileAnalysisRecord> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(BACKEND_FILE_API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ filename }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      return {
        filename,
        status: "SAFE",
        risk_score: null,
        reasons: [],
        timestamp: Date.now(),
        asset_type: "file",
      };
    }

    const data = await response.json();

    if (
      !data ||
      typeof data.status !== "string" ||
      typeof data.risk_score !== "number" ||
      !Array.isArray(data.reasons)
    ) {
      return {
        filename,
        status: "SAFE",
        risk_score: null,
        reasons: [],
        timestamp: Date.now(),
        asset_type: "file",
      };
    }

    return {
      filename,
      status: data.status as "SAFE" | "SUSPICIOUS" | "DANGEROUS",
      risk_score: data.risk_score,
      reasons: data.reasons,
      timestamp: Date.now(),
      asset_type: "file",
    };
  } catch (error: any) {
    clearTimeout(timeoutId);
    return {
      filename,
      status: "SAFE",
      risk_score: null,
      reasons: [],
      timestamp: Date.now(),
      asset_type: "file",
    };
  }
}

// Separate in-flight tracker for file analysis (prevents mixing with URL dedup)
const inFlightFileAnalyses = new Map<string, Promise<FileAnalysisRecord>>();

/**
 * Handles incoming file analysis requests from content scripts.
 * Parallel to handleAnalyzeUrl — does not touch the URL pipeline.
 */
async function handleAnalyzeFile(tabId: number, filename: string): Promise<FileAnalysisRecord> {
  if (!filename || typeof filename !== "string") {
    return {
      filename: filename || "",
      status: "SAFE",
      risk_score: null,
      reasons: [],
      timestamp: Date.now(),
      asset_type: "file",
    };
  }

  const trimmed = filename.trim();
  if (!trimmed) {
    return {
      filename: "",
      status: "SAFE",
      risk_score: null,
      reasons: [],
      timestamp: Date.now(),
      asset_type: "file",
    };
  }

  const currentState = await getTabState(tabId);
  const capturedGeneration = currentState.generation || 0;

  // Check if file is already analyzed for this chat session
  if (currentState.files[trimmed]) {
    console.log(`[VerifyFirst] File already analyzed (cached): ${trimmed}`);
    return currentState.files[trimmed];
  }

  const cacheKey = `${tabId}_${capturedGeneration}_file_${trimmed}`;
  if (inFlightFileAnalyses.has(cacheKey)) {
    console.log(`[VerifyFirst] Deduplicating concurrent file request for: ${trimmed}`);
    return inFlightFileAnalyses.get(cacheKey)!;
  }

  console.log(`[VerifyFirst] File analysis requested: ${trimmed}`);

  const analysisPromise = (async () => {
    try {
      const record = await requestFileAnalysis(trimmed);

      console.log(`[VerifyFirst] File analysis response: status=${record.status}, risk_score=${record.risk_score}`);

      // Create and record SecurityEvent for history
      try {
        const secEvent = createFileSecurityEvent(record, trimmed);
        if (secEvent) {
          record.eventId = secEvent.id;
          recordHistory(secEvent).catch(e => console.error("[VerifyFirst] Deferred file history error:", e));
        }
      } catch (e) {
        console.error("[VerifyFirst] Error dispatching file security event", e);
      }

      // Re-fetch to ensure fresh state — check generation for chat isolation
      const freshState = await getTabState(tabId);
      if ((freshState.generation || 0) !== capturedGeneration) {
        console.log(`[VerifyFirst] DISCARDED stale file result: generation ${capturedGeneration} → ${freshState.generation}`);
        return record;
      }

      // Cache the result
      freshState.files[trimmed] = record;
      await saveTabState(tabId, freshState);

      return record;
    } finally {
      inFlightFileAnalyses.delete(cacheKey);
    }
  })();

  inFlightFileAnalyses.set(cacheKey, analysisPromise);
  return analysisPromise;
}

// ── Phase 3G: Message Analysis Pipeline ─────────────────────────────────

async function requestMessageAnalysis(message: string): Promise<MessageAnalysisRecord> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(BACKEND_MESSAGE_API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ message, source: "whatsapp" }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      return {
        status: "SAFE",
        risk_score: null,
        reasons: [],
        timestamp: Date.now(),
        asset_type: "message",
      };
    }

    const data = await response.json();

    if (
      !data ||
      typeof data.status !== "string" ||
      typeof data.risk_score !== "number" ||
      !Array.isArray(data.reasons)
    ) {
      return {
        status: "SAFE",
        risk_score: null,
        reasons: [],
        timestamp: Date.now(),
        asset_type: "message",
      };
    }

    return {
      status: data.status as "SAFE" | "SUSPICIOUS" | "DANGEROUS",
      risk_score: data.risk_score,
      reasons: data.reasons,
      timestamp: Date.now(),
      asset_type: "message",
    };
  } catch (error: any) {
    clearTimeout(timeoutId);
    return {
      status: "SAFE",
      risk_score: null,
      reasons: [],
      timestamp: Date.now(),
      asset_type: "message",
    };
  }
}

async function fingerprintMessage(message: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

const inFlightMessageAnalyses = new Map<string, Promise<MessageAnalysisRecord>>();

async function handleAnalyzeMessage(tabId: number, message: string): Promise<MessageAnalysisRecord & { message: string }> {
  if (!message || typeof message !== "string") {
    return {
      message: message || "",
      status: "SAFE",
      risk_score: null,
      reasons: [],
      timestamp: Date.now(),
      asset_type: "message",
    };
  }

  const trimmed = message.trim();
  if (!trimmed) {
    return {
      message: "",
      status: "SAFE",
      risk_score: null,
      reasons: [],
      timestamp: Date.now(),
      asset_type: "message",
    };
  }

  const fingerprint = await fingerprintMessage(trimmed);
  const currentState = await getTabState(tabId);
  const capturedGeneration = currentState.generation || 0;

  if (currentState.messages && currentState.messages[fingerprint]) {
    console.log(`[VerifyFirst] Message already analyzed (cached)`);
    return { ...currentState.messages[fingerprint], message: trimmed };
  }

  const cacheKey = `${tabId}_${capturedGeneration}_msg_${fingerprint}`;
  if (inFlightMessageAnalyses.has(cacheKey)) {
    console.log(`[VerifyFirst] Deduplicating concurrent message request`);
    const record = await inFlightMessageAnalyses.get(cacheKey)!;
    return { ...record, message: trimmed };
  }

  console.log(`[VerifyFirst] Message analysis requested`);

  const analysisPromise = (async () => {
    try {
      const record = await requestMessageAnalysis(trimmed);

      console.log(`[VerifyFirst] Message analysis response: status=${record.status}`);

      try {
        const secEvent = createMessageSecurityEvent(record, trimmed);
        if (secEvent) {
          record.eventId = secEvent.id;
          recordHistory(secEvent).catch(e => console.error("[VerifyFirst] Deferred message history error:", e));
        }
      } catch (e) {
        console.error("[VerifyFirst] Error dispatching message security event", e);
      }

      const freshState = await getTabState(tabId);
      if ((freshState.generation || 0) !== capturedGeneration) {
        console.log(`[VerifyFirst] DISCARDED stale message result`);
        return record;
      }

      if (!freshState.messages) {
        freshState.messages = {};
      }
      freshState.messages[fingerprint] = record;
      await saveTabState(tabId, freshState);

      return record;
    } finally {
      inFlightMessageAnalyses.delete(cacheKey);
    }
  })();

  inFlightMessageAnalyses.set(cacheKey, analysisPromise);
  const finalRecord = await analysisPromise;
  return { ...finalRecord, message: trimmed };
}

// Runtime message listener
chrome.runtime.onMessage.addListener((message: any, sender: any, sendResponse: any) => {
  if (!message || typeof message.type !== "string") {
    return false;
  }

  const tabId = sender.tab?.id ?? -1;

  if (message.type === "ANALYZE_URL") {
    if (tabId === -1) {
      sendResponse({ error: "Unknown tab sender" });
      return false;
    }
    const safeChatIdLog = message.chatId ? `length=${message.chatId.length}` : 'empty';
    try {
      const u = new URL(message.url);
      console.log(`[VerifyFirst][SW] ANALYZE_URL received for hostname=${u.hostname}, chatId=${safeChatIdLog}`);
    } catch { }
    console.log(`[VerifyFirst] ANALYZE_URL request received.`);

    // 14C: Message validation hardening
    if (typeof message.url !== "string" || !message.url.trim()) {
      console.log(`[VerifyFirst] Rejected ANALYZE_URL with invalid/missing url payload.`);
      sendResponse({ success: false, error: "Invalid URL payload" });
      return true;
    }

    handleAnalyzeUrl(tabId, message.url).then((record) => {
      sendResponse({ success: true, record });

      // Two-way delivery: explicitly push result to content script
      // This is the PRIMARY overlay trigger — sendResponse callback is fallback
      try {
        try {
          const u = new URL(record.url);
          console.log(`[VerifyFirst][SW] ANALYSIS_RESULT sent for hostname=${u.hostname}`);
        } catch { }
        console.log(`[VerifyFirst] Sending ANALYSIS_RESULT to tab ${tabId}: status=${record.status}`);
        chrome.tabs.sendMessage(tabId, {
          type: "ANALYSIS_RESULT",
          record: record,
          chatId: message.chatId,
        }).catch((pushErr: any) => {
          console.log(`[VerifyFirst] tabs.sendMessage caught: ${pushErr?.message || pushErr}`);
        });
      } catch (pushErr: any) {
        console.log(`[VerifyFirst] Failed to push ANALYSIS_RESULT to tab: ${pushErr?.message}`);
      }
    });
    return true; // Keep message channel open for async response
  }

  if (message.type === "CHAT_SWITCHED") {
    if (tabId !== -1) {
      if (typeof message.chatId !== "string") {
        console.log(`[VerifyFirst] Rejected CHAT_SWITCHED with invalid chatId payload.`);
        sendResponse({ success: false, error: "Invalid chatId payload" });
        return true;
      }
      handleChatSwitched(tabId, message.chatId).then(() => {
        sendResponse({ success: true });
      });
      return true;
    }
  }

  if (message.type === "ANALYZE_FILE") {
    if (tabId === -1) {
      sendResponse({ error: "Unknown tab sender" });
      return false;
    }
    console.log(`[VerifyFirst] ANALYZE_FILE received for: ${message.filename}`);

    if (typeof message.filename !== "string" || !message.filename.trim()) {
      console.log(`[VerifyFirst] Rejected ANALYZE_FILE with invalid/missing filename payload.`);
      sendResponse({ success: false, error: "Invalid filename payload" });
      return true;
    }

    handleAnalyzeFile(tabId, message.filename).then((record) => {
      sendResponse({ success: true, record });

      // Push file analysis result to content script for overlay display
      try {
        console.log(`[VerifyFirst] Sending FILE_ANALYSIS_RESULT to tab ${tabId}: status=${record.status}`);
        chrome.tabs.sendMessage(tabId, {
          type: "FILE_ANALYSIS_RESULT",
          record: record,
          chatId: message.chatId,
        }).catch((pushErr: any) => {
          console.log(`[VerifyFirst] tabs.sendMessage (file) caught: ${pushErr?.message || pushErr}`);
        });
      } catch (pushErr: any) {
        console.log(`[VerifyFirst] Failed to push FILE_ANALYSIS_RESULT to tab: ${pushErr?.message}`);
      }
    });
    return true;
  }

  if (message.type === "ANALYZE_MESSAGE") {
    if (tabId === -1) {
      sendResponse({ error: "Unknown tab sender" });
      return false;
    }
    console.log(`[VerifyFirst] ANALYZE_MESSAGE received`);

    if (typeof message.message !== "string" || !message.message.trim()) {
      console.log(`[VerifyFirst] Rejected ANALYZE_MESSAGE with invalid payload.`);
      sendResponse({ success: false, error: "Invalid message payload" });
      return true;
    }

    handleAnalyzeMessage(tabId, message.message).then((record) => {
      sendResponse({ success: true, record });

      try {
        console.log(`[VerifyFirst] Sending MESSAGE_ANALYSIS_RESULT to tab ${tabId}: status=${record.status}`);
        chrome.tabs.sendMessage(tabId, {
          type: "MESSAGE_ANALYSIS_RESULT",
          record: record,
          chatId: message.chatId,
        }).catch((pushErr: any) => {
          console.log(`[VerifyFirst] tabs.sendMessage (message) caught: ${pushErr?.message || pushErr}`);
        });
      } catch (pushErr: any) {
        console.log(`[VerifyFirst] Failed to push MESSAGE_ANALYSIS_RESULT to tab: ${pushErr?.message}`);
      }
    });
    return true;
  }

  if (message.type === "TRIGGER_SCAN") {
    // Forward scan trigger to the active tab's content script
    chrome.tabs.query({ active: true, currentWindow: true }).then((tabs: any[]) => {
      const activeTabId = tabs[0]?.id;
      if (activeTabId !== undefined) {
        chrome.tabs.sendMessage(activeTabId, { type: "TRIGGER_SCAN" }).catch(() => {
          // Content script not available, ignore
        });
      }
    });
    sendResponse({ success: true });
    return false;
  }

  if (message.type === "GET_TAB_RESULTS") {
    const targetTabId = typeof message.tabId === "number" ? message.tabId : tabId;
    if (targetTabId === -1) {
      // Find active tab if tabId wasn't passed directly
      if (chrome.tabs && chrome.tabs.query) {
        chrome.tabs.query({ active: true, currentWindow: true }).then((tabs: any[]) => {
          const activeTabId = tabs[0]?.id ?? -1;
          if (activeTabId !== -1) {
            getTabState(activeTabId).then((state) => {
              sendResponse({ success: true, state });
            });
          } else {
            sendResponse({ success: true, state: { chatId: "", urls: {}, lastUpdated: Date.now() } });
          }
        });
        return true;
      }
      sendResponse({ success: true, state: { chatId: "", urls: {}, lastUpdated: Date.now() } });
      return false;
    }

    getTabState(targetTabId).then((state) => {
      sendResponse({ success: true, state });
    });
    return true;
  }

  // Module 7A: UI/API Contract handlers
  if (message.type === "GET_SECURITY_STATISTICS") {
    getSecurityStatistics().then(stats => {
      sendResponse({ success: true, data: stats });
    }).catch(err => {
      console.error("[VerifyFirst] GET_SECURITY_STATISTICS failed:", err);
      sendResponse({ success: false, error: "Security statistics could not be loaded." });
    });
    return true;
  }

  if (message.type === "QUERY_SECURITY_HISTORY") {
    if (message.query && typeof message.query !== "object") {
      sendResponse({ success: false, error: "Invalid security history query." });
      return false;
    }
    querySecurityHistory(message.query || {}).then(events => {
      sendResponse({ success: true, data: events });
    }).catch(err => {
      console.error("[VerifyFirst] QUERY_SECURITY_HISTORY failed:", err);
      sendResponse({ success: false, error: "Security history could not be loaded." });
    });
    return true;
  }

  if (message.type === "EXPORT_SECURITY_HISTORY") {
    exportSecurityHistory().then(jsonStr => {
      sendResponse({ success: true, data: jsonStr });
    }).catch(err => {
      console.error("[VerifyFirst] EXPORT_SECURITY_HISTORY failed:", err);
      sendResponse({ success: false, error: "Security history could not be exported." });
    });
    return true;
  }

  if (message.type === "CLEAR_SECURITY_HISTORY") {
    clearHistory().then(() => {
      sendResponse({ success: true, data: undefined });
    }).catch(err => {
      console.error("[VerifyFirst] CLEAR_SECURITY_HISTORY failed:", err);
      sendResponse({ success: false, error: "Security history could not be cleared." });
    });
    return true;
  }

  if (message.type === "OPEN_SECURITY_CENTER") {
    const targetTabId = tabId !== -1 ? tabId : undefined;
    if (targetTabId !== undefined) {
      chrome.tabs.sendMessage(targetTabId, message).catch(() => {});
    } else {
      chrome.tabs.query({ active: true, currentWindow: true }).then((tabs: any[]) => {
        const activeTabId = tabs[0]?.id;
        if (activeTabId !== undefined) {
          chrome.tabs.sendMessage(activeTabId, message).catch(() => {});
        }
      });
    }
    sendResponse({ success: true });
    return false;
  }

  if (message.type === "OPEN_SECURITY_EVENT") {
    console.log(`[VerifyFirst] OPEN_SECURITY_EVENT received in SW, eventId=${message.eventId}`);
    const targetTabId = tabId !== -1 ? tabId : undefined;
    if (targetTabId !== undefined) {
      chrome.tabs.sendMessage(targetTabId, message).catch(() => {});
    } else {
      chrome.tabs.query({ active: true, currentWindow: true }).then((tabs: any[]) => {
        const activeTabId = tabs[0]?.id;
        if (activeTabId !== undefined) {
          chrome.tabs.sendMessage(activeTabId, message).catch(() => {});
        }
      });
    }
    sendResponse({ success: true });
    return false;
  }

  // Test 5 requirement: Unknown message should respond with success: false
  // However, returning `false` directly means the sender won't get a response at all 
  // if another listener might handle it, but here we're the background script.
  // Wait, if no one calls sendResponse, the sender receives undefined.
  // Let's explicitly reply with success: false for any unhandled message that explicitly expects a response.
  // Actually, we'll just fall through to return false. The test explicitly checks for `success: false`.
  // Wait, if I do `sendResponse({ success: false, error: "Unknown message type." }); return false;`
  sendResponse({ success: false, error: "Unknown message type." });
  return false;
});

console.log("VerifyFirst service worker initialized (Phase 2 Pre-interaction Detection)");

// Open Security Center directly when extension icon is clicked (no popup)
chrome.action.onClicked.addListener(async (tab: any) => {
  // If the active tab is WhatsApp Web, open Security Center there
  if (tab && tab.url && tab.url.includes("web.whatsapp.com") && tab.id !== undefined) {
    console.log(`[VerifyFirst] Icon clicked on WhatsApp tab ${tab.id}, opening Security Center`);
    chrome.tabs.sendMessage(tab.id, { type: "OPEN_SECURITY_CENTER" }).catch(() => {
      // Content script may not be ready, try again after a brief delay
      setTimeout(() => {
        chrome.tabs.sendMessage(tab.id!, { type: "OPEN_SECURITY_CENTER" }).catch(() => {
          console.log("[VerifyFirst] Could not reach content script on WhatsApp tab");
        });
      }, 500);
    });
    return;
  }

  // Not on WhatsApp — find an existing WhatsApp tab and switch to it
  const tabs = await chrome.tabs.query({ url: "https://web.whatsapp.com/*" });
  if (tabs && tabs.length > 0) {
    const waTab = tabs[0];
    console.log(`[VerifyFirst] Icon clicked on non-WhatsApp tab, switching to WhatsApp tab ${waTab.id}`);
    await chrome.tabs.update(waTab.id!, { active: true });
    await chrome.windows.update(waTab.windowId!, { focused: true });
    // Send OPEN_SECURITY_CENTER after the tab is focused
    setTimeout(() => {
      chrome.tabs.sendMessage(waTab.id!, { type: "OPEN_SECURITY_CENTER" }).catch(() => {
        console.log("[VerifyFirst] Could not reach content script after tab switch");
      });
    }, 300);
    return;
  }

  // No WhatsApp tab open — open WhatsApp Web
  console.log("[VerifyFirst] No WhatsApp tab found, opening web.whatsapp.com");
  chrome.tabs.create({ url: "https://web.whatsapp.com" });
});
/**
 * 4D Privacy Hardening: Tab state cleanup
 * Ensure that full message strings/cache states are cleared from 
 * transient local storage mechanisms when the tab closes.
 */
chrome.tabs.onRemoved.addListener((tabId: number) => {
  try {
    const key = `tab_${tabId}`;
    const storage = getStorageArea();
    storage.remove(key);
    
    // Clear in-flight states for this tab
    const prefix = `${tabId}_`;
    
    for (const k of inFlightAnalyses.keys()) {
      if (k.startsWith(prefix)) inFlightAnalyses.delete(k);
    }
    
    for (const k of inFlightFileAnalyses.keys()) {
      if (k.startsWith(prefix)) inFlightFileAnalyses.delete(k);
    }
    
    for (const k of inFlightMessageAnalyses.keys()) {
      if (k.startsWith(prefix)) inFlightMessageAnalyses.delete(k);
    }
    
    console.log(`[VerifyFirst] Cleaned up state and inflight analyses for closed tab ${tabId}`);
  } catch (err) {
    console.error(`[VerifyFirst] Error cleaning up tab ${tabId}:`, err);
  }
});
