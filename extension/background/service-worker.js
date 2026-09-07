"use strict";
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
const BACKEND_API_URL = "http://localhost:8000/api/v1/analyze";
const REQUEST_TIMEOUT_MS = 5000;
/**
 * Storage accessor helper that prefers chrome.storage.session
 * with fallback to chrome.storage.local.
 */
function getStorageArea() {
    if (chrome.storage && chrome.storage.session) {
        return chrome.storage.session;
    }
    return chrome.storage.local;
}
/**
 * Retrieves the current scan state for a specific tab.
 */
async function getTabState(tabId) {
    const key = `tab_${tabId}`;
    const storage = getStorageArea();
    const result = await storage.get(key);
    if (result && result[key]) {
        return result[key];
    }
    return {
        chatId: "",
        generation: 0,
        urls: {},
        lastUpdated: Date.now(),
    };
}
/**
 * Persists the scan state for a specific tab.
 */
async function saveTabState(tabId, state) {
    const key = `tab_${tabId}`;
    const storage = getStorageArea();
    state.lastUpdated = Date.now();
    await storage.set({ [key]: state });
}
/**
 * Resets or updates state when switching chats in a tab.
 */
async function handleChatSwitched(tabId, chatId) {
    const oldState = await getTabState(tabId);
    const newGeneration = (oldState.generation || 0) + 1;
    const state = {
        chatId: chatId,
        generation: newGeneration,
        urls: {},
        lastUpdated: Date.now(),
    };
    await saveTabState(tabId, state);
    console.log(`[VerifyFirst] Chat switched → generation=${newGeneration}, chatId="${chatId}"`);
}
/**
 * Sends a URL to the FastAPI detection backend.
 * Safely handles timeouts, network failures, and invalid responses.
 */
async function requestBackendAnalysis(url) {
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
        if (!data ||
            typeof data.status !== "string" ||
            typeof data.risk_score !== "number" ||
            !Array.isArray(data.reasons)) {
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
            status: data.status,
            risk_score: data.risk_score,
            reasons: data.reasons,
            timestamp: Date.now(),
        };
    }
    catch (error) {
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
/**
 * Handles incoming URL analysis requests from content scripts.
 */
async function handleAnalyzeUrl(tabId, url) {
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
    console.log(`[VerifyFirst] Backend analysis requested: ${trimmed} (generation=${capturedGeneration})`);
    // Request backend analysis
    const record = await requestBackendAnalysis(trimmed);
    console.log(`[VerifyFirst] Backend response: status=${record.status}, risk_score=${record.risk_score}`);
    // Re-fetch to ensure fresh state — check generation to prevent cross-chat contamination
    const freshState = await getTabState(tabId);
    if ((freshState.generation || 0) !== capturedGeneration) {
        // Chat switched during analysis — discard result to prevent leaking into new chat
        console.log(`[VerifyFirst] DISCARDED stale result: generation ${capturedGeneration} → ${freshState.generation}`);
        return record;
    }
    freshState.urls[trimmed] = record;
    await saveTabState(tabId, freshState);
    return record;
}
// Runtime message listener
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message || typeof message.type !== "string") {
        return false;
    }
    const tabId = sender.tab?.id ?? -1;
    if (message.type === "ANALYZE_URL") {
        if (tabId === -1) {
            sendResponse({ error: "Unknown tab sender" });
            return false;
        }
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
                console.log(`[VerifyFirst] Sending ANALYSIS_RESULT to tab ${tabId}: status=${record.status}`);
                chrome.tabs.sendMessage(tabId, {
                    type: "ANALYSIS_RESULT",
                    record: record,
                    chatId: message.chatId,
                }).catch((pushErr) => {
                    console.log(`[VerifyFirst] tabs.sendMessage caught: ${pushErr?.message || pushErr}`);
                });
            }
            catch (pushErr) {
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
    if (message.type === "TRIGGER_SCAN") {
        // Forward scan trigger to the active tab's content script
        chrome.tabs.query({ active: true, currentWindow: true }).then((tabs) => {
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
                chrome.tabs.query({ active: true, currentWindow: true }).then((tabs) => {
                    const activeTabId = tabs[0]?.id ?? -1;
                    if (activeTabId !== -1) {
                        getTabState(activeTabId).then((state) => {
                            sendResponse({ success: true, state });
                        });
                    }
                    else {
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
    return false;
});
console.log("VerifyFirst service worker initialized (Phase 2 Pre-interaction Detection)");
