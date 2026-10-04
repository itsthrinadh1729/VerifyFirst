"use strict";
(function () {
    let currentChatId = "";
    const discoveredUrls = new Set();
    let currentChatRecords = {};
    // Phase 2: File discovery state (parallel to URL state)
    const discoveredFiles = new Set();
    let currentFileRecords = {};
    // Phase 3G: Message discovery state
    const discoveredMessages = new Set();
    let currentMessageRecords = {};
    console.log("[VerifyFirst] Scanner loaded");
    let scanDebounceTimer = null;
    let observerInstance = null;
    let bodyObserver = null;
    let currentObservedContainer = null;
    let extensionContextInvalid = false;
    const WHATSAPP_INTERNAL_DOMAINS = [
        "whatsapp.com",
        "web.whatsapp.com",
        "faq.whatsapp.com",
        "api.whatsapp.com",
        "v.whatsapp.net",
        "wa.me",
        "whatsapp.net",
        "dyn.web.whatsapp.com",
    ];
    function shutdownScanner() {
        extensionContextInvalid = true;
        if (scanDebounceTimer !== null) {
            window.clearTimeout(scanDebounceTimer);
            scanDebounceTimer = null;
        }
        if (observerInstance) {
            observerInstance.disconnect();
            observerInstance = null;
        }
        if (bodyObserver) {
            bodyObserver.disconnect();
            bodyObserver = null;
        }
    }
    /**
     * Validates if the extension context is still valid.
     * Shuts down scanning silently if extension context was invalidated.
     */
    function isContextValid() {
        if (extensionContextInvalid) {
            return false;
        }
        try {
            const isValid = typeof chrome !== "undefined" && typeof chrome.runtime !== "undefined" && Boolean(chrome.runtime?.id);
            if (!isValid) {
                shutdownScanner();
                return false;
            }
            return true;
        }
        catch {
            shutdownScanner();
            return false;
        }
    }
    /**
     * Safely dispatches runtime messages, catching context invalidation errors.
     */
    function safeSendMessage(message, callback) {
        if (extensionContextInvalid || !isContextValid()) {
            return;
        }
        try {
            chrome.runtime.sendMessage(message, (response) => {
                if (extensionContextInvalid || !isContextValid()) {
                    return;
                }
                // Safely check runtime error signals
                try {
                    const lastErr = chrome.runtime.lastError;
                    if (lastErr) {
                        const errMsg = lastErr.message || "";
                        if (errMsg.includes("Extension context invalidated")) {
                            shutdownScanner();
                            return;
                        }
                    }
                }
                catch {
                    shutdownScanner();
                    return;
                }
                if (callback && response) {
                    try {
                        callback(response);
                    }
                    catch (callbackErr) {
                        // Log callback errors to aid debugging
                        console.log(`[VerifyFirst] Callback error:`, callbackErr);
                    }
                }
                else if (callback && !response) {
                    console.log(`[VerifyFirst] safeSendMessage: callback exists but response is falsy`, response);
                }
            });
        }
        catch (err) {
            const errMsg = err?.message || String(err);
            if (errMsg.includes("Extension context invalidated") || !isContextValid()) {
                shutdownScanner();
            }
        }
    }
    /**
     * Identifies the current chat container in the DOM.
     * WhatsApp Web typically uses '#main' for the open conversation pane,
     * or a main region containing message bubbles.
     */
    function getActiveChatContainer() {
        const mainPane = document.getElementById("main");
        if (mainPane) {
            return mainPane;
        }
        const conversationRegion = document.querySelector('[data-testid="conversation-panel-wrapper"], [data-testid="conversation-panel-body"], [role="main"], [data-testid="chat-panel"], .copyable-area, [role="region"][aria-label*="Chat"]');
        if (conversationRegion) {
            return conversationRegion;
        }
        return null;
    }
    /**
     * Checks if a string extracted from the header is an action button or dynamic status text.
     */
    function isIgnoredHeaderString(text) {
        if (!text)
            return true;
        const lower = text.toLowerCase();
        return (lower.includes("search") ||
            lower.includes("menu") ||
            lower.includes("call") ||
            lower.includes("attach") ||
            lower.includes("online") ||
            lower.includes("typing") ||
            lower.includes("last seen") ||
            lower.includes("click here") ||
            lower.includes("tap here") ||
            lower.includes("profile details"));
    }
    /**
     * Attempts to extract the contact or group title from the active chat header.
     */
    function extractHeaderContactTitle(chatContainer) {
        // Strategy 1: WhatsApp data-testid based chat title (most stable)
        const testIdTitle = chatContainer.querySelector('[data-testid="conversation-info-header-chat-title"]');
        if (testIdTitle) {
            const title = testIdTitle.getAttribute("title") || testIdTitle.textContent || "";
            if (title.trim()) {
                return title.trim();
            }
        }
        // Strategy 2: Header clickable contact info span with title and dir="auto"
        const headerTitleSpan = chatContainer.querySelector('header div[role="button"] span[title][dir="auto"], header div[role="button"] span[title]');
        if (headerTitleSpan) {
            const title = headerTitleSpan.getAttribute("title") || headerTitleSpan.textContent || "";
            if (title.trim() && !isIgnoredHeaderString(title.trim())) {
                return title.trim();
            }
        }
        // Strategy 3: Header span with BOTH title attr and dir="auto" (specific to contact name)
        const nameSpan = chatContainer.querySelector('header span[title][dir="auto"]');
        if (nameSpan) {
            const title = nameSpan.getAttribute("title") || nameSpan.textContent || "";
            if (title.trim() && !isIgnoredHeaderString(title.trim())) {
                return title.trim();
            }
        }
        // Strategy 4: First span[dir="auto"] inside header (contact name span in modern WhatsApp Web)
        const dirAutoSpans = chatContainer.querySelectorAll('header span[dir="auto"]');
        for (let i = 0; i < dirAutoSpans.length; i++) {
            const span = dirAutoSpans[i];
            const title = span.getAttribute("title") || span.textContent || "";
            if (title.trim() && !isIgnoredHeaderString(title.trim())) {
                return title.trim();
            }
        }
        // Strategy 5: Header first title span inside info column (excluding buttons)
        const infoColTitle = chatContainer.querySelector('header > div:nth-child(2) span[title], header ._amig span[title]');
        if (infoColTitle) {
            const title = infoColTitle.getAttribute("title") || infoColTitle.textContent || "";
            if (title.trim() && !isIgnoredHeaderString(title.trim())) {
                return title.trim();
            }
        }
        return "";
    }
    /**
     * Retrieves a lightweight, STABLE identifier for the active chat
     * to detect conversation switches. Never transmits this identifier externally.
     *
     * CRITICAL: This must return the SAME value for the same chat across repeated calls.
     * - If header is temporarily unavailable: KEEP currentChatId
     * - If header appears with same contact: KEEP currentChatId
     * - If header appears with different contact: NEW currentChatId
     */
    function getActiveChatIdentifier() {
        const chatContainer = getActiveChatContainer();
        if (!chatContainer) {
            return "";
        }
        const title = extractHeaderContactTitle(chatContainer);
        if (title) {
            return title;
        }
        // If header is temporarily unavailable during DOM mounting/re-rendering
        // and we already established a currentChatId for this chat container, retain it
        if (currentChatId) {
            return currentChatId;
        }
        // Fallback constant for initial scan before header renders
        return "active_chat";
    }
    /**
     * Validates if a URL is a legitimate external candidate for analysis.
     */
    function isCandidateUrl(rawUrl) {
        if (!rawUrl || typeof rawUrl !== "string") {
            return false;
        }
        const trimmed = rawUrl.trim();
        if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
            return false;
        }
        if (trimmed.length > 2048) {
            return false;
        }
        try {
            const parsed = new URL(trimmed);
            const hostname = parsed.hostname.toLowerCase();
            // Filter out internal WhatsApp domains
            for (const domain of WHATSAPP_INTERNAL_DOMAINS) {
                if (hostname === domain || hostname.endsWith("." + domain)) {
                    return false;
                }
            }
            return true;
        }
        catch {
            return false;
        }
    }
    /**
     * Extracts the actual URL from a WhatsApp redirect/wrapper href.
     * WhatsApp sometimes wraps user URLs in its own redirect links.
     */
    function resolveWhatsAppRedirect(href) {
        try {
            const parsed = new URL(href);
            const hostname = parsed.hostname.toLowerCase();
            // WhatsApp redirect domains
            if (hostname === "l.whatsapp.com" || hostname === "web.whatsapp.com") {
                const actualUrl = parsed.searchParams.get("url") || parsed.searchParams.get("u");
                if (actualUrl) {
                    return decodeURIComponent(actualUrl);
                }
            }
        }
        catch {
            // Not a valid URL, return as-is
        }
        return href;
    }
    /**
     * URL pattern for extracting URLs from visible text content.
     * Matches http:// and https:// URLs, stopping at whitespace or common delimiters.
     */
    const URL_TEXT_PATTERN = /https?:\/\/[^\s<>"'\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF\u00A0]+/gi;
    /**
     * Discovers URLs in the active chat container using multiple strategies:
     * 1. Standard <a href> extraction
     * 2. WhatsApp redirect URL resolution
     * 3. Text-based URL extraction from message spans (for un-linkified URLs)
     */
    function cleanUrlString(raw) {
        // 1. Remove invisible Unicode formatting characters (defense-in-depth)
        let urlStr = raw.replace(/[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF\u00A0]/g, "");
        // 2. Remove leading/trailing parenthesis
        urlStr = urlStr.replace(/^[)\](]+/, "");
        while (/[.,;:!?\)\]\(\[]+$/.test(urlStr)) {
            const lastChar = urlStr.slice(-1);
            if (lastChar === ')') {
                const openCount = (urlStr.match(/\(/g) || []).length;
                const closeCount = (urlStr.match(/\)/g) || []).length;
                if (openCount >= closeCount)
                    break;
            }
            else if (lastChar === ']') {
                const openCount = (urlStr.match(/\[/g) || []).length;
                const closeCount = (urlStr.match(/\]/g) || []).length;
                if (openCount >= closeCount)
                    break;
            }
            urlStr = urlStr.slice(0, -1);
        }
        // 3. Remove trailing timestamp patterns like 7:08 or 11:48 AM/PM that might be attached without spaces
        urlStr = urlStr.replace(/\d{1,2}:\d{2}(?:\s*(?:AM|PM|am|pm))?$/, "");
        return urlStr;
    }
    function processExtractedString(rawStr) {
        const cleaned = cleanUrlString(rawStr);
        if (isCandidateUrl(cleaned)) {
            try {
                new URL(cleaned);
                return cleaned;
            }
            catch {
                return null;
            }
        }
        return null;
    }
    function discoverUrlsInContainer(chatContainer) {
        const found = [];
        const seen = new Set();
        const rejectedAnchors = new Set();
        const messageArea = chatContainer.querySelector('[data-testid="conversation-panel-messages"]') ||
            chatContainer.querySelector('[data-testid="conversation-panel-body"]') ||
            chatContainer.querySelector('[role="application"]') ||
            chatContainer;
        // ── Pass 1: Extract from <a href> elements ──
        const anchors = messageArea.querySelectorAll("a[href]");
        anchors.forEach((el) => {
            let href = el.getAttribute("href") || "";
            href = resolveWhatsAppRedirect(href);
            const canonicalUrl = processExtractedString(href);
            if (canonicalUrl) {
                if (!seen.has(canonicalUrl)) {
                    seen.add(canonicalUrl);
                    found.push(canonicalUrl);
                }
            }
            else {
                // Fallback: anchor is malformed or not a candidate, allow Pass 2 to scan its text
                rejectedAnchors.add(el);
            }
        });
        // ── Pass 2: Extract URLs from raw text nodes ──
        const treeWalker = document.createTreeWalker(messageArea, NodeFilter.SHOW_TEXT, {
            acceptNode: (node) => {
                const text = node.nodeValue || "";
                const lowerText = text.toLowerCase();
                if (!lowerText.includes("http://") && !lowerText.includes("https://")) {
                    return NodeFilter.FILTER_SKIP;
                }
                const parent = node.parentElement;
                if (!parent)
                    return NodeFilter.FILTER_SKIP;
                const closestAnchor = parent.closest("a[href]");
                if (closestAnchor && !rejectedAnchors.has(closestAnchor)) {
                    return NodeFilter.FILTER_SKIP;
                }
                // Structural exclusions (do NOT filter role="button" as WhatsApp uses it for clickable message bubbles)
                if (parent.closest("header, footer, [role='menuitem'], script, style, noscript, [hidden], [aria-hidden='true']")) {
                    return NodeFilter.FILTER_SKIP;
                }
                return NodeFilter.FILTER_ACCEPT;
            }
        });
        let currentNode;
        while ((currentNode = treeWalker.nextNode())) {
            const text = currentNode.nodeValue || "";
            URL_TEXT_PATTERN.lastIndex = 0;
            let match;
            while ((match = URL_TEXT_PATTERN.exec(text)) !== null) {
                // Split concatenated URLs (e.g., URL1)(URL2)
                const spaced = match[0].replace(/([)\](]+)(https?:\/\/)/gi, "$1 $2");
                const pieces = spaced.split(" ");
                for (let piece of pieces) {
                    const canonicalUrl = processExtractedString(piece);
                    if (canonicalUrl) {
                        if (!seen.has(canonicalUrl)) {
                            seen.add(canonicalUrl);
                            found.push(canonicalUrl);
                        }
                    }
                }
            }
        }
        // ── Pass 3: Extract from visible text of actual message bubbles (Fallback) ──
        const messageBubbles = messageArea.querySelectorAll('.copyable-text, [data-testid="msg-container"]');
        messageBubbles.forEach((bubble) => {
            // Avoid scanning headers, footers, sidebars that might accidentally match the generic selector
            if (bubble.closest("header, footer, [role='menuitem'], [aria-hidden='true']"))
                return;
            console.log("[VerifyFirst Source3] message bubble inspected");
            let text = bubble.innerText;
            if (typeof text !== "string") {
                // Fallback for JSDOM testing. Avoid cloneNode(true) to prevent 403 errors on WhatsApp media requests.
                text = bubble.textContent || "";
            }
            if (!text.toLowerCase().includes("http://") && !text.toLowerCase().includes("https://"))
                return;
            URL_TEXT_PATTERN.lastIndex = 0;
            let match;
            while ((match = URL_TEXT_PATTERN.exec(text)) !== null) {
                console.log("[VerifyFirst Source3] URL candidate found");
                const spaced = match[0].replace(/([^\s])(https?:\/\/)/gi, "$1 $2");
                const pieces = spaced.split(" ");
                for (let piece of pieces) {
                    const canonicalUrl = processExtractedString(piece);
                    if (canonicalUrl) {
                        console.log("[VerifyFirst Source3] candidate accepted");
                        if (!seen.has(canonicalUrl)) {
                            console.log("[VerifyFirst Source3] candidate added");
                            seen.add(canonicalUrl);
                            found.push(canonicalUrl);
                        }
                    }
                }
            }
        });
        return found;
    }
    // ── Phase 2: File/Attachment Discovery ──────────────────────────────────
    /**
     * Extracts the filename from a WhatsApp document message element.
     * Uses a three-level fallback chain for resilience against DOM changes.
     */
    function extractFilenameFromDocument(msgDoc) {
        // Strategy 1: data-testid="document-title" (most stable)
        const titleEl = msgDoc.querySelector('[data-testid="document-title"]');
        if (titleEl && titleEl.textContent && titleEl.textContent.trim()) {
            return titleEl.textContent.trim();
        }
        // Strategy 2: span with title attribute (fallback)
        const titleSpan = msgDoc.querySelector('span[title]');
        if (titleSpan) {
            const title = titleSpan.getAttribute("title");
            if (title && title.trim()) {
                return title.trim();
            }
        }
        // Strategy 3: first span[dir="auto"] (common WhatsApp text pattern)
        const dirAutoSpan = msgDoc.querySelector('span[dir="auto"]');
        if (dirAutoSpan && dirAutoSpan.textContent && dirAutoSpan.textContent.trim()) {
            return dirAutoSpan.textContent.trim();
        }
        return null;
    }
    /**
     * Discovers document/file attachments in the active chat container.
     * Only scans [data-testid="msg-document"] elements — images, videos,
     * audio, stickers, and other media types are explicitly excluded.
     */
    function discoverFilesInContainer(chatContainer) {
        const found = [];
        const seen = new Set();
        const messageArea = chatContainer.querySelector('[data-testid="conversation-panel-messages"]') ||
            chatContainer.querySelector('[data-testid="conversation-panel-body"]') ||
            chatContainer.querySelector('[role="application"]') ||
            chatContainer;
        // Only target document attachment messages
        const documentMessages = messageArea.querySelectorAll('[data-testid="msg-document"]');
        documentMessages.forEach((msgDoc) => {
            const filename = extractFilenameFromDocument(msgDoc);
            if (filename && !seen.has(filename)) {
                seen.add(filename);
                found.push(filename);
            }
        });
        return found;
    }
    // ── Phase 3G: Message Discovery ─────────────────────────────────────────
    const MAX_MESSAGE_LENGTH = 4000;
    function normalizeMessageText(text) {
        return text.replace(/\s+/g, " ").trim();
    }
    function discoverMessagesInContainer(chatContainer) {
        const found = [];
        const seen = new Set();
        const messageArea = chatContainer.querySelector('[data-testid="conversation-panel-messages"]') ||
            chatContainer.querySelector('[data-testid="conversation-panel-body"]') ||
            chatContainer.querySelector('[role="application"]') ||
            chatContainer;
        // Target incoming messages specifically and find the text span
        const messageBubbles = messageArea.querySelectorAll('.message-in .selectable-text');
        messageBubbles.forEach((bubble) => {
            // Avoid scanning headers, footers, sidebars
            if (bubble.closest("header, footer, [role='menuitem'], [aria-hidden='true']"))
                return;
            let text = bubble.innerText;
            if (typeof text !== "string") {
                // Fallback for JSDOM testing. Avoid cloneNode(true) to prevent 403 errors on WhatsApp media requests.
                text = bubble.textContent || "";
            }
            const normalized = normalizeMessageText(text);
            if (!normalized)
                return;
            const message = normalized.slice(0, MAX_MESSAGE_LENGTH);
            if (!seen.has(message)) {
                seen.add(message);
                found.push(message);
            }
        });
        return found;
    }
    /**
     * Schedules a single delayed scan for catching async-rendered messages.
     */
    function scheduleDelayedScan(delayMs) {
        if (extensionContextInvalid)
            return;
        window.setTimeout(() => {
            if (!extensionContextInvalid && isContextValid()) {
                scanActiveChatForUrls(false);
            }
        }, delayMs);
    }
    /**
     * Scans the active conversation container for new external links.
     */
    function scanActiveChatForUrls(isImmediate = false) {
        if (extensionContextInvalid || !isContextValid()) {
            shutdownScanner();
            return;
        }
        const chatContainer = getActiveChatContainer();
        if (!chatContainer) {
            // If no chat is open, reset chat ID
            if (currentChatId) {
                console.log("[VerifyFirst] No chat container found, resetting state");
                currentChatId = "";
                discoveredUrls.clear();
                currentChatRecords = {};
                discoveredFiles.clear();
                currentFileRecords = {};
                discoveredMessages.clear();
                currentMessageRecords = {};
                if (typeof window !== "undefined" && window.VerifyFirstOverlay) {
                    window.VerifyFirstOverlay.resetDisplayedWarnings();
                }
                safeSendMessage({
                    type: "CHAT_SWITCHED",
                    chatId: "",
                });
            }
            return;
        }
        // Check if the user switched to a different conversation
        const activeChatId = getActiveChatIdentifier();
        if (activeChatId !== currentChatId) {
            console.log(`[VerifyFirst] Chat switch detected: "${currentChatId}" → "${activeChatId}"`);
            currentChatId = activeChatId;
            discoveredUrls.clear();
            currentChatRecords = {};
            discoveredFiles.clear();
            currentFileRecords = {};
            discoveredMessages.clear();
            currentMessageRecords = {};
            if (typeof window !== "undefined" && window.VerifyFirstOverlay) {
                window.VerifyFirstOverlay.resetDisplayedWarnings();
            }
            safeSendMessage({
                type: "CHAT_SWITCHED",
                chatId: activeChatId,
            });
            // Schedule retry scans — WhatsApp renders messages asynchronously
            scheduleDelayedScan(500);
            scheduleDelayedScan(1500);
        }
        // Discover URLs using multi-pass extraction
        const allUrls = discoverUrlsInContainer(chatContainer);
        if (isImmediate) {
            console.log(`[VerifyFirst Lifecycle] immediate scan completed: ${allUrls.length} URLs`);
        }
        const newCandidates = [];
        for (const normalized of allUrls) {
            if (!discoveredUrls.has(normalized)) {
                discoveredUrls.add(normalized);
                newCandidates.push(normalized);
                console.log("[VerifyFirst Lifecycle] candidate discovered");
            }
        }
        // Send newly discovered URLs to background service worker
        if (newCandidates.length > 0) {
            for (const url of newCandidates) {
                // Capture current chat context before sending async request
                const requestChatId = currentChatId;
                console.log(`[VerifyFirst] ANALYZE_URL sent for candidate link.`);
                console.log(`[VerifyFirst Lifecycle] ANALYZE_URL dispatched`);
                console.log(`[VerifyFirst Source3] ANALYZE_URL dispatched`);
                safeSendMessage({
                    type: "ANALYZE_URL",
                    url: url,
                    chatId: requestChatId,
                }, (response) => {
                    console.log(`[VerifyFirst] ANALYZE_URL callback for ${url}:`, response);
                    console.log("[VerifyFirst] ANALYSIS_RESULT received", response);
                    if (!response || !response.success || !response.record) {
                        console.log(`[VerifyFirst] Callback dropped: invalid response`);
                        return;
                    }
                    // 1. Result belongs to current scan/chat generation
                    if (!requestChatId || currentChatId !== requestChatId) {
                        console.log(`[VerifyFirst] Callback dropped: chat mismatch (${requestChatId} vs ${currentChatId})`);
                        return;
                    }
                    // 2. URL belongs to current discovered URL set
                    if (!discoveredUrls.has(response.record.url)) {
                        console.log(`[VerifyFirst] Callback dropped: URL not in discoveredUrls (${response.record.url})`);
                        return;
                    }
                    // 3. Result has not already been rendered in this chat session
                    if (currentChatRecords[response.record.url] && currentChatRecords[response.record.url].status !== "SAFE") {
                        return;
                    }
                    // Store record for current chat
                    currentChatRecords[response.record.url] = response.record;
                    // Trigger automatic warning for non-SAFE results
                    if (response.record.status !== "SAFE") {
                        if (typeof window !== "undefined" && window.VerifyFirstOverlay) {
                            try {
                                console.log("[VerifyFirst] Calling showOverlay");
                                window.VerifyFirstOverlay.showVerifyFirstWarning(response.record, Object.values(currentChatRecords));
                            }
                            catch (e) {
                                console.error(`[VerifyFirst] Error displaying overlay: ${e?.message || e}`);
                            }
                        }
                    }
                });
            }
        }
        // ── Phase 2: File discovery and dispatch ──
        const allFiles = discoverFilesInContainer(chatContainer);
        const newFileCandidates = [];
        for (const filename of allFiles) {
            if (!discoveredFiles.has(filename)) {
                discoveredFiles.add(filename);
                newFileCandidates.push(filename);
                console.log(`[VerifyFirst] File candidate discovered: ${filename}`);
            }
        }
        if (newFileCandidates.length > 0) {
            for (const filename of newFileCandidates) {
                const requestChatId = currentChatId;
                console.log(`[VerifyFirst] ANALYZE_FILE sent for: ${filename}`);
                safeSendMessage({
                    type: "ANALYZE_FILE",
                    filename: filename,
                    chatId: requestChatId,
                }, (response) => {
                    if (!response || !response.success || !response.record) {
                        return;
                    }
                    // Chat isolation check
                    if (!requestChatId || currentChatId !== requestChatId) {
                        return;
                    }
                    // File dedup check
                    if (!discoveredFiles.has(response.record.filename)) {
                        return;
                    }
                    // Already rendered check
                    if (currentFileRecords[response.record.filename] && currentFileRecords[response.record.filename].status !== "SAFE") {
                        return;
                    }
                    // Store record
                    currentFileRecords[response.record.filename] = response.record;
                    // Trigger warning for non-SAFE results
                    if (response.record.status !== "SAFE") {
                        if (typeof window !== "undefined" && window.VerifyFirstOverlay) {
                            try {
                                // Build a file-aware overlay record
                                const fileOverlayRecord = {
                                    url: response.record.filename,
                                    status: response.record.status,
                                    risk_score: response.record.risk_score,
                                    reasons: response.record.reasons || [],
                                    timestamp: response.record.timestamp,
                                    eventId: response.record.eventId,
                                    assetType: "file",
                                    filename: response.record.filename,
                                };
                                const allRecords = [
                                    ...Object.values(currentChatRecords),
                                    ...Object.values(currentFileRecords).map((r) => ({
                                        url: r.filename,
                                        status: r.status,
                                        risk_score: r.risk_score,
                                        reasons: r.reasons || [],
                                        timestamp: r.timestamp,
                                        eventId: r.eventId,
                                        assetType: "file",
                                        filename: r.filename,
                                    })),
                                ];
                                window.VerifyFirstOverlay.showVerifyFirstWarning(fileOverlayRecord, allRecords);
                            }
                            catch (e) {
                                console.error(`[VerifyFirst] Error displaying file overlay: ${e?.message || e}`);
                            }
                        }
                    }
                });
            }
        }
        // ── Phase 3G: Message discovery and dispatch ──
        const allMessages = discoverMessagesInContainer(chatContainer);
        const newMessageCandidates = [];
        for (const message of allMessages) {
            if (!discoveredMessages.has(message)) {
                discoveredMessages.add(message);
                newMessageCandidates.push(message);
                console.log(`[VerifyFirst] Message candidate discovered`);
            }
        }
        if (newMessageCandidates.length > 0) {
            for (const message of newMessageCandidates) {
                const requestChatId = currentChatId;
                console.log(`[VerifyFirst] ANALYZE_MESSAGE sent`);
                safeSendMessage({
                    type: "ANALYZE_MESSAGE",
                    message: message,
                    chatId: requestChatId,
                }, (response) => {
                    if (!response || !response.success || !response.record) {
                        return;
                    }
                    if (!requestChatId || currentChatId !== requestChatId) {
                        return;
                    }
                    if (!discoveredMessages.has(response.record.message)) {
                        return;
                    }
                    if (currentMessageRecords[response.record.message] && currentMessageRecords[response.record.message].status !== "SAFE") {
                        return;
                    }
                    currentMessageRecords[response.record.message] = response.record;
                    if (response.record.status !== "SAFE") {
                        if (typeof window !== "undefined" && window.VerifyFirstOverlay) {
                            try {
                                const messageOverlayRecord = {
                                    url: response.record.message,
                                    status: response.record.status,
                                    risk_score: response.record.risk_score,
                                    reasons: response.record.reasons || [],
                                    timestamp: response.record.timestamp,
                                    eventId: response.record.eventId,
                                    assetType: "message",
                                    messagePreview: response.record.messagePreview || response.record.message.slice(0, 100),
                                };
                                const allRecords = [
                                    ...Object.values(currentChatRecords),
                                    ...Object.values(currentFileRecords).map((r) => ({
                                        url: r.filename,
                                        status: r.status,
                                        risk_score: r.risk_score,
                                        reasons: r.reasons || [],
                                        timestamp: r.timestamp,
                                        eventId: r.eventId,
                                        assetType: "file",
                                        filename: r.filename,
                                    })),
                                    ...Object.values(currentMessageRecords).map((r) => ({
                                        url: r.message,
                                        status: r.status,
                                        risk_score: r.risk_score,
                                        reasons: r.reasons || [],
                                        timestamp: r.timestamp,
                                        eventId: r.eventId,
                                        assetType: "message",
                                        messagePreview: r.messagePreview || r.message.slice(0, 100),
                                    })),
                                ];
                                window.VerifyFirstOverlay.showVerifyFirstWarning(messageOverlayRecord, allRecords);
                            }
                            catch (e) {
                                console.error(`[VerifyFirst] Error displaying message overlay: ${e?.message || e}`);
                            }
                        }
                    }
                });
            }
        }
    }
    /**
     * Central handler for analysis results pushed from the service worker.
     * This is the PRIMARY trigger for the automatic in-page warning overlay.
     */
    function handleAnalysisResult(record, resultChatId) {
        console.log(`[VerifyFirst] handleAnalysisResult called for ${record?.url} (chat: ${resultChatId})`);
        if (!record || !record.url || !record.status) {
            console.log(`[VerifyFirst] handleAnalysisResult dropped: invalid record`);
            return;
        }
        // 1. Result belongs to current scan/chat generation
        if (!resultChatId || resultChatId !== currentChatId) {
            console.log(`[VerifyFirst] handleAnalysisResult dropped: chat mismatch (${resultChatId} vs ${currentChatId})`);
            return;
        }
        // 2. URL belongs to current discovered URL set
        if (!discoveredUrls.has(record.url)) {
            console.log(`[VerifyFirst] handleAnalysisResult dropped: URL not in discoveredUrls (${record.url})`);
            return;
        }
        // 3. Result has not already been rendered in this chat session
        if (currentChatRecords[record.url] && currentChatRecords[record.url].status !== "SAFE") {
            console.log(`[VerifyFirst] handleAnalysisResult dropped: already rendered`);
            return;
        }
        // Store in current chat records (single source of truth for Security Center)
        currentChatRecords[record.url] = record;
        // SAFE links remain silent
        if (record.status === "SAFE") {
            return;
        }
        // Trigger automatic warning for SUSPICIOUS, DANGEROUS, ANALYSIS_UNAVAILABLE
        if (typeof window !== "undefined" && window.VerifyFirstOverlay) {
            try {
                console.log("[VerifyFirst] Calling showOverlay");
                window.VerifyFirstOverlay.showVerifyFirstWarning(record, Object.values(currentChatRecords));
            }
            catch (e) {
                console.error(`[VerifyFirst] Error displaying overlay: ${e?.message || e}`);
            }
        }
    }
    /**
     * Handler for file analysis results pushed from the service worker.
     */
    function handleFileAnalysisResult(record, resultChatId) {
        console.log(`[VerifyFirst] handleFileAnalysisResult called for ${record?.filename} (chat: ${resultChatId})`);
        if (!record || !record.filename || !record.status) {
            return;
        }
        if (!resultChatId || resultChatId !== currentChatId) {
            return;
        }
        if (!discoveredFiles.has(record.filename)) {
            return;
        }
        if (currentFileRecords[record.filename] && currentFileRecords[record.filename].status !== "SAFE") {
            return;
        }
        currentFileRecords[record.filename] = record;
        if (record.status === "SAFE") {
            return;
        }
        if (typeof window !== "undefined" && window.VerifyFirstOverlay) {
            try {
                const fileOverlayRecord = {
                    url: record.filename,
                    status: record.status,
                    risk_score: record.risk_score,
                    reasons: record.reasons || [],
                    timestamp: record.timestamp,
                    eventId: record.eventId,
                    assetType: "file",
                    filename: record.filename,
                };
                const allRecords = [
                    ...Object.values(currentChatRecords),
                    ...Object.values(currentFileRecords).map((r) => ({
                        url: r.filename,
                        status: r.status,
                        risk_score: r.risk_score,
                        reasons: r.reasons || [],
                        timestamp: r.timestamp,
                        eventId: r.eventId,
                        assetType: "file",
                        filename: r.filename,
                    })),
                ];
                window.VerifyFirstOverlay.showVerifyFirstWarning(fileOverlayRecord, allRecords);
            }
            catch (e) {
                console.error(`[VerifyFirst] Error displaying file overlay: ${e?.message || e}`);
            }
        }
    }
    /**
     * Handler for message analysis results pushed from the service worker.
     */
    function handleMessageAnalysisResult(record, resultChatId) {
        console.log(`[VerifyFirst] handleMessageAnalysisResult called (chat: ${resultChatId})`);
        if (!record || !record.message || !record.status) {
            return;
        }
        if (!resultChatId || resultChatId !== currentChatId) {
            return;
        }
        if (!discoveredMessages.has(record.message)) {
            return;
        }
        if (currentMessageRecords[record.message] && currentMessageRecords[record.message].status !== "SAFE") {
            return;
        }
        currentMessageRecords[record.message] = record;
        if (record.status === "SAFE") {
            return;
        }
        if (typeof window !== "undefined" && window.VerifyFirstOverlay) {
            try {
                const messageOverlayRecord = {
                    url: record.message,
                    status: record.status,
                    risk_score: record.risk_score,
                    reasons: record.reasons || [],
                    timestamp: record.timestamp,
                    eventId: record.eventId,
                    assetType: "message",
                    messagePreview: record.messagePreview || record.message.slice(0, 100),
                };
                const allRecords = [
                    ...Object.values(currentChatRecords),
                    ...Object.values(currentFileRecords).map((r) => ({
                        url: r.filename,
                        status: r.status,
                        risk_score: r.risk_score,
                        reasons: r.reasons || [],
                        timestamp: r.timestamp,
                        eventId: r.eventId,
                        assetType: "file",
                        filename: r.filename,
                    })),
                    ...Object.values(currentMessageRecords).map((r) => ({
                        url: r.message,
                        status: r.status,
                        risk_score: r.risk_score,
                        reasons: r.reasons || [],
                        timestamp: r.timestamp,
                        eventId: r.eventId,
                        assetType: "message",
                        messagePreview: r.messagePreview || r.message.slice(0, 100),
                    })),
                ];
                window.VerifyFirstOverlay.showVerifyFirstWarning(messageOverlayRecord, allRecords);
            }
            catch (e) {
                console.error(`[VerifyFirst] Error displaying message overlay: ${e?.message || e}`);
            }
        }
    }
    /**
     * Listen for ANALYSIS_RESULT messages pushed from the service worker.
     * This two-way delivery mechanism is more reliable than relying solely
     * on the sendResponse callback of the original ANALYZE_URL request.
     */
    if (!extensionContextInvalid && isContextValid()) {
        try {
            chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
                if (extensionContextInvalid || !isContextValid()) {
                    return false;
                }
                if (message && message.type === "ANALYSIS_RESULT" && message.record) {
                    console.log("[VerifyFirst] ANALYSIS_RESULT received", message);
                    handleAnalysisResult(message.record, message.chatId);
                    sendResponse({ received: true });
                    return false;
                }
                if (message && message.type === "FILE_ANALYSIS_RESULT" && message.record) {
                    handleFileAnalysisResult(message.record, message.chatId);
                    sendResponse({ received: true });
                    return false;
                }
                if (message && message.type === "MESSAGE_ANALYSIS_RESULT" && message.record) {
                    handleMessageAnalysisResult(message.record, message.chatId);
                    sendResponse({ received: true });
                    return false;
                }
                if (message && message.type === "TRIGGER_SCAN") {
                    console.log("[VerifyFirst] TRIGGER_SCAN received from Security Center");
                    scanActiveChatForUrls(false);
                    sendResponse({ triggered: true });
                    return false;
                }
                if (message && message.type === "GET_CURRENT_CHAT_STATE") {
                    console.log(`[VerifyFirst] Popup requested current chat state`);
                    const urlCount = Object.keys(currentChatRecords).length;
                    console.log(`[VerifyFirst] Returning current chat state: "${currentChatId}", ${urlCount} URLs`);
                    sendResponse({
                        chatId: currentChatId,
                        urls: currentChatRecords,
                    });
                    return false;
                }
                if (message && message.type === "CLOSE_VERIFYFIRST_OVERLAY") {
                    console.log(`[VerifyFirst] CLOSE_VERIFYFIRST_OVERLAY received`);
                    if (typeof window.VerifyFirstOverlay?.hideVerifyFirstOverlay === "function") {
                        window.VerifyFirstOverlay.hideVerifyFirstOverlay();
                    }
                    else if (typeof window.VerifyFirstOverlay?.clearVerifyFirstOverlay === "function") {
                        window.VerifyFirstOverlay.clearVerifyFirstOverlay();
                    }
                    sendResponse({ closed: true });
                    return false;
                }
                // Don't return false for unrecognized messages — let other listeners handle them
            });
            console.log("[VerifyFirst] ANALYSIS_RESULT listener registered");
        }
        catch (listenerErr) {
            console.log(`[VerifyFirst] Failed to register ANALYSIS_RESULT listener: ${listenerErr?.message}`);
        }
    }
    /**
     * Debounced scan trigger on DOM changes.
     */
    function scheduleScan() {
        if (extensionContextInvalid || !isContextValid()) {
            shutdownScanner();
            return;
        }
        if (scanDebounceTimer !== null) {
            window.clearTimeout(scanDebounceTimer);
        }
        scanDebounceTimer = window.setTimeout(() => {
            scanDebounceTimer = null;
            console.log("[VerifyFirst Lifecycle] mutation scan started");
            scanActiveChatForUrls(false);
        }, 200);
    }
    /**
     * Initialize MutationObserver to watch for dynamic DOM updates in WhatsApp Web.
     */
    function initObserver() {
        if (extensionContextInvalid || !isContextValid()) {
            shutdownScanner();
            return;
        }
        // A lightweight body observer strictly to detect when the chat container appears or changes
        bodyObserver = new MutationObserver(() => {
            if (extensionContextInvalid)
                return;
            const chatContainer = getActiveChatContainer();
            if (chatContainer !== currentObservedContainer) {
                attachChatObserver(chatContainer);
            }
        });
        bodyObserver.observe(document.body, {
            childList: true,
            subtree: true,
            attributes: false,
        });
        // Initial attach
        attachChatObserver(getActiveChatContainer());
    }
    function attachChatObserver(container) {
        if (observerInstance) {
            observerInstance.disconnect();
            observerInstance = null;
        }
        currentChatId = "";
        discoveredUrls.clear();
        currentChatRecords = {};
        discoveredFiles.clear();
        currentFileRecords = {};
        discoveredMessages.clear();
        currentMessageRecords = {};
        if (typeof window !== "undefined" && window.VerifyFirstOverlay) {
            window.VerifyFirstOverlay.resetDisplayedWarnings();
        }
        safeSendMessage({
            type: "CHAT_SWITCHED",
            chatId: "",
        });
        currentObservedContainer = container;
        if (container) {
            console.log("[VerifyFirst] Attached observer to new chat container");
            console.log("[VerifyFirst Lifecycle] container detected");
            console.log("[VerifyFirst Lifecycle] immediate scan started");
            scanActiveChatForUrls(true);
            observerInstance = new MutationObserver(() => {
                scheduleScan();
            });
            observerInstance.observe(container, {
                childList: true,
                subtree: true,
                characterData: true,
                attributes: false,
            });
        }
        else {
            console.log("[VerifyFirst] No chat container currently active to observe");
        }
    }
    // Start observing once DOM is ready
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initObserver);
    }
    else {
        initObserver();
    }
})();
