"use strict";
/**
 * VerifyFirst — Extension Popup Controller (Phase 2.1)
 *
 * Manages clean cybersecurity popup dashboard, link selection, and
 * Understand More detailed indicator breakdown.
 *
 * ALL dynamic untrusted strings are rendered using XSS-safe textContent.
 */
(function () {
    let currentRecords = [];
    let selectedIndex = 0;
    // Views
    const viewEmpty = document.getElementById("view-empty");
    const viewMain = document.getElementById("view-main");
    const viewDetails = document.getElementById("view-details");
    // Main View Elements
    const statusBadge = document.getElementById("status-badge");
    const statusText = document.getElementById("status-text");
    const scoreNum = document.getElementById("score-num");
    const urlBox = document.getElementById("url-box");
    const indicatorSummaryNote = document.getElementById("indicator-summary-note");
    const multiLinksSection = document.getElementById("multi-links-section");
    const multiLinksTitle = document.getElementById("multi-links-title");
    const linksList = document.getElementById("links-list");
    const btnUnderstandMore = document.getElementById("btn-understand-more");
    const btnBack = document.getElementById("btn-back");
    // Details View Elements
    const detailsStatusBadge = document.getElementById("details-status-badge");
    const detailsStatusText = document.getElementById("details-status-text");
    const detailsScoreNum = document.getElementById("details-score-num");
    const detailsUrlBox = document.getElementById("details-url-box");
    const indicatorsContainer = document.getElementById("indicators-container");
    function formatRuleName(rule) {
        return rule
            .toLowerCase()
            .split("_")
            .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
            .join(" ");
    }
    function applyStatusBadgeStyle(badge, textEl, status) {
        badge.className = "status-badge";
        if (status === "SAFE") {
            badge.classList.add("status-safe");
            textEl.textContent = "✓ SAFE";
        }
        else if (status === "SUSPICIOUS") {
            badge.classList.add("status-suspicious");
            textEl.textContent = "⚠ SUSPICIOUS";
        }
        else if (status === "DANGEROUS") {
            badge.classList.add("status-dangerous");
            textEl.textContent = "✕ DANGEROUS";
        }
        else {
            badge.classList.add("status-unavailable");
            textEl.textContent = "⚠ ANALYSIS UNAVAILABLE";
        }
    }
    function renderMainView() {
        if (currentRecords.length === 0) {
            viewEmpty.classList.add("active");
            viewMain.classList.remove("active");
            viewDetails.classList.remove("active");
            return;
        }
        viewEmpty.classList.remove("active");
        viewMain.classList.add("active");
        viewDetails.classList.remove("active");
        const record = currentRecords[selectedIndex];
        if (!record)
            return;
        applyStatusBadgeStyle(statusBadge, statusText, record.status);
        if (record.status === "ANALYSIS_UNAVAILABLE") {
            scoreNum.textContent = "— / 100";
        }
        else {
            scoreNum.textContent = `${record.risk_score ?? 0} / 100`;
        }
        urlBox.textContent = record.url;
        // Indicator Summary Note
        if (record.status === "SAFE") {
            indicatorSummaryNote.textContent = "No suspicious indicators detected.";
        }
        else if (record.status === "SUSPICIOUS") {
            const count = record.reasons.length;
            indicatorSummaryNote.textContent = `${count} suspicious indicator${count === 1 ? "" : "s"} detected`;
        }
        else if (record.status === "DANGEROUS") {
            indicatorSummaryNote.textContent = "We recommend that you do not open this link.";
        }
        else {
            indicatorSummaryNote.textContent = "VerifyFirst could not analyze this link right now.";
        }
        // Multiple Links List Selector
        if (currentRecords.length > 1) {
            multiLinksSection.style.display = "block";
            multiLinksTitle.textContent = `${currentRecords.length} LINKS ANALYZED`;
            linksList.innerHTML = "";
            currentRecords.forEach((item, idx) => {
                const row = document.createElement("div");
                row.className = `link-row ${idx === selectedIndex ? "active" : ""}`;
                row.addEventListener("click", () => {
                    selectedIndex = idx;
                    renderMainView();
                });
                const rowUrl = document.createElement("div");
                rowUrl.className = "link-row-url";
                rowUrl.textContent = item.url;
                const rowTag = document.createElement("div");
                rowTag.className = `link-row-tag tag-${item.status.toLowerCase()}`;
                if (item.status === "SAFE")
                    rowTag.textContent = "SAFE";
                else if (item.status === "SUSPICIOUS")
                    rowTag.textContent = `${item.risk_score ?? "N/A"}`;
                else if (item.status === "DANGEROUS")
                    rowTag.textContent = `${item.risk_score ?? "N/A"}`;
                else
                    rowTag.textContent = "N/A";
                row.appendChild(rowUrl);
                row.appendChild(rowTag);
                linksList.appendChild(row);
            });
        }
        else {
            multiLinksSection.style.display = "none";
        }
    }
    function renderDetailsView() {
        const record = currentRecords[selectedIndex];
        if (!record)
            return;
        viewMain.classList.remove("active");
        viewDetails.classList.add("active");
        applyStatusBadgeStyle(detailsStatusBadge, detailsStatusText, record.status);
        if (record.status === "ANALYSIS_UNAVAILABLE") {
            detailsScoreNum.textContent = "— / 100";
        }
        else {
            detailsScoreNum.textContent = `${record.risk_score ?? 0} / 100`;
        }
        detailsUrlBox.textContent = record.url;
        // Clear indicators container
        indicatorsContainer.innerHTML = "";
        if (record.status === "ANALYSIS_UNAVAILABLE") {
            const card = document.createElement("div");
            card.className = "indicator-card";
            const title = document.createElement("div");
            title.className = "indicator-rule-title";
            title.textContent = "Analysis Unavailable";
            const desc = document.createElement("div");
            desc.className = "indicator-rule-desc";
            desc.textContent = "The VerifyFirst backend detection service could not complete the security analysis for this link.";
            card.appendChild(title);
            card.appendChild(desc);
            indicatorsContainer.appendChild(card);
            return;
        }
        if (record.reasons.length === 0) {
            const card = document.createElement("div");
            card.className = "indicator-card";
            const title = document.createElement("div");
            title.className = "indicator-rule-title";
            title.textContent = "No Indicators Triggered";
            const desc = document.createElement("div");
            desc.className = "indicator-rule-desc";
            desc.textContent = "The detection engine identified no suspicious patterns or heuristic rule violations.";
            card.appendChild(title);
            card.appendChild(desc);
            indicatorsContainer.appendChild(card);
            return;
        }
        record.reasons.forEach((reason) => {
            const card = document.createElement("div");
            card.className = "indicator-card";
            const title = document.createElement("div");
            title.className = "indicator-rule-title";
            title.textContent = formatRuleName(reason.rule);
            const desc = document.createElement("div");
            desc.className = "indicator-rule-desc";
            desc.textContent = reason.message;
            card.appendChild(title);
            card.appendChild(desc);
            indicatorsContainer.appendChild(card);
        });
    }
    // Event Handlers
    btnUnderstandMore.addEventListener("click", () => {
        currentView = "DETAILS";
        renderDetailsView();
    });
    btnBack.addEventListener("click", () => {
        currentView = "MAIN";
        renderMainView();
    });
    // Load results directly from the active tab's content script (authoritative current chat state)
    function loadResults() {
        if (typeof chrome === "undefined" || !chrome.tabs || !chrome.tabs.query) {
            fallbackLoadFromServiceWorker();
            return;
        }
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            const activeTabId = tabs && tabs[0] ? tabs[0].id : undefined;
            if (activeTabId === undefined) {
                fallbackLoadFromServiceWorker();
                return;
            }
            chrome.tabs.sendMessage(activeTabId, { type: "GET_CURRENT_CHAT_STATE" }, (response) => {
                if (chrome.runtime.lastError || !response) {
                    // Content script might not be injected or ready; fallback to service worker
                    fallbackLoadFromServiceWorker();
                    return;
                }
                const chatId = response.chatId || "";
                const urlsObj = response.urls || {};
                const records = Object.values(urlsObj);
                records.sort((a, b) => b.timestamp - a.timestamp);
                console.log(`[VerifyFirst] Popup rendering current chat: ${chatId}`);
                console.log(`[VerifyFirst] Popup rendering ${records.length} URLs`);
                const previousSelectedUrl = currentRecords[selectedIndex]?.url;
                currentRecords = records;
                selectedIndex = 0;
                if (previousSelectedUrl) {
                    const newIndex = currentRecords.findIndex((r) => r.url === previousSelectedUrl);
                    if (newIndex !== -1) {
                        selectedIndex = newIndex;
                    }
                }
                if (currentView === "DETAILS") {
                    renderDetailsView();
                }
                else {
                    renderMainView();
                }
            });
        });
    }
    function fallbackLoadFromServiceWorker() {
        chrome.runtime.sendMessage({ type: "GET_TAB_RESULTS" }, (response) => {
            if (chrome.runtime.lastError || !response || !response.success || !response.state) {
                currentRecords = [];
                renderMainView();
                return;
            }
            const state = response.state;
            const records = Object.values(state.urls || {});
            records.sort((a, b) => b.timestamp - a.timestamp);
            console.log(`[VerifyFirst] Popup rendering fallback state: ${state.chatId || "unknown"}`);
            console.log(`[VerifyFirst] Popup rendering ${records.length} URLs`);
            const previousSelectedUrl = currentRecords[selectedIndex]?.url;
            currentRecords = records;
            selectedIndex = 0;
            if (previousSelectedUrl) {
                const newIndex = currentRecords.findIndex((r) => r.url === previousSelectedUrl);
                if (newIndex !== -1) {
                    selectedIndex = newIndex;
                }
            }
            if (currentView === "DETAILS") {
                renderDetailsView();
            }
            else {
                renderMainView();
            }
        });
    }
    // Auto-refresh interval handle
    let refreshInterval = null;
    let currentView = "MAIN";
    document.addEventListener("DOMContentLoaded", () => {
        // Step 1: Tell service worker to trigger a scan in the content script
        chrome.runtime.sendMessage({ type: "TRIGGER_SCAN" });
        // Step 2: Load results after a brief delay to let the scan complete
        window.setTimeout(loadResults, 300);
        // Step 3: Auto-refresh every 1.5 seconds while popup is open
        refreshInterval = window.setInterval(loadResults, 1500);
    });
    // Clean up interval when popup closes
    window.addEventListener("unload", () => {
        if (refreshInterval !== null) {
            window.clearInterval(refreshInterval);
            refreshInterval = null;
        }
    });
})();
