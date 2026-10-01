"use strict";
/**
 * VerifyFirst In-Page Security Center Controller
 * Phases 7B & 7C: Shell and Views
 */
(() => {
    const HOST_ID = "verifyfirst-security-center-root";
    let hostElement = null;
    let shadow = null;
    let telemetry = null; // Dynamically imported telemetry client
    let currentView = "overview";
    let previousView = "overview";
    // Local state for history pagination/filters
    let currentHistoryQuery = { sort: "newest", limit: 50, offset: 0 };
    let allRecentHistory = [];
    let currentlyViewedEvent = null;
    let pendingNavigation = null;
    let historyEvents = [];
    let filteredHistoryEvents = [];
    let historyFilters = {
        search: "",
        status: "ALL",
        action: "ALL",
        sort: "NEWEST"
    };
    async function initTelemetry() {
        if (!telemetry) {
            try {
                const telemetryUrl = chrome.runtime.getURL("shared/telemetryClient.js");
                telemetry = await import(telemetryUrl);
            }
            catch (err) {
                console.error("[VerifyFirst] Failed to load telemetry client dynamically:", err);
            }
        }
        return telemetry;
    }
    function getHost() {
        return document.getElementById(HOST_ID);
    }
    function isOpen() {
        return !!getHost();
    }
    function close() {
        const el = getHost();
        if (el && el.parentNode) {
            // Animate out if desired, then remove
            const backdrop = shadow?.querySelector('.vf-sc-backdrop');
            if (backdrop)
                backdrop.classList.remove('vf-sc-visible');
            setTimeout(() => {
                if (el.parentNode)
                    el.parentNode.removeChild(el);
                hostElement = null;
                shadow = null;
                // Reset transient UI state on close
                currentView = "overview";
                currentlyViewedEvent = null;
            }, 200); // match transition time
        }
        else {
            currentView = "overview";
            currentlyViewedEvent = null;
        }
    }
    function toggle() {
        if (isOpen()) {
            close();
        }
        else {
            open();
        }
    }
    // Handle Escape key globally when open
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape" && isOpen()) {
            close();
        }
    });
    async function resolvePendingNavigation() {
        if (!pendingNavigation)
            return;
        if (pendingNavigation.view === "event" && pendingNavigation.eventId) {
            console.log(`[VerifyFirst] Resolving pending navigation for eventId=${pendingNavigation.eventId}`);
            await initTelemetry();
            try {
                const events = await telemetry.fetchHistory({ sort: "newest", limit: 10000 });
                console.log(`[VerifyFirst] Fetched ${events.length} events, searching for eventId=${pendingNavigation.eventId}`);
                const targetEvent = events.find((ev) => ev.id === pendingNavigation?.eventId);
                if (targetEvent) {
                    console.log(`[VerifyFirst] Event found: hostname=${targetEvent.hostname}, status=${targetEvent.status}`);
                    currentlyViewedEvent = targetEvent;
                    previousView = pendingNavigation.originatingView || "overview";
                    currentView = "event-details";
                }
                else {
                    console.warn(`[VerifyFirst] Event not found for eventId=${pendingNavigation.eventId}, falling back to overview`);
                    currentView = "overview";
                }
            }
            catch (err) {
                console.error("[VerifyFirst] Error resolving pending navigation:", err);
                currentView = "overview";
            }
        }
        pendingNavigation = null;
    }
    async function open() {
        if (isOpen()) {
            console.log("[VerifyFirst] Security Center already open.");
            return;
        }
        // Guard against invalidated extension context (e.g., after extension reload)
        if (!chrome.runtime?.id) {
            console.warn("[VerifyFirst] Extension context invalidated. Please refresh the page.");
            return;
        }
        console.log("[VerifyFirst] Opening in-page Security Center.");
        // Ensure telemetry is loaded
        await initTelemetry();
        hostElement = document.createElement("div");
        hostElement.id = HOST_ID;
        hostElement.style.all = "initial"; // Reset all inherited styles
        shadow = hostElement.attachShadow({ mode: "closed" });
        // Load CSS
        const styleLink = document.createElement("link");
        styleLink.rel = "stylesheet";
        styleLink.href = chrome.runtime.getURL("content/security-center/securityCenter.css");
        shadow.appendChild(styleLink);
        // Build DOM structure
        const backdrop = document.createElement("div");
        backdrop.className = "vf-sc-backdrop";
        // Optional: click backdrop to close
        backdrop.addEventListener("click", (e) => {
            if (e.target === backdrop)
                close();
        });
        const modal = document.createElement("div");
        modal.className = "vf-sc-modal";
        // Header (Navbar)
        const header = document.createElement("div");
        header.className = "vf-sc-header";
        header.innerHTML = `
      <div class="vf-sc-brand">
        <img src="${chrome.runtime.getURL('assets/logo-mark.svg')}" class="vf-sc-logo-mark" alt="Logo" />
        <span class="vf-sc-brand-title">VerifyFirst</span>
      </div>
      <div class="vf-sc-nav">
        <button class="vf-sc-nav-btn vf-sc-active" data-view="overview">Overview</button>
        <button class="vf-sc-nav-btn" data-view="links">Links</button>
        <button class="vf-sc-nav-btn" data-view="history">History</button>
        <button class="vf-sc-nav-btn" data-view="settings">Settings</button>
      </div>
      <div class="vf-sc-close-container">
        <button class="vf-sc-close-btn" title="Close (Esc)">&times;</button>
      </div>
    `;
        // Attach nav listeners
        const navButtons = header.querySelectorAll(".vf-sc-nav-btn");
        navButtons.forEach(btn => {
            btn.addEventListener("click", (e) => {
                navButtons.forEach(b => b.classList.remove("vf-sc-active"));
                e.currentTarget.classList.add("vf-sc-active");
                switchView(e.currentTarget.dataset.view || "overview");
            });
        });
        const closeBtn = header.querySelector(".vf-sc-close-btn");
        closeBtn?.addEventListener("click", close);
        modal.appendChild(header);
        // Body container (Main only)
        const body = document.createElement("div");
        body.className = "vf-sc-body";
        // Main Content Area
        const main = document.createElement("div");
        main.className = "vf-sc-main";
        main.id = "vf-sc-main-content";
        body.appendChild(main);
        modal.appendChild(body);
        backdrop.appendChild(modal);
        shadow.appendChild(backdrop);
        // Inject into document body
        document.body.appendChild(hostElement);
        // Trigger animation
        requestAnimationFrame(() => {
            backdrop.classList.add("vf-sc-visible");
        });
        // Resolve any pending navigation before rendering
        await resolvePendingNavigation();
        // Render initial view
        switchView(currentView);
    }
    async function switchView(viewName) {
        if (viewName !== "event-details") {
            previousView = viewName;
        }
        currentView = viewName;
        const main = shadow?.getElementById("vf-sc-main-content");
        if (!main)
            return;
        main.innerHTML = `
      <div class="vf-sc-state-message" style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; text-align: center; color: var(--text);">
        <div class="vf-sc-state-icon" style="font-size: 24px; color: var(--text-muted); margin-bottom: 12px; animation: vf-sc-pulse 1.5s infinite;">⌛</div>
        <div style="font-weight: 500; font-size: 13px;">Loading security data...</div>
      </div>
    `;
        if (!telemetry) {
            main.innerHTML = `<div class="vf-sc-state-message">Telemetry client not loaded.</div>`;
            return;
        }
        try {
            if (viewName === "overview") {
                await renderOverview(main);
            }
            else if (viewName === "links") {
                await renderLinks(main);
            }
            else if (viewName === "history") {
                await renderHistory(main);
            }
            else if (viewName === "settings") {
                await renderSettings(main);
            }
            else if (viewName === "event-details") {
                await renderEventDetails(main);
            }
        }
        catch (e) {
            main.innerHTML = `
        <div class="vf-sc-state-message" style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; text-align: center; color: var(--text);">
          <div class="vf-sc-state-icon" style="font-size: 24px; color: var(--text-muted); margin-bottom: 12px;">⚠</div>
          <div style="font-weight: 600; font-size: 14px; margin-bottom: 4px;">Security data unavailable.</div>
          <div style="font-size: 13px; color: var(--text-secondary); margin-bottom: 16px;">VerifyFirst protection remains active.</div>
          <button type="button" class="vf-sc-btn vf-sc-btn-primary" id="btn-retry-view">Try Again</button>
        </div>
      `;
            main.querySelector("#btn-retry-view")?.addEventListener("click", () => switchView(viewName));
        }
    }
    function openHistoryWithStatus(status) {
        historyFilters.search = "";
        historyFilters.action = "ALL";
        historyFilters.sort = "NEWEST";
        historyFilters.status = status;
        // Update navbar active state
        if (shadow) {
            const navButtons = shadow.querySelectorAll(".vf-sc-nav-btn");
            navButtons.forEach(b => b.classList.remove("vf-sc-active"));
            const historyBtn = shadow.querySelector('.vf-sc-nav-btn[data-view="history"]');
            if (historyBtn)
                historyBtn.classList.add("vf-sc-active");
        }
        switchView("history");
    }
    // --- Rendering Helpers ---
    function getBadgeHtml(status) {
        const s = (status || "").toLowerCase();
        if (s === "safe")
            return `<span class="vf-sc-badge safe">Safe</span>`;
        if (s === "suspicious")
            return `<span class="vf-sc-badge suspicious">Suspicious</span>`;
        if (s === "dangerous")
            return `<span class="vf-sc-badge dangerous">Dangerous</span>`;
        return `<span class="vf-sc-badge unverified">Unavailable</span>`;
    }
    function getHostname(url) {
        try {
            return new URL(url).hostname;
        }
        catch {
            return url;
        }
    }
    function formatTime(ts) {
        if (!ts)
            return "Unknown";
        const date = new Date(ts);
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
    function getSeverityLabel(score) {
        const s = score || 0;
        if (s <= 10)
            return 'Very Low';
        if (s <= 25)
            return 'Low';
        if (s <= 65)
            return 'Medium';
        if (s <= 90)
            return 'High';
        return 'Critical';
    }
    function escapeHtml(value) {
        return String(value ?? "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
    function getAssetDisplayValue(event) {
        switch (event.assetType) {
            case "file":
                return event.filename || "Unknown file";
            case "message":
                return event.messagePreview || "Message";
            case "url":
            default:
                return event.hostname || "Unknown host";
        }
    }
    function renderAssetHtml(event) {
        const displayValue = escapeHtml(getAssetDisplayValue(event));
        return `<span class="vf-sc-host-text" title="${displayValue}">${displayValue}</span>`;
    }
    function renderEventRows(events) {
        if (!events || events.length === 0) {
            return ``;
        }
        let html = "";
        events.forEach(ev => {
            // Use ev.id as the unique row identifier
            const safeId = (ev.id || "").replace(/"/g, "&quot;");
            html += `
        <tr data-id="${safeId}" class="vf-sc-event-row" tabindex="0">
          <td style="font-family: var(--vf-font-mono, monospace); max-width: 150px;">
            ${renderAssetHtml(ev)}
          </td>
          <td>${getBadgeHtml(ev.status)}</td>
          <td>${ev.riskScore ?? '-'}</td>
          <td style="font-size:11px; font-weight:600;">${ev.protectionAction || 'ALLOW'}</td>
          <td style="color:#94A3B8;">${formatTime(ev.timestamp)}</td>
        </tr>
      `;
        });
        return html;
    }
    function attachRowClickListeners(container, events) {
        const rows = container.querySelectorAll('.vf-sc-event-row');
        rows.forEach(row => {
            const handleRowClick = (e) => {
                const id = e.currentTarget.dataset.id;
                const ev = events.find(x => x.id === id);
                if (ev) {
                    currentlyViewedEvent = ev;
                    switchView("event-details");
                }
            };
            row.addEventListener("click", handleRowClick);
            row.addEventListener("keydown", (e) => {
                const keyEvent = e;
                if (keyEvent.key === "Enter" || keyEvent.key === " ") {
                    keyEvent.preventDefault();
                    handleRowClick(e);
                }
            });
        });
    }
    // --- Views ---
    async function renderOverview(container) {
        const stats = await telemetry.fetchStatistics();
        const events = await telemetry.fetchHistory({ sort: "newest", limit: 5 });
        allRecentHistory = events; // cache for row clicks
        container.innerHTML = `
      <div class="vf-sc-view-header">
        <h1 class="vf-sc-view-title">Overview</h1>
        <div class="vf-sc-view-subtitle">Security &amp; Link Protection Overview</div>
      </div>
      
      <div class="vf-sc-stat-grid">
        <button class="vf-sc-stat-card" data-status="ALL">
          <div class="vf-sc-stat-label">Total Analyzed <span class="vf-sc-stat-arrow">&rarr;</span></div>
          <div class="vf-sc-stat-value">${stats.totalEvents}</div>
        </button>
        <button class="vf-sc-stat-card safe" data-status="SAFE">
          <div class="vf-sc-stat-label">Safe <span class="vf-sc-stat-arrow">&rarr;</span></div>
          <div class="vf-sc-stat-value safe">${stats.safeCount}</div>
        </button>
        <button class="vf-sc-stat-card suspicious" data-status="SUSPICIOUS">
          <div class="vf-sc-stat-label">Suspicious <span class="vf-sc-stat-arrow">&rarr;</span></div>
          <div class="vf-sc-stat-value suspicious">${stats.suspiciousCount}</div>
        </button>
        <button class="vf-sc-stat-card dangerous" data-status="DANGEROUS">
          <div class="vf-sc-stat-label">Dangerous <span class="vf-sc-stat-arrow">&rarr;</span></div>
          <div class="vf-sc-stat-value dangerous">${stats.dangerousCount}</div>
        </button>
      </div>

      <div style="margin-bottom:32px;">
        <h3 class="vf-sc-section-title">Protection Activity</h3>
        <div class="vf-sc-compact-stats">
           <div class="vf-sc-compact-stat">
             <div class="vf-sc-compact-stat-label">Allowed</div>
             <div class="vf-sc-compact-stat-value safe">${stats.allowedCount}</div>
           </div>
           <div class="vf-sc-compact-stat">
             <div class="vf-sc-compact-stat-label">Warned</div>
             <div class="vf-sc-compact-stat-value suspicious">${stats.warnedCount}</div>
           </div>
           <div class="vf-sc-compact-stat">
             <div class="vf-sc-compact-stat-label">Blocked</div>
             <div class="vf-sc-compact-stat-value dangerous">${stats.blockedCount}</div>
           </div>
           <div class="vf-sc-compact-stat">
             <div class="vf-sc-compact-stat-label">Unique Hosts</div>
             <div class="vf-sc-compact-stat-value">${stats.uniqueHostnames}</div>
           </div>
        </div>
      </div>

      <div>
        <h3 class="vf-sc-section-title">Recent Activity</h3>
        <div class="vf-sc-table-container">
          <table class="vf-sc-table">
            <thead>
              <tr><th>Hostname / IP</th><th>Status</th><th>Risk Score</th><th>Protection Action</th><th>Time</th></tr>
            </thead>
            <tbody>
              ${renderEventRows(events)}
            </tbody>
          </table>
        </div>
      </div>
    `;
        const statCards = container.querySelectorAll('.vf-sc-stat-card');
        statCards.forEach(card => {
            card.addEventListener("click", (e) => {
                const status = e.currentTarget.dataset.status;
                if (status) {
                    openHistoryWithStatus(status);
                }
            });
        });
        attachRowClickListeners(container, events);
    }
    async function renderLinks(container) {
        const events = await telemetry.fetchHistory({ sort: "newest", limit: 50 });
        container.innerHTML = `
      <div class="vf-sc-view-header">
        <h1 class="vf-sc-view-title">Links</h1>
        <div class="vf-sc-view-subtitle">Recently analyzed security events</div>
      </div>
      ${events.length === 0 ? `
        <div class="vf-sc-empty-state">
          <div style="font-weight: 600; margin-bottom: 4px;">No security events yet.</div>
          <div style="color: var(--text-secondary); font-size: 13px;">Analyzed links will appear here after VerifyFirst processes them.</div>
        </div>
      ` : `
      <div class="vf-sc-table-container">
        <table class="vf-sc-table">
          <thead>
            <tr><th>Hostname / IP</th><th>Status</th><th>Risk Score</th><th>Protection Action</th><th>Time</th></tr>
          </thead>
          <tbody>
            ${renderEventRows(events)}
          </tbody>
        </table>
      </div>
      `}
    `;
        attachRowClickListeners(container, events);
    }
    function applyHistoryFilters() {
        filteredHistoryEvents = historyEvents.filter(ev => {
            if (historyFilters.search) {
                const query = historyFilters.search.toLowerCase();
                const displayValue = getAssetDisplayValue(ev).toLowerCase();
                if (!displayValue.includes(query))
                    return false;
            }
            // 2. Status
            if (historyFilters.status !== "ALL" && ev.status !== historyFilters.status) {
                return false;
            }
            // 3. Action
            if (historyFilters.action !== "ALL" && ev.protectionAction !== historyFilters.action) {
                return false;
            }
            return true;
        });
        // 4. Sort
        filteredHistoryEvents.sort((a, b) => {
            const timeA = a.timestamp || 0;
            const timeB = b.timestamp || 0;
            return historyFilters.sort === "NEWEST" ? timeB - timeA : timeA - timeB;
        });
    }
    function updateHistoryUI(container) {
        const tbody = container.querySelector("tbody");
        const countEl = container.querySelector("#hist-count");
        const emptyEl = container.querySelector("#hist-empty");
        const clearBtn = container.querySelector("#hist-clear");
        const tableContainer = container.querySelector(".vf-sc-table-container");
        if (!tbody || !countEl || !emptyEl || !clearBtn || !tableContainer)
            return;
        if (historyFilters.search || historyFilters.status !== "ALL" || historyFilters.action !== "ALL" || historyFilters.sort !== "NEWEST") {
            clearBtn.style.display = "inline-flex";
        }
        else {
            clearBtn.style.display = "none";
        }
        countEl.textContent = `Showing ${filteredHistoryEvents.length} of ${historyEvents.length} events`;
        if (filteredHistoryEvents.length === 0) {
            emptyEl.style.display = "flex";
            tableContainer.style.display = "none";
        }
        else {
            emptyEl.style.display = "none";
            tableContainer.style.display = "block";
            tbody.innerHTML = renderEventRows(filteredHistoryEvents);
            attachRowClickListeners(container, filteredHistoryEvents);
        }
    }
    async function renderHistory(container) {
        // Fetch complete history using limit 1000 to get a good dataset
        historyEvents = await telemetry.fetchHistory({ sort: "newest", limit: 1000, offset: 0 });
        applyHistoryFilters();
        container.innerHTML = `
      <div class="vf-sc-view-header">
        <h1 class="vf-sc-view-title">History</h1>
        <div class="vf-sc-view-subtitle">Full security event log</div>
      </div>
      
      <div class="vf-sc-filters" id="hist-toolbar">
         <input type="text" id="hist-search" class="vf-sc-input" placeholder="Search events..." style="flex:1" value="${escapeHtml(historyFilters.search)}">
         
         <span class="vf-sc-filter-group">
           Status:
           <select id="hist-status" class="vf-sc-select">
             <option value="ALL" ${historyFilters.status === "ALL" ? "selected" : ""}>All</option>
             <option value="SAFE" ${historyFilters.status === "SAFE" ? "selected" : ""}>Safe</option>
             <option value="SUSPICIOUS" ${historyFilters.status === "SUSPICIOUS" ? "selected" : ""}>Suspicious</option>
             <option value="DANGEROUS" ${historyFilters.status === "DANGEROUS" ? "selected" : ""}>Dangerous</option>
           </select>
         </span>
         
         <span class="vf-sc-filter-group">
           Action:
           <select id="hist-action" class="vf-sc-select">
             <option value="ALL" ${historyFilters.action === "ALL" ? "selected" : ""}>All</option>
             <option value="ALLOW" ${historyFilters.action === "ALLOW" ? "selected" : ""}>Allow</option>
             <option value="WARN" ${historyFilters.action === "WARN" ? "selected" : ""}>Warn</option>
             <option value="BLOCK" ${historyFilters.action === "BLOCK" ? "selected" : ""}>Block</option>
           </select>
         </span>
         
         <span class="vf-sc-filter-group">
           Sort:
           <select id="hist-sort" class="vf-sc-select">
             <option value="NEWEST" ${historyFilters.sort === "NEWEST" ? "selected" : ""}>Newest</option>
             <option value="OLDEST" ${historyFilters.sort === "OLDEST" ? "selected" : ""}>Oldest</option>
           </select>
         </span>
         
         <button id="hist-clear" class="vf-sc-btn vf-sc-btn-secondary" style="display: none;">Clear</button>
      </div>
      
      <div id="hist-count" style="font-size: 13px; color: var(--text-secondary); margin-bottom: 12px; text-align: right;"></div>
      
      <div id="hist-empty" class="vf-sc-empty-state" style="display: none;">
        No security events match your filters.
        <button id="hist-empty-clear" class="vf-sc-btn vf-sc-btn-primary" style="margin-top: 16px;">Clear filters</button>
      </div>

      <div class="vf-sc-table-container">
        <table class="vf-sc-table">
          <thead>
            <tr><th>Hostname / IP</th><th>Status</th><th>Risk Score</th><th>Protection Action</th><th>Time</th></tr>
          </thead>
          <tbody>
          </tbody>
        </table>
      </div>
    `;
        // Attach control listeners
        const searchInput = container.querySelector("#hist-search");
        const statusSelect = container.querySelector("#hist-status");
        const actionSelect = container.querySelector("#hist-action");
        const sortSelect = container.querySelector("#hist-sort");
        const clearBtn = container.querySelector("#hist-clear");
        const emptyClearBtn = container.querySelector("#hist-empty-clear");
        const handleFilterChange = () => {
            historyFilters.search = searchInput.value;
            historyFilters.status = statusSelect.value;
            historyFilters.action = actionSelect.value;
            historyFilters.sort = sortSelect.value;
            applyHistoryFilters();
            updateHistoryUI(container);
        };
        searchInput.addEventListener("input", handleFilterChange);
        statusSelect.addEventListener("change", handleFilterChange);
        actionSelect.addEventListener("change", handleFilterChange);
        sortSelect.addEventListener("change", handleFilterChange);
        const clearFilters = () => {
            historyFilters.search = "";
            historyFilters.status = "ALL";
            historyFilters.action = "ALL";
            historyFilters.sort = "NEWEST";
            searchInput.value = "";
            statusSelect.value = "ALL";
            actionSelect.value = "ALL";
            sortSelect.value = "NEWEST";
            applyHistoryFilters();
            updateHistoryUI(container);
        };
        clearBtn.addEventListener("click", clearFilters);
        emptyClearBtn.addEventListener("click", clearFilters);
        // Initial render
        updateHistoryUI(container);
    }
    async function renderSettings(container) {
        const manifest = chrome.runtime.getManifest();
        const version = manifest ? manifest.version : "1.0.0";
        container.innerHTML = `
      <div class="vf-sc-settings">
        <div class="vf-sc-view-header">
          <h1 class="vf-sc-view-title">Settings</h1>
          <div class="vf-sc-view-subtitle">Manage your security data and preferences</div>
        </div>
        
        <div class="vf-sc-settings-section">
          <h3 class="vf-sc-section-title vf-sc-settings-section-title">GENERAL</h3>
          <div class="vf-sc-settings-row" style="border: 1px solid var(--border); border-radius: 8px; background: var(--surface);">
            <div>
              <div class="vf-sc-settings-row-title">Export Security History</div>
              <div class="vf-sc-detail-text">Download your security event history in your preferred format.</div>
            </div>
            <div class="vf-sc-dropdown">
              <button class="vf-sc-btn vf-sc-btn-primary" id="btn-export-dropdown" aria-haspopup="true" aria-expanded="false" aria-label="Export security history">Export &#x25BE;</button>
              <div class="vf-sc-dropdown-menu" id="export-dropdown-menu">
                <button class="vf-sc-dropdown-item" data-format="json">JSON</button>
                <button class="vf-sc-dropdown-item" data-format="csv">CSV</button>
                <button class="vf-sc-dropdown-item" data-format="txt">TXT</button>
              </div>
            </div>
          </div>
        </div>

        <div class="vf-sc-settings-section">
          <h3 class="vf-sc-section-title vf-sc-settings-section-title">SECURITY DATA</h3>
          <div class="vf-sc-settings-row" style="border: 1px solid rgba(240, 68, 68, 0.3); border-radius: 8px; background: var(--surface);">
            <div>
              <div class="vf-sc-settings-row-title" style="color:var(--dangerous);">Clear Security History</div>
              <div class="vf-sc-detail-text">Permanently remove all locally stored security events.</div>
            </div>
            <button class="vf-sc-btn vf-sc-btn-danger" id="btn-clear-history" aria-label="Clear security history">Clear</button>
          </div>
        </div>

        <div class="vf-sc-about">
          <div class="vf-sc-about-title">VerifyFirst</div>
          <div class="vf-sc-about-text">Detect threats before you interact with them.</div>
          <div class="vf-sc-about-version">Version ${version}</div>
        </div>
      </div>

      <!-- Confirmation Modal -->
      <div class="vf-sc-confirm-backdrop" id="confirm-clear-backdrop">
        <div class="vf-sc-confirm-modal">
          <div class="vf-sc-confirm-header">
            <h2 class="vf-sc-confirm-title">Clear Security History</h2>
            <button class="vf-sc-confirm-close" id="btn-confirm-close" title="Close (Esc)">&times;</button>
          </div>
          <div class="vf-sc-confirm-body">
            This will permanently remove all locally stored VerifyFirst security events.<br><br>
            Your link protection will remain active.
          </div>
          <label class="vf-sc-confirm-input-label">To confirm, type:<br><span>CLEAR SECURITY HISTORY</span></label>
          <input type="text" class="vf-sc-input vf-sc-confirm-input" id="input-confirm-clear" autocomplete="off" spellcheck="false" />
          <div class="vf-sc-confirm-footer">
            <button class="vf-sc-btn vf-sc-btn-secondary" id="btn-confirm-cancel">Cancel</button>
            <button class="vf-sc-btn vf-sc-btn-danger vf-sc-btn-disabled" id="btn-confirm-submit">Clear Security History</button>
          </div>
        </div>
      </div>
    `;
        // Export Logic
        const exportBtn = container.querySelector('#btn-export-dropdown');
        const exportMenu = container.querySelector('#export-dropdown-menu');
        if (exportBtn && exportMenu) {
            exportBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                exportMenu.classList.toggle('show');
            });
            document.addEventListener('click', (e) => {
                if (!exportMenu.contains(e.target)) {
                    exportMenu.classList.remove('show');
                }
            });
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape')
                    exportMenu.classList.remove('show');
            });
            const exportItems = exportMenu.querySelectorAll('.vf-sc-dropdown-item');
            exportItems.forEach(item => {
                item.addEventListener('click', async (e) => {
                    const format = e.currentTarget.dataset.format;
                    exportMenu.classList.remove('show');
                    try {
                        const events = await telemetry.fetchHistory({ sort: "newest", limit: 10000 });
                        let content = "";
                        let type = "";
                        let ext = format;
                        if (format === "json") {
                            content = JSON.stringify(events, null, 2);
                            type = "application/json";
                        }
                        else if (format === "csv") {
                            const headers = ["Hostname", "Status", "Score", "Action", "Time"];
                            const rows = events.map((ev) => {
                                const timeStr = ev.timestamp ? new Date(ev.timestamp).toISOString() : "";
                                return [
                                    `"${(ev.hostname || "").replace(/"/g, '""')}"`,
                                    `"${ev.status || ""}"`,
                                    `"${ev.riskScore ?? ""}"`,
                                    `"${ev.protectionAction || ""}"`,
                                    `"${timeStr}"`
                                ].join(",");
                            });
                            content = [headers.join(","), ...rows].join("\n");
                            type = "text/csv";
                        }
                        else if (format === "txt") {
                            content = "VerifyFirst Security History\n============================\n\n";
                            events.forEach((ev) => {
                                const timeStr = ev.timestamp ? new Date(ev.timestamp).toLocaleString() : "Unknown";
                                content += `Hostname: ${ev.hostname || "unknown"}\n`;
                                content += `Status: ${ev.status || "Unknown"}\n`;
                                content += `Score: ${ev.riskScore ?? "-"}\n`;
                                content += `Action: ${ev.protectionAction || "ALLOW"}\n`;
                                content += `Time: ${timeStr}\n`;
                                content += `----------------------------\n\n`;
                            });
                            type = "text/plain";
                        }
                        const blob = new Blob([content], { type });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement("a");
                        a.href = url;
                        a.download = `verifyfirst-security-history.${ext}`;
                        a.click();
                        URL.revokeObjectURL(url);
                    }
                    catch (err) {
                        console.error("Export failed:", err);
                        alert("Export failed");
                    }
                });
            });
        }
        // Clear Modal Logic
        const clearBtn = container.querySelector('#btn-clear-history');
        const backdrop = container.querySelector('#confirm-clear-backdrop');
        const closeBtn = container.querySelector('#btn-confirm-close');
        const cancelBtn = container.querySelector('#btn-confirm-cancel');
        const submitBtn = container.querySelector('#btn-confirm-submit');
        const confirmInput = container.querySelector('#input-confirm-clear');
        const closeModal = () => {
            backdrop?.classList.remove('show');
            if (confirmInput)
                confirmInput.value = "";
            submitBtn?.classList.add('vf-sc-btn-disabled');
            clearBtn?.focus();
        };
        if (clearBtn && backdrop && closeBtn && cancelBtn && submitBtn && confirmInput) {
            clearBtn.addEventListener('click', () => {
                backdrop.classList.add('show');
                confirmInput.focus();
            });
            closeBtn.addEventListener('click', closeModal);
            cancelBtn.addEventListener('click', closeModal);
            backdrop.addEventListener('click', (e) => {
                if (e.target === backdrop)
                    closeModal();
            });
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape' && backdrop.classList.contains('show')) {
                    e.stopPropagation();
                    closeModal();
                }
            });
            confirmInput.addEventListener('input', () => {
                if (confirmInput.value === "CLEAR SECURITY HISTORY") {
                    submitBtn.classList.remove('vf-sc-btn-disabled');
                }
                else {
                    submitBtn.classList.add('vf-sc-btn-disabled');
                }
            });
            confirmInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' && !submitBtn.classList.contains('vf-sc-btn-disabled')) {
                    submitBtn.click();
                }
            });
            submitBtn.addEventListener('click', async () => {
                if (submitBtn.classList.contains('vf-sc-btn-disabled'))
                    return;
                try {
                    submitBtn.innerHTML = "Clearing...";
                    await telemetry.wipeHistory();
                    closeModal();
                    historyFilters.search = "";
                    historyFilters.status = "ALL";
                    historyFilters.action = "ALL";
                    historyFilters.sort = "NEWEST";
                    submitBtn.innerHTML = "Clear Security History";
                }
                catch (err) {
                    console.error("Clear failed:", err);
                    alert("Clear failed");
                    submitBtn.innerHTML = "Clear Security History";
                }
            });
        }
    }
    async function renderEventDetails(container) {
        if (!currentlyViewedEvent) {
            switchView("history");
            return;
        }
        const ev = currentlyViewedEvent;
        let reasonsHtml = (ev.reasons && ev.reasons.length > 0)
            ? ev.reasons.map(r => {
                return `<div class="vf-sc-detection-item-new">
            <div class="vf-sc-detection-icon" style="color: var(--brand-gold);">
              <svg viewBox="0 0 24 24" fill="currentColor"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>
            </div>
            <div class="vf-sc-detection-text">
              <div class="vf-sc-detection-name">${escapeHtml(r.rule || 'Indicator')}</div>
              <div class="vf-sc-detection-desc">${escapeHtml(r.message || '')}</div>
            </div>
          </div>`;
            }).join('')
            : `<div style="padding: 12px 0; color: var(--text-muted); font-size: 12px; font-weight: 400;">No specific detection reasons were provided.</div>`;
        const reasonsCount = ev.reasons ? ev.reasons.length : 0;
        const indicatorsCountText = reasonsCount === 1
            ? "1 detection indicator was detected for this destination."
            : `${reasonsCount} detection indicators were detected for this destination.`;
        let datePart = "";
        let timePart = "";
        if (ev.timestamp) {
            const dateObj = new Date(ev.timestamp);
            datePart = dateObj.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
            timePart = dateObj.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
        }
        container.innerHTML = `
      <div class="vf-sc-event-page" style="display: flex; flex-direction: column; height: 100%;">

        <div class="vf-sc-event-heading" style="flex-shrink: 0;">
          <div class="vf-sc-event-heading-left">
            <div class="vf-sc-event-title-block">
              <h1>Security Event</h1>
              <p>Detailed information about this security event</p>
            </div>
          </div>
          
          <div class="vf-sc-event-heading-right" style="display: flex; flex-direction: column; align-items: flex-end; gap: 8px;">
            <div class="vf-sc-event-detected-at">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
              <div class="vf-sc-event-detected-at-text">
                <span class="vf-sc-event-detected-at-label">Detected At</span>
                <span class="vf-sc-event-detected-at-val">${escapeHtml(datePart || 'Unknown Date')} ${timePart ? '• ' + escapeHtml(timePart) : ''}</span>
              </div>
            </div>
            <button class="vf-sc-btn vf-sc-btn-secondary" id="btn-back-details" style="padding: 4px 10px; font-size: 12px;" aria-label="Go back to previous view">
              &#8592; Back
            </button>
          </div>
        </div>

        <div class="vf-sc-event-scroll-area" style="flex: 1; overflow-y: auto; padding-right: 8px;">

        <div class="vf-sc-banner-card">
          <div class="vf-sc-banner-col vf-sc-banner-col-host">
            <div class="vf-sc-icon-box-large">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><circle cx="16" cy="16" r="4"></circle><line x1="12" y1="16" x2="16" y2="16"></line><line x1="16" y1="12" x2="16" y2="16"></line></svg>
            </div>
            <div class="vf-sc-host-details-col">
              <span class="vf-sc-host-details-label">${ev.assetType === 'file' ? 'Filename' : ev.assetType === 'message' ? 'Message Preview' : 'Hostname / IP'}</span>
              <span class="vf-sc-host-details-val" style="display: block; max-width: 100%; font-family: var(--vf-font-mono, monospace);">${renderAssetHtml(ev)}</span>
              <button class="vf-sc-copy-btn-new" id="vf-sc-copy-btn-hostname" data-clipboard="${escapeHtml(getAssetDisplayValue(ev))}">
                <svg viewBox="0 0 24 24"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>
                Copy
              </button>
            </div>
          </div>

          <div class="vf-sc-banner-col vf-sc-banner-col-verdict">
            <div class="vf-sc-verdict-icon ${ev.status === 'SAFE' ? 'safe' : ev.status === 'DANGEROUS' ? 'dangerous' : 'suspicious'}">
              ${ev.status === 'SAFE' ? `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><polyline points="9 12 11 14 15 10"></polyline></svg>` :
            ev.status === 'DANGEROUS' ? `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>` :
                `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>`}
            </div>
            <div class="vf-sc-verdict-details">
              <div class="vf-sc-verdict-title ${ev.status === 'SAFE' ? 'safe' : ev.status === 'DANGEROUS' ? 'dangerous' : 'suspicious'}" style="font-size: 20px; font-weight: 700; text-transform: uppercase;">
                ${ev.status || 'UNKNOWN'}
              </div>
              <div style="font-size: 12px; font-weight: 600; margin-bottom: 4px; color: var(--text-primary);">
                Protection: ${ev.protectionAction || 'ALLOW'}
              </div>
              <div class="vf-sc-verdict-desc" style="font-size: 12px; color: var(--text-secondary);">
                ${ev.status === 'SAFE' ? 'This destination appears to be safe.' : ev.status === 'DANGEROUS' ? 'This destination is considered dangerous and access was blocked.' : 'This destination shows suspicious characteristics.'}
              </div>
            </div>
          </div>

          <div class="vf-sc-banner-col vf-sc-banner-col-risk" style="justify-content: center; align-items: center; text-align: center;">
            <div style="font-size: 12px; font-weight: 500; color: var(--text-muted); margin-bottom: 4px;">Risk Score</div>
            <div class="vf-sc-risk-score-text" style="font-size: 20px; font-weight: 700; color: var(--text-primary); margin-bottom: 8px;">
              ${ev.riskScore ?? 0} <span style="color: var(--text-secondary); font-size: 14px;">/ 100</span>
            </div>
            <div class="vf-sc-risk-badge ${(ev.riskScore || 0) <= 25 ? 'safe' : (ev.riskScore || 0) <= 65 ? 'suspicious' : 'dangerous'}">
              ${getSeverityLabel(ev.riskScore)}
            </div>
          </div>
        </div>

        <div class="vf-sc-bottom-grid">
          <div class="vf-sc-list-card">
            <div class="vf-sc-card-header">
              <div class="vf-sc-card-header-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
              </div>
              <div class="vf-sc-card-header-titles">
                <h2>Detection Reasons</h2>
                <p>${indicatorsCountText}</p>
              </div>
            </div>
            <div class="vf-sc-detection-list-new">
              ${reasonsHtml}
            </div>
          </div>

          <div class="vf-sc-list-card">
            <div class="vf-sc-card-header">
              <div class="vf-sc-card-header-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
              </div>
              <div class="vf-sc-card-header-titles">
                <h2>Additional Information</h2>
                <p>Technical details about this event.</p>
              </div>
            </div>
            <div class="vf-sc-info-list">
              <div class="vf-sc-info-row">
                <div class="vf-sc-info-row-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg></div>
                <div class="vf-sc-info-row-label">Asset Type:</div>
                <div class="vf-sc-info-row-val">${ev.assetType === 'file' ? 'File' : ev.assetType === 'message' ? 'Message' : 'Link'}</div>
              </div>
              <div class="vf-sc-info-row">
                <div class="vf-sc-info-row-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="14" width="6" height="6" rx="1"></rect><rect x="16" y="14" width="6" height="6" rx="1"></rect><rect x="9" y="4" width="6" height="6" rx="1"></rect><path d="M5 14v-2a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2v2"></path><line x1="12" y1="10" x2="12" y2="14"></line></svg></div>
                <div class="vf-sc-info-row-label">Detection Source:</div>
                <div class="vf-sc-info-row-val">VerifyFirst Protection</div>
              </div>
              <div class="vf-sc-info-row">
                <div class="vf-sc-info-row-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg></div>
                <div class="vf-sc-info-row-label">Detected At:</div>
                <div class="vf-sc-info-row-val">${datePart || 'Unknown Date'} ${timePart ? '• ' + timePart : ''}</div>
              </div>
              <div class="vf-sc-info-row">
                <div class="vf-sc-info-row-icon"></div>
                <div class="vf-sc-info-row-label">Event ID:</div>
                <div class="vf-sc-info-row-val">${escapeHtml(ev.id || 'Unknown')}</div>
              </div>
            </div>
          </div>
        </div>
        
        </div>
      </div>
    `;
        const backBtn = container.querySelector("#btn-back-details");
        backBtn?.addEventListener("click", () => {
            switchView(previousView);
        });
        container.querySelector('#vf-sc-copy-btn-hostname')?.addEventListener('click', (e) => {
            const btn = e.currentTarget;
            const textToCopy = btn.getAttribute('data-clipboard') || 'unknown';
            navigator.clipboard.writeText(textToCopy).then(() => {
                const originalHtml = btn.innerHTML;
                btn.innerHTML = `<svg viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z" fill="currentColor"/></svg> Copied`;
                setTimeout(() => { btn.innerHTML = originalHtml; }, 2000);
            });
        });
    }
    // --- Main Listener ---
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (message.type === "OPEN_SECURITY_CENTER") {
            console.log("[VerifyFirst] OPEN_SECURITY_CENTER received");
            const initializeAndNavigate = async () => {
                if (!isOpen())
                    await open();
            };
            initializeAndNavigate();
            sendResponse({ success: true });
            return true; // async
        }
        if (message.type === "OPEN_SECURITY_EVENT") {
            console.log(`[VerifyFirst] OPEN_SECURITY_EVENT received, eventId=${message.eventId}, source=${message.source}`);
            pendingNavigation = {
                view: "event",
                eventId: message.eventId,
                originatingView: message.source === "overlay" ? "overview" : "overview"
            };
            const initializeAndNavigate = async () => {
                if (!isOpen()) {
                    console.log("[VerifyFirst] Security Center not open, opening with pending navigation");
                    await open();
                }
                else {
                    console.log("[VerifyFirst] Security Center already open, resolving navigation inline");
                    await resolvePendingNavigation();
                    switchView(currentView);
                }
            };
            initializeAndNavigate();
            sendResponse({ success: true });
            return true; // async
        }
    });
    console.log("VerifyFirst Security Center Controller initialized.");
})();
