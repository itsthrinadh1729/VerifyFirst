/**
 * VerifyFirst — Security Center Controller (Module 7)
 *
 * Full-page security dashboard for the VerifyFirst Chrome extension.
 * Communicates with the service worker exclusively through telemetryClient.ts.
 *
 * ALL dynamic untrusted strings are rendered using XSS-safe textContent.
 * No direct chrome.storage.local access.
 * No security logic — presentation only.
 */
import { fetchStatistics, fetchHistory, triggerExport, wipeHistory } from "../shared/telemetryClient.js";
let currentView = "overview";
let previousView = "overview";
let selectedEvent = null;
// History pagination state
const HISTORY_PAGE_SIZE = 20;
let historyPage = 0;
let historyHasMore = false;
// ============================================================
// DOM References
// ============================================================
function $(id) {
    return document.getElementById(id);
}
// Views
const views = {
    "overview": $("view-overview"),
    "link-analysis": $("view-link-analysis"),
    "history": $("view-history"),
    "event-details": $("view-event-details"),
    "settings": $("view-settings"),
};
// Nav buttons
const navButtons = document.querySelectorAll(".nav-item[data-view]");
// ============================================================
// Navigation
// ============================================================
function navigateTo(view) {
    if (view !== "event-details") {
        previousView = view;
    }
    currentView = view;
    // Toggle view visibility
    for (const [name, el] of Object.entries(views)) {
        if (name === view) {
            el.classList.add("active");
        }
        else {
            el.classList.remove("active");
        }
    }
    // Toggle nav active state
    navButtons.forEach((btn) => {
        const btnView = btn.getAttribute("data-view");
        if (btnView === view) {
            btn.classList.add("active");
        }
        else {
            btn.classList.remove("active");
        }
    });
    // Load data for the view
    switch (view) {
        case "overview":
            loadOverview();
            break;
        case "link-analysis":
            loadLinkAnalysis();
            break;
        case "history":
            loadHistory();
            break;
        case "event-details":
            renderEventDetails();
            break;
    }
}
// Sidebar nav click handlers
navButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
        const view = btn.getAttribute("data-view");
        if (view) {
            navigateTo(view);
        }
    });
});
function navigateToHistoryWithStatus(status) {
    const statusSelect = $("filter-status");
    statusSelect.value = status;
    // Reset other filters
    $("filter-protection").value = "";
    $("filter-hostname").value = "";
    $("filter-min-risk").value = "";
    $("filter-max-risk").value = "";
    $("filter-from-date").value = "";
    $("filter-to-date").value = "";
    $("filter-sort").value = "newest";
    navigateTo("history");
}
function setupStatCardInteractivity(id, status) {
    const el = $(id);
    if (!el)
        return;
    el.tabIndex = 0;
    el.classList.add("interactive-card");
    const handleInteraction = (e) => {
        e.preventDefault();
        navigateToHistoryWithStatus(status);
    };
    el.addEventListener("click", handleInteraction);
    el.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
            handleInteraction(e);
        }
    });
}
setupStatCardInteractivity("stat-total", "");
setupStatCardInteractivity("stat-safe", "SAFE");
setupStatCardInteractivity("stat-suspicious", "SUSPICIOUS");
setupStatCardInteractivity("stat-dangerous", "DANGEROUS");
const viewAllActivityBtn = $("btn-view-all-activity");
if (viewAllActivityBtn) {
    viewAllActivityBtn.addEventListener("click", (e) => {
        e.preventDefault();
        navigateToHistoryWithStatus("");
    });
}
// ============================================================
// Time Formatting
// ============================================================
function formatRelativeTime(timestamp) {
    const now = Date.now();
    const diff = now - timestamp;
    if (diff < 0)
        return "just now";
    const seconds = Math.floor(diff / 1000);
    if (seconds < 60)
        return "just now";
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60)
        return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24)
        return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    if (days < 7)
        return `${days}d ago`;
    return new Date(timestamp).toLocaleDateString();
}
function formatTimestamp(timestamp) {
    return new Date(timestamp).toLocaleString();
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
function renderHostnameText(hostname) {
    const host = hostname || 'unknown';
    // Use CSS class .table-hostname or .detail-hostname with truncation
    return host;
}
// ============================================================
// Status Badge Helpers
// ============================================================
function getStatusBadgeClass(status) {
    switch (status) {
        case "SAFE": return "badge-safe";
        case "SUSPICIOUS": return "badge-suspicious";
        case "DANGEROUS": return "badge-dangerous";
        default: return "";
    }
}
function getStatusLabel(status) {
    switch (status) {
        case "SAFE": return "SAFE";
        case "SUSPICIOUS": return "SUSPICIOUS";
        case "DANGEROUS": return "DANGEROUS";
        default: return status;
    }
}
// ============================================================
// Formatting rule names
// ============================================================
function formatRuleName(rule) {
    return rule
        .toLowerCase()
        .split("_")
        .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
        .join(" ");
}
// ============================================================
// OVERVIEW
// ============================================================
async function loadOverview() {
    const loadingEl = $("overview-loading");
    const errorEl = $("overview-error");
    const contentEl = $("overview-content");
    loadingEl.style.display = "";
    errorEl.style.display = "none";
    contentEl.style.display = "none";
    try {
        const [stats, recentEvents] = await Promise.all([
            fetchStatistics(),
            fetchHistory({ sort: "newest", limit: 5 }),
        ]);
        loadingEl.style.display = "none";
        contentEl.style.display = "";
        // Primary stats
        $("stat-total-value").textContent = String(stats.totalEvents);
        $("stat-safe-value").textContent = String(stats.safeCount);
        $("stat-suspicious-value").textContent = String(stats.suspiciousCount);
        $("stat-dangerous-value").textContent = String(stats.dangerousCount);
        // Protection activity
        $("stat-allowed-value").textContent = String(stats.allowedCount);
        $("stat-warned-value").textContent = String(stats.warnedCount);
        $("stat-blocked-value").textContent = String(stats.blockedCount);
        $("stat-hostnames-value").textContent = String(stats.uniqueHostnames);
        $("stat-avg-risk-value").textContent =
            stats.averageRiskScore !== null ? String(Math.round(stats.averageRiskScore)) : "—";
        $("stat-highest-risk-value").textContent =
            stats.highestRiskScore !== null ? String(stats.highestRiskScore) : "—";
        // Recent activity
        renderRecentActivity(recentEvents);
    }
    catch {
        loadingEl.style.display = "none";
        errorEl.style.display = "";
    }
}
function renderRecentActivity(events) {
    const listEl = $("overview-recent-list");
    const emptyEl = $("overview-recent-empty");
    listEl.innerHTML = "";
    if (events.length === 0) {
        emptyEl.style.display = "";
        return;
    }
    emptyEl.style.display = "none";
    events.forEach((event) => {
        const row = document.createElement("div");
        row.className = "event-list-item interactive-row";
        row.tabIndex = 0;
        const handleClick = () => openEventDetails(event);
        row.addEventListener("click", handleClick);
        row.addEventListener("keydown", (e) => {
            if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                handleClick();
            }
        });
        const hostname = document.createElement("div");
        hostname.className = "event-item-hostname table-hostname-trunc";
        hostname.title = event.hostname || "unknown";
        hostname.textContent = event.hostname;
        const badge = document.createElement("div");
        badge.className = `event-item-badge ${getStatusBadgeClass(event.status)}`;
        badge.textContent = getStatusLabel(event.status);
        const score = document.createElement("div");
        score.className = "event-item-score";
        score.textContent = event.riskScore !== null ? String(event.riskScore) : "—";
        const protection = document.createElement("div");
        protection.className = "event-item-protection";
        protection.textContent = event.protectionAction;
        const time = document.createElement("div");
        time.className = "event-item-time";
        time.textContent = formatRelativeTime(event.timestamp);
        row.appendChild(hostname);
        row.appendChild(badge);
        row.appendChild(score);
        row.appendChild(protection);
        row.appendChild(time);
        listEl.appendChild(row);
    });
}
$("overview-retry").addEventListener("click", () => loadOverview());
// ============================================================
// LINK ANALYSIS
// ============================================================
async function loadLinkAnalysis() {
    const loadingEl = $("link-analysis-loading");
    const errorEl = $("link-analysis-error");
    const contentEl = $("link-analysis-content");
    const emptyEl = $("link-analysis-empty");
    const tableEl = $("link-analysis-table");
    loadingEl.style.display = "";
    errorEl.style.display = "none";
    contentEl.style.display = "none";
    try {
        const events = await fetchHistory({ sort: "newest" });
        loadingEl.style.display = "none";
        contentEl.style.display = "";
        if (events.length === 0) {
            emptyEl.style.display = "";
            tableEl.style.display = "none";
            return;
        }
        emptyEl.style.display = "none";
        tableEl.style.display = "";
        renderEventTable($("link-analysis-tbody"), events);
    }
    catch {
        loadingEl.style.display = "none";
        errorEl.style.display = "";
    }
}
$("link-analysis-retry").addEventListener("click", () => loadLinkAnalysis());
// ============================================================
// SECURITY HISTORY
// ============================================================
function buildHistoryQuery() {
    const query = {};
    const status = $("filter-status").value;
    if (status)
        query.status = status;
    const protection = $("filter-protection").value;
    if (protection)
        query.protectionAction = protection;
    const hostname = $("filter-hostname").value.trim();
    if (hostname)
        query.hostname = hostname;
    const minRisk = $("filter-min-risk").value;
    if (minRisk !== "")
        query.minRiskScore = Number(minRisk);
    const maxRisk = $("filter-max-risk").value;
    if (maxRisk !== "")
        query.maxRiskScore = Number(maxRisk);
    const fromDate = $("filter-from-date").value;
    if (fromDate)
        query.fromTimestamp = new Date(fromDate).toISOString();
    const toDate = $("filter-to-date").value;
    if (toDate) {
        // Set to end of day
        const d = new Date(toDate);
        d.setHours(23, 59, 59, 999);
        query.toTimestamp = d.toISOString();
    }
    const sort = $("filter-sort").value;
    query.sort = sort;
    query.limit = HISTORY_PAGE_SIZE;
    query.offset = historyPage * HISTORY_PAGE_SIZE;
    return query;
}
async function loadHistory() {
    const loadingEl = $("history-loading");
    const errorEl = $("history-error");
    const contentEl = $("history-content");
    const emptyEl = $("history-empty");
    const tableEl = $("history-table");
    const paginationEl = $("history-pagination");
    loadingEl.style.display = "";
    errorEl.style.display = "none";
    contentEl.style.display = "none";
    try {
        const query = buildHistoryQuery();
        const events = await fetchHistory(query);
        loadingEl.style.display = "none";
        contentEl.style.display = "";
        if (events.length === 0 && historyPage === 0) {
            emptyEl.style.display = "";
            tableEl.style.display = "none";
            paginationEl.style.display = "none";
            return;
        }
        emptyEl.style.display = "none";
        tableEl.style.display = "";
        renderEventTable($("history-tbody"), events);
        // Pagination
        historyHasMore = events.length >= HISTORY_PAGE_SIZE;
        if (historyPage > 0 || historyHasMore) {
            paginationEl.style.display = "";
            $("btn-prev-page").disabled = historyPage === 0;
            $("btn-next-page").disabled = !historyHasMore;
            $("page-info").textContent = `Page ${historyPage + 1}`;
        }
        else {
            paginationEl.style.display = "none";
        }
    }
    catch {
        loadingEl.style.display = "none";
        errorEl.style.display = "";
    }
}
$("btn-apply-filters").addEventListener("click", () => {
    historyPage = 0;
    loadHistory();
});
$("btn-reset-filters").addEventListener("click", () => {
    $("filter-status").value = "";
    $("filter-protection").value = "";
    $("filter-hostname").value = "";
    $("filter-min-risk").value = "";
    $("filter-max-risk").value = "";
    $("filter-from-date").value = "";
    $("filter-to-date").value = "";
    $("filter-sort").value = "newest";
    historyPage = 0;
    loadHistory();
});
$("btn-prev-page").addEventListener("click", () => {
    if (historyPage > 0) {
        historyPage--;
        loadHistory();
    }
});
$("btn-next-page").addEventListener("click", () => {
    if (historyHasMore) {
        historyPage++;
        loadHistory();
    }
});
$("history-retry").addEventListener("click", () => loadHistory());
// ============================================================
// SHARED: Event Table Renderer
// ============================================================
function renderEventTable(tbody, events) {
    tbody.innerHTML = "";
    events.forEach((event) => {
        const tr = document.createElement("tr");
        tr.className = "interactive-row";
        tr.tabIndex = 0;
        const handleClick = () => openEventDetails(event);
        tr.addEventListener("click", handleClick);
        tr.addEventListener("keydown", (e) => {
            if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                handleClick();
            }
        });
        const tdHostname = document.createElement("td");
        const hostnameSpan = document.createElement("span");
        hostnameSpan.className = "table-hostname-trunc";
        hostnameSpan.title = event.hostname || "unknown";
        hostnameSpan.textContent = event.hostname;
        tdHostname.appendChild(hostnameSpan);
        const tdStatus = document.createElement("td");
        const statusSpan = document.createElement("span");
        statusSpan.className = `table-badge ${getStatusBadgeClass(event.status)}`;
        statusSpan.textContent = getStatusLabel(event.status);
        tdStatus.appendChild(statusSpan);
        const tdScore = document.createElement("td");
        tdScore.textContent = event.riskScore !== null ? `${event.riskScore} / 100` : "—";
        const tdProtection = document.createElement("td");
        const protectionSpan = document.createElement("span");
        protectionSpan.className = "table-protection";
        protectionSpan.textContent = event.protectionAction;
        tdProtection.appendChild(protectionSpan);
        const tdTime = document.createElement("td");
        const timeSpan = document.createElement("span");
        timeSpan.className = "table-time";
        timeSpan.textContent = formatRelativeTime(event.timestamp);
        timeSpan.title = formatTimestamp(event.timestamp);
        tdTime.appendChild(timeSpan);
        tr.appendChild(tdHostname);
        tr.appendChild(tdStatus);
        tr.appendChild(tdScore);
        tr.appendChild(tdProtection);
        tr.appendChild(tdTime);
        tbody.appendChild(tr);
    });
}
// ============================================================
// EVENT DETAILS
// ============================================================
function openEventDetails(event) {
    selectedEvent = event;
    navigateTo("event-details");
}
function renderEventDetails() {
    if (!selectedEvent)
        return;
    const event = selectedEvent;
    // Hostname
    const hostEl = $("detail-hostname");
    hostEl.textContent = event.hostname;
    hostEl.title = event.hostname || "unknown";
    hostEl.classList.add("table-hostname-trunc");
    // Status badge
    const statusBadge = $("detail-status-badge");
    statusBadge.className = `detail-status-badge ${getStatusBadgeClass(event.status)}`;
    statusBadge.textContent = getStatusLabel(event.status);
    // Risk score
    $("detail-risk-score").textContent =
        event.riskScore !== null ? `${event.riskScore} / 100` : "— / 100";
    // Protection action
    const protectionEl = $("detail-protection");
    protectionEl.textContent = event.protectionAction;
    // Reasons
    const reasonsList = $("detail-reasons-list");
    reasonsList.innerHTML = "";
    if (event.reasons.length === 0) {
        const noReasons = document.createElement("div");
        noReasons.className = "detail-reason-card";
        const noTitle = document.createElement("div");
        noTitle.className = "detail-reason-rule";
        noTitle.textContent = "No Detection Reasons";
        const noDesc = document.createElement("div");
        noDesc.className = "detail-reason-message";
        noDesc.textContent = "No specific detection reasons were provided.";
        noReasons.appendChild(noTitle);
        noReasons.appendChild(noDesc);
        reasonsList.appendChild(noReasons);
    }
    else {
        event.reasons.forEach((reason) => {
            const card = document.createElement("div");
            card.className = "detail-reason-card";
            const ruleEl = document.createElement("div");
            ruleEl.className = "detail-reason-rule";
            ruleEl.textContent = formatRuleName(reason.rule);
            const msgEl = document.createElement("div");
            msgEl.className = "detail-reason-message";
            msgEl.textContent = reason.message;
            card.appendChild(ruleEl);
            card.appendChild(msgEl);
            reasonsList.appendChild(card);
        });
    }
    // Threat Context
    const threatSection = $("detail-threat-section");
    const threatContainer = $("detail-threat-context");
    threatContainer.innerHTML = "";
    if (event.threatContext) {
        threatSection.style.display = "";
        if (event.threatContext.title) {
            const titleEl = document.createElement("div");
            titleEl.className = "threat-context-title";
            titleEl.textContent = event.threatContext.title;
            threatContainer.appendChild(titleEl);
        }
        if (event.threatContext.summary) {
            const summaryEl = document.createElement("div");
            summaryEl.className = "threat-context-summary";
            summaryEl.textContent = event.threatContext.summary;
            threatContainer.appendChild(summaryEl);
        }
        if (event.threatContext.technicalDetails && event.threatContext.technicalDetails.length > 0) {
            const detailsTitle = document.createElement("div");
            detailsTitle.className = "threat-context-details-title";
            detailsTitle.textContent = "Technical Details";
            threatContainer.appendChild(detailsTitle);
            event.threatContext.technicalDetails.forEach((detail) => {
                const detailEl = document.createElement("div");
                detailEl.className = "threat-context-detail-item";
                detailEl.textContent = detail;
                threatContainer.appendChild(detailEl);
            });
        }
        if (event.threatContext.userImpact) {
            const impactTitle = document.createElement("div");
            impactTitle.className = "threat-context-impact-title";
            impactTitle.textContent = "User Impact";
            threatContainer.appendChild(impactTitle);
            const impactEl = document.createElement("div");
            impactEl.className = "threat-context-impact";
            impactEl.textContent = event.threatContext.userImpact;
            threatContainer.appendChild(impactEl);
        }
    }
    else {
        threatSection.style.display = "none";
    }
    // Recommended Action
    const actionSection = $("detail-action-section");
    const actionEl = $("detail-recommended-action");
    if (event.threatContext && event.threatContext.recommendedAction) {
        actionSection.style.display = "";
        actionEl.textContent = event.threatContext.recommendedAction;
    }
    else {
        actionSection.style.display = "none";
    }
    // Metadata
    $("detail-timestamp").textContent = formatTimestamp(event.timestamp);
    $("detail-event-id").textContent = event.id;
}
$("btn-details-back").addEventListener("click", () => {
    navigateTo(previousView);
});
// ============================================================
// SETTINGS — Export
// ============================================================
const exportToggle = $("btn-export-toggle");
const exportMenu = $("export-dropdown-menu");
exportToggle?.addEventListener("click", (e) => {
    e.stopPropagation();
    const isExpanded = exportToggle.getAttribute("aria-expanded") === "true";
    exportToggle.setAttribute("aria-expanded", String(!isExpanded));
    exportMenu.style.display = isExpanded ? "none" : "block";
});
document.addEventListener("click", (e) => {
    if (!exportToggle.contains(e.target) && !exportMenu.contains(e.target)) {
        exportToggle.setAttribute("aria-expanded", "false");
        exportMenu.style.display = "none";
    }
});
const formatItems = document.querySelectorAll(".dropdown-item[data-format]");
formatItems.forEach((item) => {
    item.addEventListener("click", async (e) => {
        const format = e.currentTarget.getAttribute("data-format") || "json";
        exportToggle.setAttribute("aria-expanded", "false");
        exportMenu.style.display = "none";
        const originalText = exportToggle.textContent;
        exportToggle.textContent = "Exporting...";
        exportToggle.disabled = true;
        try {
            const jsonStr = await triggerExport();
            let exportData = jsonStr;
            let mimeType = "application/json";
            let extension = "json";
            const events = JSON.parse(jsonStr);
            if (format === "csv") {
                mimeType = "text/csv";
                extension = "csv";
                const header = ["ID", "Hostname", "Status", "Risk Score", "Protection Action", "Time"];
                const rows = events.map(ev => [
                    ev.id, ev.hostname, ev.status, String(ev.riskScore || ''), ev.protectionAction, new Date(ev.timestamp).toISOString()
                ]);
                exportData = [header, ...rows].map(row => row.join(",")).join("\n");
            }
            else if (format === "txt") {
                mimeType = "text/plain";
                extension = "txt";
                exportData = events.map(ev => `[${new Date(ev.timestamp).toISOString()}] ${ev.hostname} - ${ev.status} (Risk: ${ev.riskScore || '-'}) - ${ev.protectionAction}`).join("\n");
            }
            const blob = new Blob([exportData], { type: mimeType });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `verifyfirst-security-history.${extension}`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            exportToggle.textContent = "Exported ✓";
            setTimeout(() => {
                exportToggle.textContent = originalText;
                exportToggle.disabled = false;
            }, 2000);
        }
        catch {
            exportToggle.textContent = "Export Failed";
            setTimeout(() => {
                exportToggle.textContent = originalText;
                exportToggle.disabled = false;
            }, 2000);
        }
    });
});
// ============================================================
// SETTINGS — Clear History
// ============================================================
const clearModal = $("clear-confirm-modal");
$("btn-clear").addEventListener("click", () => {
    clearModal.style.display = "";
});
$("btn-clear-cancel").addEventListener("click", () => {
    clearModal.style.display = "none";
});
$("btn-clear-confirm").addEventListener("click", async () => {
    const btn = $("btn-clear-confirm");
    btn.textContent = "Clearing...";
    btn.disabled = true;
    try {
        await wipeHistory();
        clearModal.style.display = "none";
        btn.textContent = "Clear History";
        btn.disabled = false;
        // Refresh overview and history if they were loaded
        if (currentView === "settings") {
            // Preload fresh data so navigating away shows zeros
            loadOverview();
        }
    }
    catch {
        btn.textContent = "Failed";
        setTimeout(() => {
            btn.textContent = "Clear History";
            btn.disabled = false;
        }, 2000);
    }
});
// ============================================================
// INITIALIZATION
// ============================================================
document.addEventListener("DOMContentLoaded", () => {
    navigateTo("overview");
});
