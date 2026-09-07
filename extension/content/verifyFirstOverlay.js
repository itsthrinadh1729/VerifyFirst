"use strict";
/**
 * VerifyFirst — In-Page Security Warning Overlay for WhatsApp Web
 *
 * Automatically displays a floating security warning inside WhatsApp Web
 * when an external link is classified as SUSPICIOUS, DANGEROUS, or ANALYSIS_UNAVAILABLE.
 *
 * Uses Shadow DOM to isolate styles and XSS-safe DOM rendering for all untrusted strings.
 *
 * Official Design System:
 * - Brand: Warm Gold (#FFE082) & Boxed "S" Security Mark
 * - Interactive/Accent: Cyan (#22D3EE)
 * - Deep Background: Navy Black (#0B141A)
 * - Surface/Cards: Dark Slate (#1E2A33)
 */
(function () {
    console.log("[VerifyFirst] Overlay module loaded");
    // Track URLs for which warnings have already been displayed in the active chat
    const displayedWarnings = new Set();
    const OVERLAY_CONTAINER_ID = "verifyfirst-overlay-host";
    let overlayDismissTimer = null;
    function resetDismissTimer(delayMs = 8000) {
        if (overlayDismissTimer !== null) {
            window.clearTimeout(overlayDismissTimer);
        }
        overlayDismissTimer = window.setTimeout(() => {
            clearVerifyFirstOverlay();
        }, delayMs);
    }
    function pauseDismissTimer() {
        if (overlayDismissTimer !== null) {
            window.clearTimeout(overlayDismissTimer);
            overlayDismissTimer = null;
        }
    }
    /**
     * Formats raw rule names into user-friendly title casing.
     */
    function formatRuleTitle(rule) {
        return rule
            .toLowerCase()
            .split("_")
            .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
            .join(" ");
    }
    /**
     * Removes active in-page warning overlay element from the DOM.
     */
    function clearVerifyFirstOverlay() {
        if (overlayDismissTimer !== null) {
            window.clearTimeout(overlayDismissTimer);
            overlayDismissTimer = null;
        }
        const host = document.getElementById(OVERLAY_CONTAINER_ID);
        if (host && host.parentNode) {
            host.parentNode.removeChild(host);
        }
    }
    /**
     * Resets the set of displayed warnings (called on chat switch).
     */
    function resetDisplayedWarnings() {
        displayedWarnings.clear();
        clearVerifyFirstOverlay();
    }
    /**
     * Displays an automatic security warning overlay inside WhatsApp Web.
     */
    function showVerifyFirstWarning(record, force = false) {
        // SAFE links remain silent
        if (!record || record.status === "SAFE") {
            return;
        }
        const normalizedUrl = (record.url || "").trim().toLowerCase();
        if (!force && displayedWarnings.has(normalizedUrl)) {
            return; // Already displayed for this URL in the active chat session
        }
        displayedWarnings.add(normalizedUrl);
        // Remove any existing overlay before rendering
        clearVerifyFirstOverlay();
        // Host element
        const host = document.createElement("div");
        host.id = OVERLAY_CONTAINER_ID;
        host.style.position = "fixed";
        host.style.top = "16px";
        host.style.right = "16px";
        host.style.zIndex = "2147483647";
        host.style.pointerEvents = "auto";
        host.style.display = "block";
        // Shadow DOM for style isolation
        const shadow = host.attachShadow({ mode: "open" });
        // Stylesheet matching Master Design System
        const style = document.createElement("style");
        style.textContent = `
      :host {
        position: fixed !important;
        top: 16px !important;
        right: 16px !important;
        z-index: 2147483647 !important;
        display: block !important;
        pointer-events: auto !important;
      }
      * { box-sizing: border-box; margin: 0; padding: 0; }
      .overlay-card {
        width: 310px;
        max-width: min(310px, calc(100vw - 32px));
        min-height: auto;
        background: #0B141A;
        color: #F8FAFC;
        border-radius: 12px;
        padding: 12px 14px;
        font-family: 'Poppins', 'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        box-shadow: 0 12px 32px rgba(0, 0, 0, 0.55), 0 2px 8px rgba(0, 0, 0, 0.35);
        border: 1px solid rgba(148, 163, 184, 0.22);
        animation: vfFadeSlide 200ms ease-out;
        pointer-events: auto;
      }
      @keyframes vfFadeSlide {
        from { opacity: 0; transform: translateY(-8px); }
        to { opacity: 1; transform: translateY(0); }
      }
      .overlay-card.suspicious { border: 1px solid rgba(255, 224, 130, 0.85); box-shadow: 0 12px 32px rgba(0, 0, 0, 0.55), 0 0 12px rgba(255, 224, 130, 0.2); }
      .overlay-card.dangerous { border: 1px solid #F87171; box-shadow: 0 12px 32px rgba(0, 0, 0, 0.55), 0 0 14px rgba(248, 113, 113, 0.25); }
      .overlay-card.analysis_unavailable, .overlay-card.unavailable { border: 1px solid rgba(148, 163, 184, 0.4); }

      .header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding-bottom: 6px;
        margin-bottom: 9px;
        border-bottom: 1px solid rgba(148, 163, 184, 0.15);
      }
      .brand {
        display: flex;
        align-items: center;
      }
      .brand-logo {
        height: 30px;
        width: auto;
        display: block;
      }
      .close-btn {
        background: transparent;
        border: none;
        color: #8696A0;
        font-size: 18px;
        cursor: pointer;
        line-height: 1;
        padding: 0 4px;
        border-radius: 4px;
        transition: color 150ms ease;
      }
      .close-btn:hover { color: #F8FAFC; }

      .status-title {
        font-size: 13px;
        font-weight: 700;
        margin-bottom: 8px;
        display: flex;
        align-items: center;
        gap: 5px;
      }
      .suspicious .status-title { color: #FFE082; }
      .dangerous .status-title { color: #F87171; }
      .analysis_unavailable .status-title, .unavailable .status-title { color: #94A3B8; }

      .score-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        background: #1E2A33;
        border: 1px solid rgba(148, 163, 184, 0.10);
        border-radius: 6px;
        padding: 7px 9px;
        margin-bottom: 8px;
      }
      .score-label {
        color: #94A3B8;
        font-weight: 600;
        text-transform: uppercase;
        font-size: 8px;
        letter-spacing: 0.5px;
      }
      .score-val {
        font-weight: 700;
        font-size: 14px;
        color: #F8FAFC;
      }

      .explanation-text {
        font-size: 11px;
        line-height: 1.35;
        color: #94A3B8;
        margin-bottom: 8px;
      }

      .url-box {
        font-family: SFMono-Regular, Consolas, 'Liberation Mono', Menlo, monospace;
        font-size: 11px;
        color: #CBD5E1;
        background: #0B141A;
        padding: 7px 8px;
        border-radius: 5px;
        border: 1px solid rgba(148, 163, 184, 0.18);
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        margin-bottom: 10px;
      }

      .actions {
        display: flex;
        gap: 6px;
        justify-content: flex-end;
      }
      .btn {
        font-size: 11px;
        font-weight: 600;
        padding: 5px 11px;
        border-radius: 5px;
        cursor: pointer;
        border: none;
        transition: background-color 150ms ease, color 150ms ease, opacity 150ms ease;
      }
      .btn-secondary {
        background: #1E2A33;
        border: 1px solid rgba(148, 163, 184, 0.20);
        color: #CBD5E1;
      }
      .btn-secondary:hover { background: #26343B; color: #F8FAFC; }
      .btn-primary {
        background: #22D3EE;
        color: #0B141A;
      }
      .btn-primary:hover { opacity: 0.9; }

      /* Detail View Specific Styles */
      .back-link {
        background: transparent;
        border: none;
        color: #8696A0;
        font-size: 12px;
        font-weight: 600;
        cursor: pointer;
        display: flex;
        align-items: center;
        gap: 4px;
        padding: 2px 4px;
        border-radius: 4px;
        transition: color 150ms ease;
      }
      .back-link:hover { color: #F8FAFC; }

      .section-label {
        font-size: 9px;
        font-weight: 600;
        color: #94A3B8;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 6px;
        margin-top: 6px;
      }

      .indicators-list {
        display: flex;
        flex-direction: column;
        gap: 6px;
        max-height: 160px;
        overflow-y: auto;
        margin-bottom: 9px;
      }

      .indicator-item {
        background: #1E2A33;
        border-left: 3px solid #22D3EE;
        padding: 7px 8px;
        border-radius: 0 5px 5px 0;
      }
      .suspicious .indicator-item { border-left-color: #FFE082; }
      .dangerous .indicator-item { border-left-color: #F87171; }
      .analysis_unavailable .indicator-item, .unavailable .indicator-item { border-left-color: #94A3B8; }

      .indicator-title {
        font-size: 11px;
        font-weight: 700;
        color: #F8FAFC;
        margin-bottom: 2px;
      }

      .indicator-desc {
        font-size: 10px;
        color: #94A3B8;
        line-height: 1.3;
      }
    `;
        shadow.appendChild(style);
        const card = document.createElement("div");
        card.className = `overlay-card ${record.status.toLowerCase()}`;
        // Helper to create VerifyFirst Brand Logo (using logo.svg with inline SVG fallback)
        function createBrandLogo() {
            const img = document.createElement("img");
            img.className = "brand-logo";
            try {
                img.src = chrome.runtime.getURL("assets/logo.svg");
            }
            catch {
                // In case chrome.runtime is unavailable
            }
            img.alt = "VerifyFirst";
            img.onerror = () => {
                // Fallback text mark if image fails
                img.style.display = "none";
                const fallback = document.createElement("span");
                fallback.style.fontSize = "13px";
                fallback.style.fontWeight = "800";
                fallback.style.color = "#FFE082";
                fallback.style.letterSpacing = "0.5px";
                fallback.textContent = "VERIFYFIRST";
                img.parentNode?.replaceChild(fallback, img);
            };
            return img;
        }
        // Render Overview View (Main Warning Card)
        function renderOverviewView() {
            card.innerHTML = "";
            // Header Row
            const header = document.createElement("div");
            header.className = "header";
            const brand = document.createElement("div");
            brand.className = "brand";
            brand.appendChild(createBrandLogo());
            const closeBtn = document.createElement("button");
            closeBtn.type = "button";
            closeBtn.className = "close-btn";
            closeBtn.textContent = "×";
            closeBtn.addEventListener("click", clearVerifyFirstOverlay);
            header.appendChild(brand);
            header.appendChild(closeBtn);
            card.appendChild(header);
            // Warning Title
            const statusTitle = document.createElement("div");
            statusTitle.className = "status-title";
            if (record.status === "SUSPICIOUS") {
                statusTitle.textContent = "⚠ Suspicious link detected";
            }
            else if (record.status === "DANGEROUS") {
                statusTitle.textContent = "⚠ Dangerous link detected";
            }
            else {
                statusTitle.textContent = "⚠ Analysis unavailable";
            }
            card.appendChild(statusTitle);
            // Risk Score Row
            const scoreRow = document.createElement("div");
            scoreRow.className = "score-row";
            const scoreLabel = document.createElement("span");
            scoreLabel.className = "score-label";
            scoreLabel.textContent = "RISK SCORE";
            const scoreVal = document.createElement("span");
            scoreVal.className = "score-val";
            if (record.status === "ANALYSIS_UNAVAILABLE") {
                scoreVal.textContent = "— / 100";
            }
            else {
                scoreVal.textContent = `${record.risk_score ?? 0} / 100`;
            }
            scoreRow.appendChild(scoreLabel);
            scoreRow.appendChild(scoreVal);
            card.appendChild(scoreRow);
            // Explanation Text
            const explanationText = document.createElement("div");
            explanationText.className = "explanation-text";
            if (record.status === "SUSPICIOUS") {
                explanationText.textContent = "Suspicious characteristics were detected in this URL.";
            }
            else if (record.status === "DANGEROUS") {
                explanationText.textContent = "This link shows characteristics commonly associated with unsafe URLs.";
            }
            else {
                explanationText.textContent = "VerifyFirst could not complete the security analysis.";
            }
            card.appendChild(explanationText);
            // URL Box
            const urlBox = document.createElement("div");
            urlBox.className = "url-box";
            urlBox.textContent = record.url;
            card.appendChild(urlBox);
            // Action Buttons
            const actions = document.createElement("div");
            actions.className = "actions";
            const dismissBtn = document.createElement("button");
            dismissBtn.type = "button";
            dismissBtn.className = "btn btn-secondary";
            dismissBtn.textContent = "Dismiss";
            dismissBtn.addEventListener("click", clearVerifyFirstOverlay);
            const detailsBtn = document.createElement("button");
            detailsBtn.type = "button";
            detailsBtn.className = "btn btn-primary";
            detailsBtn.textContent = "View Details";
            detailsBtn.addEventListener("click", renderDetailsView);
            actions.appendChild(dismissBtn);
            actions.appendChild(detailsBtn);
            card.appendChild(actions);
        }
        // Render Details View (In-Place Expanded Indicators View)
        function renderDetailsView() {
            resetDismissTimer();
            card.innerHTML = "";
            // Header Row with Back button & Brand
            const header = document.createElement("div");
            header.className = "header";
            const backLink = document.createElement("button");
            backLink.type = "button";
            backLink.className = "back-link";
            backLink.textContent = "← Back";
            backLink.addEventListener("click", renderOverviewView);
            const brand = document.createElement("div");
            brand.className = "brand";
            brand.appendChild(createBrandLogo());
            const closeBtn = document.createElement("button");
            closeBtn.type = "button";
            closeBtn.className = "close-btn";
            closeBtn.textContent = "×";
            closeBtn.addEventListener("click", clearVerifyFirstOverlay);
            header.appendChild(backLink);
            header.appendChild(brand);
            header.appendChild(closeBtn);
            card.appendChild(header);
            // Status Title
            const statusTitle = document.createElement("div");
            statusTitle.className = "status-title";
            if (record.status === "SUSPICIOUS") {
                statusTitle.textContent = "⚠ Suspicious link";
            }
            else if (record.status === "DANGEROUS") {
                statusTitle.textContent = "⚠ Dangerous link";
            }
            else {
                statusTitle.textContent = "⚠ Analysis unavailable";
            }
            card.appendChild(statusTitle);
            // Risk Score Row
            const scoreRow = document.createElement("div");
            scoreRow.className = "score-row";
            const scoreLabel = document.createElement("span");
            scoreLabel.className = "score-label";
            scoreLabel.textContent = "RISK SCORE";
            const scoreVal = document.createElement("span");
            scoreVal.className = "score-val";
            if (record.status === "ANALYSIS_UNAVAILABLE") {
                scoreVal.textContent = "— / 100";
            }
            else {
                scoreVal.textContent = `${record.risk_score ?? 0} / 100`;
            }
            scoreRow.appendChild(scoreLabel);
            scoreRow.appendChild(scoreVal);
            card.appendChild(scoreRow);
            // URL Box
            const urlBox = document.createElement("div");
            urlBox.className = "url-box";
            urlBox.textContent = record.url;
            card.appendChild(urlBox);
            // Section Label
            const sectionLabel = document.createElement("div");
            sectionLabel.className = "section-label";
            sectionLabel.textContent = "DETECTED INDICATORS";
            card.appendChild(sectionLabel);
            // Indicators List
            const list = document.createElement("div");
            list.className = "indicators-list";
            if (record.status === "ANALYSIS_UNAVAILABLE") {
                const item = document.createElement("div");
                item.className = "indicator-item";
                const title = document.createElement("div");
                title.className = "indicator-title";
                title.textContent = "Service Unavailable";
                const desc = document.createElement("div");
                desc.className = "indicator-desc";
                desc.textContent = "The backend detection service could not complete the security analysis for this link.";
                item.appendChild(title);
                item.appendChild(desc);
                list.appendChild(item);
            }
            else if (!record.reasons || record.reasons.length === 0) {
                const item = document.createElement("div");
                item.className = "indicator-item";
                const title = document.createElement("div");
                title.className = "indicator-title";
                title.textContent = "Risk Threshold Exceeded";
                const desc = document.createElement("div");
                desc.className = "indicator-desc";
                desc.textContent = "Overall characteristics exceeded the safety threshold.";
                item.appendChild(title);
                item.appendChild(desc);
                list.appendChild(item);
            }
            else {
                record.reasons.forEach((reason) => {
                    const item = document.createElement("div");
                    item.className = "indicator-item";
                    const title = document.createElement("div");
                    title.className = "indicator-title";
                    title.textContent = formatRuleTitle(reason.rule);
                    const desc = document.createElement("div");
                    desc.className = "indicator-desc";
                    desc.textContent = reason.message;
                    item.appendChild(title);
                    item.appendChild(desc);
                    list.appendChild(item);
                });
            }
            card.appendChild(list);
            // Action Buttons Row (Back + Dismiss)
            const actions = document.createElement("div");
            actions.className = "actions";
            const backBtn = document.createElement("button");
            backBtn.type = "button";
            backBtn.className = "btn btn-secondary";
            backBtn.textContent = "Back";
            backBtn.addEventListener("click", renderOverviewView);
            const dismissBtn = document.createElement("button");
            dismissBtn.type = "button";
            dismissBtn.className = "btn btn-secondary";
            dismissBtn.textContent = "Dismiss";
            dismissBtn.addEventListener("click", clearVerifyFirstOverlay);
            actions.appendChild(backBtn);
            actions.appendChild(dismissBtn);
            card.appendChild(actions);
        }
        // Initial Overview Render
        renderOverviewView();
        // Pause dismiss timer when user hovers over the warning card
        card.addEventListener("mouseenter", () => {
            pauseDismissTimer();
        });
        card.addEventListener("mouseleave", () => {
            resetDismissTimer(6000);
        });
        shadow.appendChild(card);
        const targetParent = document.body || document.documentElement;
        targetParent.appendChild(host);
        console.log(`[VerifyFirst] Warning visible`);
        resetDismissTimer(8000);
    }
    // Attach functions to window scope for non-module content script execution
    if (typeof window !== "undefined") {
        window.VerifyFirstOverlay = {
            showVerifyFirstWarning,
            clearVerifyFirstOverlay,
            resetDisplayedWarnings,
        };
    }
})();
