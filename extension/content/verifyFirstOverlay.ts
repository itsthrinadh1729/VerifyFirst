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

interface OverlayDetectionReason {
  rule: string;
  message: string;
}

interface OverlayAnalysisRecord {
  url: string;
  status: "SAFE" | "SUSPICIOUS" | "DANGEROUS" | "ANALYSIS_UNAVAILABLE";
  risk_score: number | null;
  reasons: OverlayDetectionReason[];
  threat_context?: {
    title: string;
    summary: string;
    technical_details: string[];
    user_impact: string;
    recommended_action: string;
  } | null;
  timestamp: number;
  eventId?: string;
  assetType?: "url" | "file" | "message";
  filename?: string;
  messagePreview?: string;
}

(function () {
  console.log("[VerifyFirst] Overlay module loaded");
  // Track URLs for which warnings have already been displayed in the active chat
  const displayedWarnings: Set<string> = new Set<string>();
  const dismissedWarnings: Set<string> = new Set<string>();
  let currentWarningUrl: string | null = null;
  let activeWarningPool: OverlayAnalysisRecord[] = [];
  const OVERLAY_CONTAINER_ID = "verifyfirst-overlay-host";
  let overlayDismissTimer: number | null = null;

  function resetDismissTimer(delayMs: number = 8000): void {
    if (overlayDismissTimer !== null) {
      window.clearTimeout(overlayDismissTimer);
    }
    overlayDismissTimer = window.setTimeout(() => {
      clearVerifyFirstOverlay();
    }, delayMs);
  }

  function pauseDismissTimer(): void {
    if (overlayDismissTimer !== null) {
      window.clearTimeout(overlayDismissTimer);
      overlayDismissTimer = null;
    }
  }

  function formatRuleTitle(rule: string): string {
    return rule
      .toLowerCase()
      .split("_")
      .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
      .join(" ");
  }

  function escapeHtml(value: unknown): string {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  /**
   * Removes active in-page warning overlay element from the DOM.
   */
  function clearVerifyFirstOverlay(): void {
    if (overlayDismissTimer !== null) {
      window.clearTimeout(overlayDismissTimer);
      overlayDismissTimer = null;
    }

    const host = document.getElementById(OVERLAY_CONTAINER_ID);
    if (host && host.parentNode) {
      host.parentNode.removeChild(host);
    }
    
    // Reset transient UI state on close
    currentViewType = "overview";
    currentWarningUrl = null;
    activeWarningPool = [];
  }

  /**
   * Resets the set of displayed warnings (called on chat switch).
   */
  function resetDisplayedWarnings(): void {
    displayedWarnings.clear();
    dismissedWarnings.clear();
    currentWarningUrl = null;
    activeWarningPool = [];
    clearVerifyFirstOverlay();
  }

  /**
   * Displays an automatic security warning overlay inside WhatsApp Web.
   */
  function handleDismiss(): void {
    if (currentWarningUrl) {
      dismissedWarnings.add(currentWarningUrl.trim().toLowerCase());
    }
    activeWarningPool = activeWarningPool.filter(r => r.url !== currentWarningUrl);
    if (activeWarningPool.length > 0) {
      currentWarningUrl = activeWarningPool[0].url;
      renderCurrentOverlayView("overview");
    } else {
      clearVerifyFirstOverlay();
    }
  }

  function goNextWarning(): void {
    if (activeWarningPool.length <= 1) return;
    let idx = activeWarningPool.findIndex(r => r.url === currentWarningUrl);
    if (idx < 0) idx = 0;
    if (idx < activeWarningPool.length - 1) {
      currentWarningUrl = activeWarningPool[idx + 1].url;
      renderCurrentOverlayView("overview");
    }
  }

  function goPrevWarning(): void {
    if (activeWarningPool.length <= 1) return;
    let idx = activeWarningPool.findIndex(r => r.url === currentWarningUrl);
    if (idx < 0) idx = 0;
    if (idx > 0) {
      currentWarningUrl = activeWarningPool[idx - 1].url;
      renderCurrentOverlayView("overview");
    }
  }

  let currentViewType: "overview" | "details" = "overview";

  /**
   * Shared overlay stylesheet for the Shadow DOM.
   */
  const OVERLAY_STYLES = `
      :host {
        position: fixed !important;
        top: 24px !important;
        right: 24px !important;
        z-index: 2147483647 !important;
        display: block !important;
        pointer-events: none !important;
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
      .header { display: flex; align-items: center; justify-content: space-between; padding-bottom: 6px; margin-bottom: 9px; border-bottom: 1px solid rgba(148, 163, 184, 0.15); }
      .brand { display: flex; align-items: center; }
      .brand-logo { height: 30px; width: auto; display: block; }
      .close-btn { background: transparent; border: none; color: #8696A0; font-size: 18px; cursor: pointer; line-height: 1; padding: 0 4px; border-radius: 4px; transition: color 150ms ease; }
      .close-btn:hover { color: #F8FAFC; }
      .status-title { font-size: 14px; font-weight: 700; margin-bottom: 8px; display: flex; align-items: center; gap: 5px; }
      .suspicious .status-title { color: #FFE082; }
      .dangerous .status-title { color: #F87171; }
      .analysis_unavailable .status-title, .unavailable .status-title { color: #94A3B8; }
      .score-row { display: flex; justify-content: space-between; align-items: center; background: #1E2A33; border: 1px solid rgba(148, 163, 184, 0.10); border-radius: 6px; padding: 7px 9px; margin-bottom: 8px; }
      .score-label { color: #CBD5E1; font-weight: 600; text-transform: uppercase; font-size: 10px; letter-spacing: 0.5px; }
      .score-val { font-weight: 700; font-size: 16px; color: #F8FAFC; }
      .explanation-text { font-size: 12px; line-height: 1.4; color: #CBD5E1; margin-bottom: 8px; }
      .url-box { font-family: SFMono-Regular, Consolas, 'Liberation Mono', Menlo, monospace; font-size: 12px; color: #E2E8F0; background: #0B141A; padding: 8px 10px; border-radius: 5px; border: 1px solid rgba(148, 163, 184, 0.18); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; margin-bottom: 10px; }
      .nav-controls { display: flex; align-items: center; gap: 12px; color: #E2E8F0; font-size: 12px; font-weight: 600; }
      .nav-btn { background: transparent; border: none; color: #8696A0; font-size: 16px; cursor: pointer; padding: 2px 8px; border-radius: 4px; transition: color 150ms ease, background 150ms ease; }
      .nav-btn:hover { color: #F8FAFC; background: rgba(148, 163, 184, 0.15); }
      .nav-btn:disabled { color: rgba(134, 150, 160, 0.4); cursor: default; background: transparent; }
      .actions { display: flex; gap: 6px; justify-content: flex-end; }
      .action-col { display: flex; flex-direction: column; gap: 8px; }
      .action-row { display: flex; align-items: center; justify-content: flex-end; gap: 6px; }
      .action-row.has-nav { justify-content: space-between; }
      .btn { font-size: 12px; font-weight: 600; padding: 6px 12px; border-radius: 5px; cursor: pointer; border: none; transition: background-color 150ms ease, color 150ms ease, opacity 150ms ease; }
      .btn-secondary { background: #1E2A33; border: 1px solid rgba(148, 163, 184, 0.20); color: #CBD5E1; }
      .btn-secondary:hover { background: #26343B; color: #F8FAFC; }
      .btn-primary { background: #22D3EE; color: #0B141A; }
      .btn-primary:hover { opacity: 0.9; }
      .back-link { background: transparent; border: none; color: #8696A0; font-size: 12px; font-weight: 600; cursor: pointer; display: flex; align-items: center; gap: 4px; padding: 2px 4px; border-radius: 4px; transition: color 150ms ease; }
      .back-link:hover { color: #F8FAFC; }
      .section-label { font-size: 10px; font-weight: 600; color: #CBD5E1; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; margin-top: 6px; }
      .indicators-list { display: flex; flex-direction: column; gap: 6px; max-height: 160px; overflow-y: auto; margin-bottom: 9px; }
      .indicator-item { background: #1E2A33; border-left: 3px solid #22D3EE; padding: 7px 8px; border-radius: 0 5px 5px 0; }
      .suspicious .indicator-item { border-left-color: #FFE082; }
      .dangerous .indicator-item { border-left-color: #F87171; }
      .analysis_unavailable .indicator-item, .unavailable .indicator-item { border-left-color: #94A3B8; }
      .indicator-title { font-size: 12px; font-weight: 700; color: #F8FAFC; margin-bottom: 2px; }
      .indicator-desc { font-size: 11px; color: #CBD5E1; line-height: 1.3; }
  `;

  /** MutationObserver to re-attach overlay host if WhatsApp removes it */
  let hostRecoveryObserver: MutationObserver | null = null;

  /**
   * Ensures a single, body-level Shadow DOM host exists for the overlay.
   *
   * Architecture:
   *   document.body
   *     └── #verifyfirst-overlay-host  (position:fixed, pointer-events:none)
   *            └── ShadowRoot
   *                   ├── <style>
   *                   └── .overlay-card  (pointer-events:auto)
   */
  function ensureOverlayHost(): { host: HTMLElement; shadow: ShadowRoot; card: HTMLDivElement } {
    let host = document.getElementById(OVERLAY_CONTAINER_ID);
    let shadow: ShadowRoot;
    let card: HTMLDivElement;

    if (host && host.shadowRoot) {
      shadow = host.shadowRoot;
      card = shadow.querySelector('.overlay-card') as HTMLDivElement;
      if (!card) {
        console.log("[VerifyFirst] Overlay card created");
        card = document.createElement("div");
        shadow.appendChild(card);
      }
      if (!host.parentNode) {
        (document.body || document.documentElement).appendChild(host);
        console.log("[VerifyFirst] Overlay host attached", { connected: document.body.contains(host), parent: host.parentElement?.tagName });
      }
    } else {
      if (host && host.parentNode) host.parentNode.removeChild(host);

      console.log("[VerifyFirst] Creating overlay host");
      host = document.createElement("div");
      host.id = OVERLAY_CONTAINER_ID;
      host.style.position = "fixed";
      host.style.top = "24px";
      host.style.right = "24px";
      host.style.zIndex = "2147483647";
      host.style.pointerEvents = "none";
      host.style.display = "block";

      shadow = host.attachShadow({ mode: "open" });
      const style = document.createElement("style");
      style.textContent = OVERLAY_STYLES;
      shadow.appendChild(style);

      card = document.createElement("div");
      console.log("[VerifyFirst] Overlay card created");
      shadow.appendChild(card);
      card.addEventListener("mouseenter", () => pauseDismissTimer());
      card.addEventListener("mouseleave", () => resetDismissTimer(6000));

      if (document.body) {
        document.body.appendChild(host);
        console.log("[VerifyFirst] Overlay host attached", { connected: document.body.contains(host), parent: host.parentElement?.tagName });
      } else {
        window.addEventListener("DOMContentLoaded", () => {
          if (host && !host.parentNode) {
            document.body.appendChild(host);
            console.log("[VerifyFirst] Overlay host attached", { connected: document.body.contains(host), parent: host.parentElement?.tagName });
          }
        }, { once: true });
      }

      if (!hostRecoveryObserver) {
        hostRecoveryObserver = new MutationObserver(() => {
          const existing = document.getElementById(OVERLAY_CONTAINER_ID);
          if (!existing && activeWarningPool.length > 0) {
            console.log("[VerifyFirst] Overlay host removed by page, re-attaching");
            renderCurrentOverlayView();
          }
        });
        if (document.body) hostRecoveryObserver.observe(document.body, { childList: true });
      }
    }
    return { host, shadow, card };
  }

  function renderCurrentOverlayView(viewType?: "overview" | "details"): void {
    if (viewType) currentViewType = viewType;
    const record = activeWarningPool.find(r => r.url === currentWarningUrl) || activeWarningPool[0];
    if (!record) {
      clearVerifyFirstOverlay();
      return;
    }
    currentWarningUrl = record.url;

    console.log("[VerifyFirst] Rendering overlay", { url: currentWarningUrl, itemCount: activeWarningPool.length });

    const { host, shadow, card } = ensureOverlayHost();

    card.className = `overlay-card ${record.status.toLowerCase()}`;
    card.innerHTML = "";

    function createBrandLogo(): HTMLElement {
      const img = document.createElement("img");
      img.className = "brand-logo";
      try { img.src = chrome.runtime.getURL("assets/logo.svg"); } catch {}
      img.alt = "VerifyFirst";
      img.onerror = () => {
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

    if (currentViewType === "overview") {
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

      const statusTitle = document.createElement("div");
      statusTitle.className = "status-title";
      let assetLabel = "link";
      if (record.assetType === "file") assetLabel = "file";
      else if (record.assetType === "message") assetLabel = "message";
      
      if (record.status === "SUSPICIOUS") {
        statusTitle.textContent = record.threat_context ? `⚠ ${record.threat_context.title}` : `⚠ Suspicious ${assetLabel} detected`;
      } else if (record.status === "DANGEROUS") {
        statusTitle.textContent = record.threat_context ? `⚠ ${record.threat_context.title}` : `⚠ Dangerous ${assetLabel} detected`;
      } else {
        statusTitle.textContent = "⚠ Analysis unavailable";
      }
      card.appendChild(statusTitle);

      const scoreRow = document.createElement("div");
      scoreRow.className = "score-row";

      const scoreLabel = document.createElement("span");
      scoreLabel.className = "score-label";
      scoreLabel.textContent = "RISK SCORE";

      const scoreVal = document.createElement("span");
      scoreVal.className = "score-val";
      if (record.status === "ANALYSIS_UNAVAILABLE") {
        scoreVal.textContent = "— / 100";
      } else {
        scoreVal.textContent = `${record.risk_score ?? 0} / 100`;
      }
      scoreRow.appendChild(scoreLabel);
      scoreRow.appendChild(scoreVal);
      card.appendChild(scoreRow);

      const explanationText = document.createElement("div");
      explanationText.className = "explanation-text";
      if (record.threat_context) {
        explanationText.innerHTML = `<strong>Why:</strong> ${escapeHtml(record.threat_context.summary)}`;
      } else if (record.status === "SUSPICIOUS") {
        if (record.assetType === "message") {
          explanationText.textContent = "This message shows suspicious characteristics.";
        } else if (record.assetType === "file") {
          explanationText.textContent = "This file shows suspicious characteristics.";
        } else {
          explanationText.textContent = "Suspicious characteristics were detected in this URL.";
        }
      } else if (record.status === "DANGEROUS") {
        if (record.assetType === "message") {
          explanationText.textContent = "This message has characteristics commonly associated with scams or phishing.";
        } else if (record.assetType === "file") {
          explanationText.textContent = "This file has characteristics commonly associated with unsafe files.";
        } else {
          explanationText.textContent = "This link shows characteristics commonly associated with unsafe URLs.";
        }
      } else {
        explanationText.textContent = "VerifyFirst could not complete the security analysis.";
      }
      card.appendChild(explanationText);
      
      if (record.threat_context && record.status === "DANGEROUS") {
        const recommendedText = document.createElement("div");
        recommendedText.className = "explanation-text";
        recommendedText.innerHTML = `<strong>Recommended:</strong> ${escapeHtml(record.threat_context.recommended_action)}`;
        card.appendChild(recommendedText);
      }

      const urlBox = document.createElement("div");
      urlBox.className = "url-box";
      if (record.assetType === "message") {
        urlBox.textContent = record.messagePreview || record.url.slice(0, 100);
      } else if (record.assetType === "file") {
        urlBox.textContent = record.filename || record.url;
      } else {
        urlBox.textContent = record.url;
      }
      card.appendChild(urlBox);

      // Navigation & Actions
      const actionCol = document.createElement("div");
      actionCol.className = "action-col";
      
      const actionRow = document.createElement("div");
      actionRow.className = "action-row";

      if (activeWarningPool.length > 1) {
        actionRow.classList.add("has-nav");
        
        const navControls = document.createElement("div");
        navControls.className = "nav-controls";
        
        const prevBtn = document.createElement("button");
        prevBtn.type = "button";
        prevBtn.className = "nav-btn";
        prevBtn.textContent = "‹";
        
        const currentIndex = activeWarningPool.findIndex(r => r.url === currentWarningUrl);
        
        if (currentIndex <= 0) {
          prevBtn.disabled = true;
        } else {
          prevBtn.addEventListener("click", goPrevWarning);
        }
        
        const label = document.createElement("span");
        label.textContent = `${Math.max(1, currentIndex + 1)} of ${activeWarningPool.length}`;
        
        const nextBtn = document.createElement("button");
        nextBtn.type = "button";
        nextBtn.className = "nav-btn";
        nextBtn.textContent = "›";
        
        if (currentIndex >= activeWarningPool.length - 1) {
          nextBtn.disabled = true;
        } else {
          nextBtn.addEventListener("click", goNextWarning);
        }
        
        navControls.appendChild(prevBtn);
        navControls.appendChild(label);
        navControls.appendChild(nextBtn);
        actionRow.appendChild(navControls);
      }

      const buttonsGroup = document.createElement("div");
      buttonsGroup.style.display = "flex";
      buttonsGroup.style.gap = "6px";

      if (record.status === "SUSPICIOUS") {
        const detailsBtn = document.createElement("button");
        detailsBtn.type = "button";
        detailsBtn.className = "btn btn-secondary";
        detailsBtn.textContent = "Details";
        detailsBtn.addEventListener("click", () => {
          const eventId = record.eventId;
          if (!eventId) {
            console.error("[VerifyFirst] Details clicked but no eventId on record");
            return;
          }
          console.log(`[VerifyFirst] Details clicked, eventId=${eventId}`);
          clearVerifyFirstOverlay();
          chrome.runtime.sendMessage({
            type: "OPEN_SECURITY_EVENT",
            eventId: eventId,
            source: "overlay"
          });
        });
        
        const continueBtn = document.createElement("button");
        continueBtn.type = "button";
        continueBtn.className = "btn btn-primary";
        continueBtn.textContent = "Continue";
        continueBtn.addEventListener("click", () => {
          if (record.assetType === "url" || !record.assetType) {
            // Open the suspicious URL directly since the user confirmed "Continue"
            window.open(record.url, "_blank", "noopener,noreferrer");
            clearVerifyFirstOverlay();
          } else {
            // For files and messages, we just dismiss the overlay and let the user interact with the WhatsApp UI
            handleDismiss();
          }
        });
        
        buttonsGroup.appendChild(detailsBtn);
        buttonsGroup.appendChild(continueBtn);
      } else {
        // DANGEROUS or ANALYSIS_UNAVAILABLE
        if (record.status === "DANGEROUS") {
          const detailsBtn = document.createElement("button");
          detailsBtn.type = "button";
          detailsBtn.className = "btn btn-secondary";
          detailsBtn.textContent = "Details";
          detailsBtn.addEventListener("click", () => {
            const eventId = record.eventId;
            if (!eventId) {
              console.error("[VerifyFirst] Details clicked but no eventId on record");
              return;
            }
            console.log(`[VerifyFirst] Details clicked, eventId=${eventId}`);
            clearVerifyFirstOverlay();
            chrome.runtime.sendMessage({
              type: "OPEN_SECURITY_EVENT",
              eventId: eventId,
              source: "overlay"
            });
          });
          buttonsGroup.appendChild(detailsBtn);
        }

        const closeBtn = document.createElement("button");
        closeBtn.type = "button";
        closeBtn.className = "btn btn-secondary";
        closeBtn.textContent = "Close";
        closeBtn.addEventListener("click", handleDismiss);
        buttonsGroup.appendChild(closeBtn);
      }

      actionRow.appendChild(buttonsGroup);
      actionCol.appendChild(actionRow);
      card.appendChild(actionCol);

    } else {
      resetDismissTimer();
      const header = document.createElement("div");
      header.className = "header";

      const backLink = document.createElement("button");
      backLink.type = "button";
      backLink.className = "back-link";
      backLink.textContent = "← Back";
      backLink.addEventListener("click", () => renderCurrentOverlayView("overview"));

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

      const statusTitle = document.createElement("div");
      statusTitle.className = "status-title";
      let assetLabel = "link";
      if (record.assetType === "file") assetLabel = "file";
      else if (record.assetType === "message") assetLabel = "message";

      if (record.status === "SUSPICIOUS") {
        statusTitle.textContent = `⚠ Suspicious ${assetLabel}`;
      } else if (record.status === "DANGEROUS") {
        statusTitle.textContent = `⚠ Dangerous ${assetLabel}`;
      } else {
        statusTitle.textContent = "⚠ Analysis unavailable";
      }
      card.appendChild(statusTitle);

      const scoreRow = document.createElement("div");
      scoreRow.className = "score-row";
      const scoreLabel = document.createElement("span");
      scoreLabel.className = "score-label";
      scoreLabel.textContent = "RISK SCORE";
      const scoreVal = document.createElement("span");
      scoreVal.className = "score-val";
      if (record.status === "ANALYSIS_UNAVAILABLE") {
        scoreVal.textContent = "— / 100";
      } else {
        scoreVal.textContent = `${record.risk_score ?? 0} / 100`;
      }
      scoreRow.appendChild(scoreLabel);
      scoreRow.appendChild(scoreVal);
      card.appendChild(scoreRow);

      const urlBox = document.createElement("div");
      urlBox.className = "url-box";
      if (record.assetType === "message") {
        urlBox.textContent = record.messagePreview || record.url.slice(0, 100);
      } else if (record.assetType === "file") {
        urlBox.textContent = record.filename || record.url;
      } else {
        urlBox.textContent = record.url;
      }
      card.appendChild(urlBox);

      const sectionLabel = document.createElement("div");
      sectionLabel.className = "section-label";
      sectionLabel.textContent = "DETECTED INDICATORS";
      card.appendChild(sectionLabel);

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
      } else if (!record.reasons || record.reasons.length === 0) {
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
      } else {
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

      const actions = document.createElement("div");
      actions.className = "actions";

      const backBtn = document.createElement("button");
      backBtn.type = "button";
      backBtn.className = "btn btn-secondary";
      backBtn.textContent = "Back";
      backBtn.addEventListener("click", () => renderCurrentOverlayView("overview"));

      const dismissBtn = document.createElement("button");
      dismissBtn.type = "button";
      dismissBtn.className = "btn btn-secondary";
      dismissBtn.textContent = "Dismiss";
      dismissBtn.addEventListener("click", handleDismiss);

      actions.appendChild(backBtn);
      actions.appendChild(dismissBtn);
      card.appendChild(actions);
    }

    // --- DIAGNOSTICS START ---
    const rect = card.getBoundingClientRect();
    console.log("[VerifyFirst] Overlay rendered:", {
        connected: host.isConnected,
        width: rect.width,
        height: rect.height,
        top: rect.top,
        right: window.innerWidth - rect.right
    });
    // --- DIAGNOSTICS END ---
  }

  function renderUnverifiedView(url: string): void {
    resetDismissTimer(8000);
    
    let host = document.getElementById(OVERLAY_CONTAINER_ID);
    let shadow: ShadowRoot;
    let card: HTMLDivElement;

    if (!host) {
        // Reuse host creation logic but simplify for now
        // Assuming host exists or create it:
        host = document.createElement("div");
        host.id = OVERLAY_CONTAINER_ID;
        host.style.position = "fixed";
        host.style.top = "16px";
        host.style.right = "16px";
        host.style.zIndex = "2147483647";
        host.style.pointerEvents = "auto";
        host.style.display = "block";
        shadow = host.attachShadow({ mode: "open" });
        // Minimal style for unverified
        const style = document.createElement("style");
        style.textContent = `
            :host { position: fixed !important; top: 16px !important; right: 16px !important; z-index: 2147483647 !important; display: block !important; pointer-events: auto !important; }
            * { box-sizing: border-box; margin: 0; padding: 0; }
            .overlay-card { width: 310px; background: #0B141A; color: #F8FAFC; border-radius: 12px; padding: 12px 14px; font-family: sans-serif; box-shadow: 0 12px 32px rgba(0,0,0,0.55); border: 1px solid rgba(148, 163, 184, 0.4); animation: vfFadeSlide 200ms ease-out; }
            @keyframes vfFadeSlide { from { opacity: 0; transform: translateY(-8px); } to { opacity: 1; transform: translateY(0); } }
            .header { display: flex; align-items: center; justify-content: space-between; padding-bottom: 6px; margin-bottom: 9px; border-bottom: 1px solid rgba(148, 163, 184, 0.15); }
            .close-btn { background: transparent; border: none; color: #8696A0; font-size: 18px; cursor: pointer; }
            .status-title { font-size: 14px; font-weight: 700; margin-bottom: 8px; color: #94A3B8; }
            .explanation-text { font-size: 12px; line-height: 1.4; color: #CBD5E1; margin-bottom: 8px; }
            .url-box { font-family: monospace; font-size: 12px; color: #E2E8F0; background: #0B141A; padding: 8px 10px; border-radius: 5px; border: 1px solid rgba(148, 163, 184, 0.18); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; margin-bottom: 10px; }
            .actions { display: flex; gap: 6px; justify-content: flex-end; }
            .btn { font-size: 12px; font-weight: 600; padding: 6px 12px; border-radius: 5px; cursor: pointer; border: none; }
            .btn-secondary { background: #1E2A33; border: 1px solid rgba(148, 163, 184, 0.20); color: #CBD5E1; }
        `;
        shadow.appendChild(style);
        card = document.createElement("div");
        shadow.appendChild(card);
        const targetParent = document.body || document.documentElement;
        targetParent.appendChild(host);
    } else {
        shadow = host.shadowRoot as ShadowRoot;
        card = shadow.querySelector('.overlay-card') as HTMLDivElement || document.createElement("div");
        if (!card.parentNode) shadow.appendChild(card);
    }

    card.className = "overlay-card";
    card.innerHTML = "";

    const header = document.createElement("div");
    header.className = "header";
    const brand = document.createElement("div");
    brand.textContent = "VERIFYFIRST";
    brand.style.color = "#FFE082";
    brand.style.fontWeight = "800";
    brand.style.fontSize = "13px";
    
    const closeBtn = document.createElement("button");
    closeBtn.className = "close-btn";
    closeBtn.textContent = "×";
    closeBtn.addEventListener("click", clearVerifyFirstOverlay);
    header.appendChild(brand);
    header.appendChild(closeBtn);
    card.appendChild(header);

    const statusTitle = document.createElement("div");
    statusTitle.className = "status-title";
    statusTitle.textContent = "⚠ Link not verified yet";
    card.appendChild(statusTitle);

    const explanation = document.createElement("div");
    explanation.className = "explanation-text";
    explanation.textContent = "VerifyFirst hasn't completed its security analysis for this link.";
    card.appendChild(explanation);

    const urlBox = document.createElement("div");
    urlBox.className = "url-box";
    urlBox.textContent = url;
    card.appendChild(urlBox);

    const actions = document.createElement("div");
    actions.className = "actions";
    const dismissBtn = document.createElement("button");
    dismissBtn.className = "btn btn-secondary";
    dismissBtn.textContent = "Dismiss";
    dismissBtn.addEventListener("click", clearVerifyFirstOverlay);
    actions.appendChild(dismissBtn);
    card.appendChild(actions);
  }

  function showUnverifiedWarning(url: string): void {
      if (!url) return;
      renderUnverifiedView(url);
  }


  /**
   * Displays an automatic security warning overlay inside WhatsApp Web.
   */
  function showVerifyFirstWarning(record: OverlayAnalysisRecord, allRecords: OverlayAnalysisRecord[] = [], force: boolean = false): void {
    console.log("[VerifyFirst] showOverlay entered");
    if (!record) return;
    try {
      const u = new URL(record.url);
      console.log(`[VerifyFirst][Overlay] showVerifyFirstWarning called for hostname=${u.hostname}, status=${record.status}`);
    } catch { }

    let pool = allRecords
      .filter(r => r.status === "SUSPICIOUS" || r.status === "DANGEROUS" || r.status === "ANALYSIS_UNAVAILABLE")
      .filter(r => !dismissedWarnings.has((r.url || "").trim().toLowerCase()));

    if (pool.length === 0 && (record.status === "SUSPICIOUS" || record.status === "DANGEROUS" || record.status === "ANALYSIS_UNAVAILABLE")) {
        const norm = (record.url || "").trim().toLowerCase();
        if (!dismissedWarnings.has(norm)) {
             pool = [record];
        }
    }
    
    const uniquePool: OverlayAnalysisRecord[] = [];
    const seenUrls = new Set<string>();
    for (const r of pool) {
        if (!seenUrls.has(r.url)) {
            seenUrls.add(r.url);
            uniquePool.push(r);
        }
    }
    activeWarningPool = uniquePool;

    if (activeWarningPool.length === 0) {
      clearVerifyFirstOverlay();
      return;
    }

    const host = document.getElementById(OVERLAY_CONTAINER_ID);
    const isOverlayOpen = host && host.parentNode;

    const normalizedUrl = (record.url || "").trim().toLowerCase();
    const isNewTrigger = !displayedWarnings.has(normalizedUrl) || force;

    if (isNewTrigger) {
        displayedWarnings.add(normalizedUrl);
        if (!isOverlayOpen) {
            currentWarningUrl = record.url;
        }
    } else {
        if (!isOverlayOpen) {
            return;
        }
    }

    if (!activeWarningPool.some(r => r.url === currentWarningUrl)) {
        currentWarningUrl = activeWarningPool[0].url;
    }

    renderCurrentOverlayView();
    console.log(`[VerifyFirst] Warning visible`);
    resetDismissTimer(8000);
  }



  // Attach functions to window scope for non-module content script execution
  if (typeof window !== "undefined") {
    (window as any).VerifyFirstOverlay = {
      showVerifyFirstWarning,
      showUnverifiedWarning,
      clearVerifyFirstOverlay,
      resetDisplayedWarnings,
    };
  }
})();
