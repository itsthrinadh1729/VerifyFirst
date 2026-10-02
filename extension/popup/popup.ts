/**
 * VerifyFirst — Popup Launcher Controller
 *
 * Lightweight popup that:
 * 1. Shows real-time security statistics (safe/suspicious/dangerous counts)
 * 2. Opens the full in-page Security Center on the active WhatsApp tab
 * 3. Handles edge cases (non-WhatsApp tabs, extension context issues)
 *
 * ALL dynamic untrusted strings are rendered using XSS-safe textContent.
 */

(function () {
  const btnOpen = document.getElementById("btn-open-center") as HTMLButtonElement;
  const launcherStatus = document.getElementById("launcher-status") as HTMLDivElement;
  const footerText = document.getElementById("footer-text") as HTMLSpanElement;

  const statSafe = document.getElementById("stat-safe") as HTMLDivElement;
  const statSuspicious = document.getElementById("stat-suspicious") as HTMLDivElement;
  const statDangerous = document.getElementById("stat-dangerous") as HTMLDivElement;

  let activeWhatsAppTabId: number | undefined;

  /**
   * Check if the active tab is WhatsApp Web and store the tab ID.
   */
  function checkActiveTab(callback: (isWhatsApp: boolean) => void): void {
    if (typeof chrome === "undefined" || !chrome.tabs || !chrome.tabs.query) {
      callback(false);
      return;
    }

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs: any[]) => {
      const tab = tabs && tabs[0];
      if (tab && tab.url && tab.url.includes("web.whatsapp.com") && tab.id !== undefined) {
        activeWhatsAppTabId = tab.id;
        callback(true);
      } else {
        activeWhatsAppTabId = undefined;
        callback(false);
      }
    });
  }

  /**
   * Load security statistics from the background service worker.
   */
  function loadStats(): void {
    chrome.runtime.sendMessage({ type: "GET_SECURITY_STATISTICS" }, (response: any) => {
      if (chrome.runtime.lastError || !response || !response.success || !response.data) {
        return;
      }

      const stats = response.data;

      const safeCount = statSafe.querySelector(".stat-count");
      const suspiciousCount = statSuspicious.querySelector(".stat-count");
      const dangerousCount = statDangerous.querySelector(".stat-count");

      if (safeCount) safeCount.textContent = String(stats.safeCount ?? 0);
      if (suspiciousCount) suspiciousCount.textContent = String(stats.suspiciousCount ?? 0);
      if (dangerousCount) dangerousCount.textContent = String(stats.dangerousCount ?? 0);
    });
  }

  /**
   * Open the in-page Security Center on the active WhatsApp tab.
   */
  function openSecurityCenter(): void {
    if (activeWhatsAppTabId === undefined) return;

    // Send OPEN_SECURITY_CENTER message to the active tab's content script
    chrome.tabs.sendMessage(activeWhatsAppTabId, { type: "OPEN_SECURITY_CENTER" }, (response: any) => {
      if (chrome.runtime.lastError) {
        // Try via service worker relay as fallback
        chrome.runtime.sendMessage({ type: "OPEN_SECURITY_CENTER" });
      }
    });

    // Close the popup after a brief delay to let the message dispatch
    setTimeout(() => {
      window.close();
    }, 150);
  }

  /**
   * Update UI based on whether we're on a WhatsApp tab.
   */
  function updateUI(isWhatsApp: boolean): void {
    if (isWhatsApp) {
      btnOpen.disabled = false;
      launcherStatus.classList.remove("inactive");
      footerText.textContent = "Scanning links in real-time";
    } else {
      btnOpen.disabled = true;
      launcherStatus.classList.add("inactive");

      const statusText = launcherStatus.querySelector(".status-text");
      if (statusText) statusText.textContent = "Open WhatsApp Web";

      footerText.textContent = "Navigate to web.whatsapp.com to activate";
    }
  }

  // Event Handlers
  btnOpen.addEventListener("click", openSecurityCenter);

  // Initialize
  document.addEventListener("DOMContentLoaded", () => {
    checkActiveTab((isWhatsApp) => {
      updateUI(isWhatsApp);

      if (isWhatsApp) {
        // Trigger a scan in the content script
        chrome.runtime.sendMessage({ type: "TRIGGER_SCAN" });
      }

      // Load stats regardless of tab
      loadStats();
    });
  });
})();
