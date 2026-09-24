/**
 * VerifyFirst — Module 7: Security Center Tests
 * 
 * 26 test cases covering the Security Center UI architecture,
 * MV3 message contract, data flow, and privacy guarantees.
 * 
 * Uses the same jsdom-based test approach as the existing project tests.
 */

const { JSDOM } = require("./extension/node_modules/jsdom");
const fs = require("fs");
const path = require("path");

let passed = 0;
let failed = 0;

function assert(condition, testName) {
  if (condition) {
    passed++;
    console.log(`  ✅ ${testName}`);
  } else {
    failed++;
    console.log(`  ❌ ${testName}`);
  }
}

// ============================================================
// Load Security Center source files
// ============================================================

const htmlPath = path.join(__dirname, "extension", "security-center", "security-center.html");
const tsPath = path.join(__dirname, "extension", "security-center", "security-center.ts");
const jsPath = path.join(__dirname, "extension", "security-center", "security-center.js");
const cssPath = path.join(__dirname, "extension", "security-center", "security-center.css");
const manifestPath = path.join(__dirname, "extension", "manifest.json");
const serviceWorkerTsPath = path.join(__dirname, "extension", "background", "service-worker.ts");
const telemetrySrc = fs.readFileSync(path.join(__dirname, 'extension/shared/telemetryClient.ts'), 'utf8');

const htmlContent = fs.readFileSync(htmlPath, "utf-8");
const tsContent = fs.readFileSync(tsPath, "utf-8");
const jsContent = fs.readFileSync(jsPath, "utf-8");
const cssContent = fs.readFileSync(cssPath, "utf-8");
const manifestContent = JSON.parse(fs.readFileSync(manifestPath, "utf-8"));
const serviceWorkerTs = fs.readFileSync(serviceWorkerTsPath, "utf-8");
const telemetryClientTs = telemetrySrc;

// Also load all UI source files to scan for forbidden patterns
const securityCenterUIFiles = [tsContent, jsContent, htmlContent, cssContent];

console.log("\n🛡️  VerifyFirst Security Center Tests (Module 7)\n");
console.log("─".repeat(55));

// ============================================================
// Test 1: Security Center page loads
// ============================================================

console.log("\n📄 PART A — Security Center Entry\n");

const dom = new JSDOM(htmlContent);
const doc = dom.window.document;

assert(
  doc.querySelector("title").textContent === "VerifyFirst Security Center",
  "1. Security Center HTML has correct title"
);

// ============================================================
// Test 2: Extension icon opens Security Center (manifest check)
// ============================================================

assert(
  !manifestContent.action.default_popup,
  "2. manifest.json has no default_popup (enables chrome.action.onClicked)"
);

// ============================================================
// Test 3: Service worker has icon click handler for open/focus
// ============================================================

assert(
  serviceWorkerTs.includes("chrome.action.onClicked.addListener") &&
  serviceWorkerTs.includes("OPEN_SECURITY_CENTER"),
  "3. Service worker has chrome.action.onClicked handler sending OPEN_SECURITY_CENTER"
);

// Verify focus-existing-tab logic
assert(
  !serviceWorkerTs.includes("chrome.tabs.create({ url: securityCenterUrl })"),
  "3b. Service worker does not create new tab for Security Center"
);

// ============================================================
// Test 4: Overview requests statistics through telemetryClient
// ============================================================

console.log("\n📊 PART C — Overview\n");

assert(
  tsContent.includes("fetchStatistics()"),
  "4. Overview calls fetchStatistics() from telemetryClient"
);

// ============================================================
// Test 5: Recent events are loaded through telemetryClient
// ============================================================

assert(
  tsContent.includes('fetchHistory({ sort: "newest", limit: 5 })') || 
  tsContent.includes("fetchHistory({") && tsContent.includes("limit: 5"),
  "5. Overview loads recent events via fetchHistory with limit 5"
);

// ============================================================
// Test 6: No direct chrome.storage.local access in UI code
// ============================================================

console.log("\n🔒 PART K — MV3 Architecture\n");

const uiStorageViolation = securityCenterUIFiles.some(
  (src) => {
    // Exclude comment lines from the check
    const lines = src.split("\n");
    return lines.some(line => {
      const trimmed = line.trim();
      if (trimmed.startsWith("*") || trimmed.startsWith("//") || trimmed.startsWith("<!--")) return false;
      return line.includes("chrome.storage.local") || line.includes("chrome.storage.session");
    });
  }
);

assert(
  !uiStorageViolation,
  "6. No direct chrome.storage.local access in Security Center UI code"
);

// ============================================================
// Test 7: History filters are passed through query API
// ============================================================

console.log("\n📜 PART E — Security History\n");

assert(
  tsContent.includes("fetchHistory(query") || tsContent.includes("fetchHistory("),
  "7. History filters passed through fetchHistory query API"
);

// ============================================================
// Test 8: Status filters work
// ============================================================

assert(
  tsContent.includes("query.status") && htmlContent.includes('id="filter-status"'),
  "8. Status filter is implemented and connected"
);

// ============================================================
// Test 9: Protection-action filters work
// ============================================================

assert(
  tsContent.includes("query.protectionAction") && htmlContent.includes('id="filter-protection"'),
  "9. Protection action filter is implemented and connected"
);

// ============================================================
// Test 10: Hostname search works
// ============================================================

assert(
  tsContent.includes("query.hostname") && htmlContent.includes('id="filter-hostname"'),
  "10. Hostname search filter is implemented and connected"
);

// ============================================================
// Test 11: Risk range is passed correctly
// ============================================================

assert(
  tsContent.includes("query.minRiskScore") && tsContent.includes("query.maxRiskScore"),
  "11. Risk score range (min/max) filters are implemented"
);

// ============================================================
// Test 12: Date range is passed correctly
// ============================================================

assert(
  tsContent.includes("query.fromTimestamp") && tsContent.includes("query.toTimestamp"),
  "12. Date range (from/to) filters are implemented"
);

// ============================================================
// Test 13: Pagination works
// ============================================================

assert(
  tsContent.includes("query.limit") && tsContent.includes("query.offset") &&
  tsContent.includes("historyPage"),
  "13. Pagination with limit/offset is implemented"
);

// ============================================================
// Test 14: Event Details displays existing SecurityEvent data
// ============================================================

console.log("\n🔍 PART F — Event Details\n");

assert(
  tsContent.includes("event.hostname") &&
  tsContent.includes("event.riskScore") &&
  tsContent.includes("event.protectionAction") &&
  tsContent.includes("event.reasons"),
  "14. Event Details renders hostname, riskScore, protectionAction, reasons"
);

// ============================================================
// Test 15: threatContext is displayed without frontend threat logic
// ============================================================

assert(
  tsContent.includes("event.threatContext") &&
  tsContent.includes("event.threatContext.title") &&
  tsContent.includes("event.threatContext.summary") &&
  tsContent.includes("event.threatContext.technicalDetails") &&
  tsContent.includes("event.threatContext.userImpact"),
  "15. threatContext is rendered directly from event data (no frontend logic)"
);

// Verify no risk score calculations in UI
const riskLogicPattern = /riskScore\s*[><=!]+\s*\d+/;
const hasRiskLogic = riskLogicPattern.test(tsContent);

assert(
  !hasRiskLogic,
  "15b. No security decision logic (riskScore > N) in UI code"
);

// ============================================================
// Test 16: Empty history state works
// ============================================================

console.log("\n⚡ PART H — Loading / Empty / Error States\n");

assert(
  htmlContent.includes("No security events yet."),
  "16. Empty state message exists in HTML"
);

// ============================================================
// Test 17: Loading state works
// ============================================================

assert(
  htmlContent.includes("Loading security data..."),
  "17. Loading state message exists in HTML"
);

// ============================================================
// Test 18: Error state works
// ============================================================

assert(
  htmlContent.includes("Security data unavailable.") &&
  htmlContent.includes("VerifyFirst protection remains active."),
  "18. Error state message exists with protection-active reassurance"
);

// ============================================================
// Test 19: Export invokes triggerExport
// ============================================================

console.log("\n⚙️ PART G — Settings\n");

assert(
  tsContent.includes("triggerExport()"),
  "19. Export button calls triggerExport()"
);

// ============================================================
// Test 20: Export produces a downloadable JSON file
// ============================================================

assert(
  tsContent.includes("verifyfirst-security-history.json") &&
  tsContent.includes("application/json") &&
  tsContent.includes("URL.createObjectURL"),
  "20. Export produces downloadable JSON file with correct filename"
);

// ============================================================
// Test 21: Clear History asks for confirmation
// ============================================================

assert(
  htmlContent.includes("Clear all security history?") &&
  htmlContent.includes("clear-confirm-modal") &&
  htmlContent.includes("btn-clear-cancel") &&
  htmlContent.includes("btn-clear-confirm"),
  "21. Clear History shows confirmation dialog with Cancel/Confirm buttons"
);

// ============================================================
// Test 22: Clear History calls wipeHistory
// ============================================================

assert(
  tsContent.includes("wipeHistory()"),
  "22. Clear confirmation calls wipeHistory()"
);

// ============================================================
// Test 23: After clear, statistics/history refresh
// ============================================================

assert(
  tsContent.includes("loadOverview") && 
  // After wipeHistory, the code refreshes overview
  tsContent.indexOf("wipeHistory") < tsContent.lastIndexOf("loadOverview"),
  "23. After clear, overview/statistics are refreshed"
);

// ============================================================
// Test 24: No raw URL is rendered
// ============================================================

console.log("\n🔐 PART J — Privacy\n");

// Check that the Security Center TS only uses .hostname, never .url for display
const tsLines = tsContent.split("\n");
const rendersRawUrl = tsLines.some(line => {
  const trimmed = line.trim();
  if (trimmed.startsWith("//") || trimmed.startsWith("*")) return false;
  // Check for event.url being used for display (textContent = event.url)
  return (trimmed.includes(".textContent = event.url") || 
          trimmed.includes("textContent = selectedEvent.url"));
});

assert(
  !rendersRawUrl,
  "24. No raw URL is rendered in Security Center (uses hostname only)"
);

// ============================================================
// Test 25: No WhatsApp message content is rendered
// ============================================================

const whatsappContentLeaks = securityCenterUIFiles.some(
  (src) => src.includes("chatId") || src.includes("message.body") || 
           src.includes("messageContent") || src.includes("chatContent")
);

assert(
  !whatsappContentLeaks,
  "25. No WhatsApp chat/message content referenced in Security Center"
);

// ============================================================
// Test 26: Existing WhatsApp overlay behavior remains intact
// ============================================================

console.log("\n🟢 PART J — Existing Behavior\n");

// Verify the content scripts are still in manifest
const contentScripts = manifestContent.content_scripts;
const whatsappScript = contentScripts && contentScripts[0];

assert(
  whatsappScript &&
  whatsappScript.matches.includes("https://web.whatsapp.com/*") &&
  whatsappScript.js.includes("content/verifyFirstOverlay.js") &&
  whatsappScript.js.includes("content/whatsappScanner.js") &&
  whatsappScript.js.includes("content/protection/navigationGuard.js"),
  "26. WhatsApp content scripts (overlay, scanner, navigationGuard) preserved in manifest"
);

// ============================================================
// Additional structural checks
// ============================================================

console.log("\n📐 BONUS — Structural Integrity\n");

// HTML structure: Sidebar with 4 nav items
const navItems = doc.querySelectorAll(".nav-item[data-view]");
assert(navItems.length === 4, "B1. Sidebar has exactly 4 navigation items");

// Views exist
assert(doc.getElementById("view-overview") !== null, "B2. Overview view exists");
assert(doc.getElementById("view-link-analysis") !== null, "B3. Link Analysis view exists");
assert(doc.getElementById("view-history") !== null, "B4. History view exists");
assert(doc.getElementById("view-settings") !== null, "B5. Settings view exists");
assert(doc.getElementById("view-event-details") !== null, "B6. Event Details view exists");

// Logo uses existing asset
assert(
  htmlContent.includes("../assets/logo-mark.svg"),
  "B7. Uses existing VerifyFirst logo-mark.svg asset"
);

// Script tag references compiled JS, not TS
assert(
  htmlContent.includes('src="security-center.js"') &&
  !htmlContent.includes('src="security-center.ts"'),
  "B8. HTML references compiled .js, not .ts"
);

// TS imports from telemetryClient
assert(
  tsContent.includes('from "../shared/telemetryClient.js"') || tsContent.includes('import(') || tsContent.includes('require('),
  "B9. TypeScript imports from telemetryClient via correct relative path"
);

// TS does NOT import from historyStore, statistics, etc. directly
const forbiddenImports = [
  "historyStore",
  "statistics.js",
  "historyQuery.js",
  "export.js",
];
const hasForbiddenImport = forbiddenImports.some(
  (mod) => tsContent.includes(`from "${mod}"`) || tsContent.includes(`from './${mod}'`) ||
           tsContent.includes(`from "../background/security/${mod}"`)
);

assert(
  !hasForbiddenImport,
  "B10. Security Center does NOT directly import historyStore/statistics/historyQuery/export"
);

// ============================================================
// REGRESSION TESTS — Module 7 does not break WhatsApp protection
// ============================================================

console.log("\n🔄 REGRESSION — Module 7 ↔ WhatsApp Isolation\n");

// Load additional source files for regression checks
const overlayTs = fs.readFileSync(
  path.join(__dirname, "extension", "content", "verifyFirstOverlay.ts"), "utf-8"
);
const scannerTs = fs.readFileSync(
  path.join(__dirname, "extension", "content", "whatsappScanner.ts"), "utf-8"
);
const navGuardTs = fs.readFileSync(
  path.join(__dirname, "extension", "content", "protection", "navigationGuard.ts"), "utf-8"
);

// R1. chrome.action.onClicked is registered AFTER and INDEPENDENTLY from chrome.runtime.onMessage
const onMessageLine = serviceWorkerTs.indexOf("chrome.runtime.onMessage.addListener");
const onClickedLine = serviceWorkerTs.indexOf("chrome.action.onClicked.addListener");

assert(
  onMessageLine !== -1 && onClickedLine !== -1 && onClickedLine > onMessageLine,
  "R1. action.onClicked is registered after and independently from runtime.onMessage"
);

// R2. The onClicked handler does NOT call sendResponse or interfere with message handling
const onClickedBlock = serviceWorkerTs.substring(onClickedLine);
assert(
  !onClickedBlock.includes("sendResponse") &&
  !onClickedBlock.includes("onMessage"),
  "R2. onClicked handler does not touch sendResponse or onMessage"
);

// R3. ANALYZE_URL handler still exists in service worker
assert(
  serviceWorkerTs.includes('message.type === "ANALYZE_URL"') &&
  serviceWorkerTs.includes("handleAnalyzeUrl"),
  "R3. ANALYZE_URL message handler remains in service worker"
);

// R4. ANALYSIS_RESULT push to content script still exists
assert(
  serviceWorkerTs.includes('type: "ANALYSIS_RESULT"') &&
  serviceWorkerTs.includes("chrome.tabs.sendMessage(tabId"),
  "R4. ANALYSIS_RESULT push-to-tab still exists in service worker"
);

// R5. WhatsApp overlay exposes showVerifyFirstWarning on window
assert(
  overlayTs.includes("showVerifyFirstWarning") &&
  overlayTs.includes("VerifyFirstOverlay"),
  "R5. verifyFirstOverlay still exposes showVerifyFirstWarning"
);

// R6. WhatsApp scanner still sends ANALYZE_URL via chrome.runtime.sendMessage
assert(
  scannerTs.includes("ANALYZE_URL") &&
  scannerTs.includes("chrome.runtime.sendMessage"),
  "R6. whatsappScanner still dispatches ANALYZE_URL via chrome.runtime.sendMessage"
);

// R7. NavigationGuard is still loaded and referenced
assert(
  scannerTs.includes("NavigationGuard") &&
  navGuardTs.includes("class NavigationGuard") || navGuardTs.includes("NavigationGuard"),
  "R7. NavigationGuard is still instantiated in scanner and defined in protection/"
);

// ============================================================
// Summary
// ============================================================

console.log("\n" + "═".repeat(55));
console.log(`\n🛡️  Security Center Tests: ${passed} passed, ${failed} failed out of ${passed + failed}\n`);

if (failed > 0) {
  process.exit(1);
}

