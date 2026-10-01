import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const { JSDOM } = require('../extension/node_modules/jsdom');

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const securityCenterCodePath = path.join(__dirname, '../extension/content/security-center/securityCenter.js');
const securityCenterCode = fs.readFileSync(securityCenterCodePath, 'utf8');

const overlayCodePath = path.join(__dirname, '../extension/content/verifyFirstOverlay.js');
const overlayCode = fs.readFileSync(overlayCodePath, 'utf8');

async function runXSSTest() {
  console.log("Running Phase 4E XSS tests...");
  let failed = false;
  const dom = new JSDOM(`<!DOCTYPE html><html><body></body></html>`, {
    runScripts: "dangerously",
    url: "https://web.whatsapp.com/"
  });

  const window = dom.window;
  const document = window.document;

  const maliciousUrl = `https://<script>alert('url')</script>`;
  const maliciousHostname = `<script>alert('host')</script>`;
  const maliciousFilename = `<script>alert('file')</script>`;
  const maliciousMessage = `"<img src=x onerror=alert('msg')>`;
  const maliciousRule = `"<script>alert('rule')</script>`;
  const maliciousReason = `<script>alert('reason')</script>`;
  const maliciousSummary = `<script>alert('summary')</script>`;
  const maliciousTitle = `<script>alert('title')</script>`;
  const maliciousImpact = `<script>alert('impact')</script>`;
  const maliciousRecAction = `<script>alert('rec')</script>`;

  const maliciousRecord = {
    id: "malicious-123",
    timestamp: Date.now(),
    url: maliciousUrl,
    hostname: maliciousHostname,
    status: "DANGEROUS",
    riskScore: 100,
    protectionAction: "BLOCK",
    assetType: "message",
    filename: maliciousFilename,
    messagePreview: maliciousMessage,
    reasons: [
      { rule: maliciousRule, message: maliciousReason }
    ],
    threat_context: {
      title: maliciousTitle,
      summary: maliciousSummary,
      technical_details: [],
      user_impact: maliciousImpact,
      recommended_action: maliciousRecAction
    },
    threatContext: {
      title: maliciousTitle,
      summary: maliciousSummary,
      technicalDetails: [],
      userImpact: maliciousImpact,
      recommendedAction: maliciousRecAction
    }
  };

  // Mock chrome API
  let uiMessageListeners = [];
  window.chrome = {
    runtime: {
      id: "mock-ext",
      getURL: (p) => "mock://" + p,
      onMessage: {
        addListener: (fn) => { uiMessageListeners.push(fn); }
      }
    }
  };
  
  window.requestAnimationFrame = (cb) => setTimeout(cb, 0);

  // Load scripts
  window.eval(overlayCode);
  
  // Expose the mocked telemetry to securityCenter before it loads
  window.eval(`
    // Wrap to avoid module issues if needed
  `);
  
  // We need to inject telemetry into the module. We can just mock the whole history
  // by intercepting the telemetry import, but jsdom doesn't support dynamic imports easily.
  // Instead, let's inject a mock telemetry variable globally and modify securityCenter to use it if available.
  const modifiedSCCode = securityCenterCode
    .replace(
      'telemetry = await import(telemetryUrl);',
      'telemetry = window.mockTelemetry;'
    )
    .replace('mode: "closed"', 'mode: "open"');

  window.mockTelemetry = {
    fetchHistory: async () => [maliciousRecord],
    fetchStatistics: async () => ({
      totalEvents: 1, safeCount: 0, suspiciousCount: 0, dangerousCount: 1,
      allowedCount: 0, warnedCount: 0, blockedCount: 1, uniqueHostnames: 1
    })
  };

  window.eval(modifiedSCCode);

  // 1. Test verifyFirstOverlay
  window.VerifyFirstOverlay.showVerifyFirstWarning(maliciousRecord, [maliciousRecord]);
  
  await new Promise(r => setTimeout(r, 100)); // allow async rendering
  
  // Check the DOM
  const overlayHost = document.getElementById("verifyfirst-overlay-host");
  if (!overlayHost) {
    console.error("Overlay host not found");
    failed = true;
  } else {
    window.eval(`
    const overlay = document.getElementById("verifyfirst-overlay-host");
    console.log("JSDOM inner overlay shadowRoot:", !!overlay.shadowRoot);
    if (overlay.shadowRoot) {
      console.log("Overlay innerHTML length:", overlay.shadowRoot.innerHTML.length);
      window.testOverlayHtml = overlay.shadowRoot.innerHTML;
    }
  `);
  
  const html = window.testOverlayHtml || "";
    
    // Check if unescaped tags exist in HTML
    if (html.includes("<script>alert('summary')</script>")) {
      console.error("[FAIL] overlay: Unescaped summary found in DOM!");
      failed = true;
    }
    if (html.includes("<script>alert('rec')</script>")) {
      console.error("[FAIL] overlay: Unescaped recommended_action found in DOM!");
      failed = true;
    }
    
    // Ensure properly escaped versions exist
    if (!html.includes("&lt;script&gt;alert('summary')&lt;/script&gt;")) {
      console.error("[FAIL] overlay: Escaped summary not found in DOM!");
      failed = true;
    }
  }

  // 2. Test Security Center
  for (let fn of uiMessageListeners) {
    fn({ type: "OPEN_SECURITY_CENTER" }, {}, () => {});
  }
  
  await new Promise(r => setTimeout(r, 500)); // allow async rendering
  
  const scHost = document.getElementById("verifyfirst-security-center-root");
  if (!scHost) {
    console.error("Security Center host not found");
    failed = true;
  } else {
    // Navigate to event details to check reason rendering
    for (let fn of uiMessageListeners) {
      fn({ type: "OPEN_SECURITY_EVENT", eventId: maliciousRecord.id, source: "overlay" }, {}, () => {});
    }
    await new Promise(r => setTimeout(r, 500));
    
    window.eval(`
      const sc = document.getElementById("verifyfirst-security-center-root");
      console.log("JSDOM inner sc shadowRoot:", !!sc.shadowRoot);
      console.log("JSDOM inner sc outerHTML:", sc.outerHTML);
      if (sc.shadowRoot) {
        console.log("SC innerHTML length:", sc.shadowRoot.innerHTML.length);
        window.testScHtml = sc.shadowRoot.innerHTML;
      }
    `);
    
    const html = window.testScHtml || "";
    
    // 4E Requirements: Verify literal text, never executed markup.
    const checks = [
      { name: "message", raw: maliciousMessage },
      { name: "rule", raw: maliciousRule },
      { name: "reason", raw: maliciousReason }
    ];
    
    for (const check of checks) {
      if (html.includes(check.raw)) {
        console.error(`[FAIL] SC: Unescaped ${check.name} found in DOM!`);
        failed = true;
      }
    }
    
    // Check asset rendering by verifying the serialized HTML doesn't contain raw but DOES contain the canonical escaped version.
    const expectedCanonical = `"&lt;img src=x onerror=alert('msg')&gt;`;
    if (!html.includes(expectedCanonical)) {
      console.error(`[FAIL] SC: Asset-aware rendering failed, missing message preview.`);
      console.error("Expected:", expectedCanonical);
      console.error("HTML length:", html.length);
      console.error("indexOf:", html.indexOf("vf-sc-host-details-val"));
      if (html.length < 1000) console.error("Full HTML:", html);
      failed = true;
    }
  }
  
  if (failed) {
    process.exit(1);
  } else {
    console.log("[PASS] Phase 4E XSS tests passed.");
  }
}

function escapeHtmlStr(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

runXSSTest().catch(err => {
  console.error(err);
  process.exit(1);
});
