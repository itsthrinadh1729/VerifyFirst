import assert from 'assert';
import { sanitizeUrlToHostname } from '../extension/background/security/sanitizer.js';
import { createSecurityEvent } from '../extension/background/security/event.js';
import crypto from 'crypto';

if (typeof globalThis.crypto === 'undefined') {
  globalThis.crypto = crypto;
}

async function runTests() {
  console.log("Running SecurityEvent 5A tests...");

  // Test URL Sanitization
  const testUrl = "https://user:password@evil.com/login?token=SECRET#fragment";
  const hostname = sanitizeUrlToHostname(testUrl);
  assert.strictEqual(hostname, "evil.com", "Sanitizer must extract only the hostname");

  assert.strictEqual(sanitizeUrlToHostname("http://example.com/path"), "example.com");
  assert.strictEqual(sanitizeUrlToHostname("example.org/path?q=1"), "example.org"); // Missing protocol should be handled

  // Test Event Creation
  
  // SAFE creates event
  const safeAnalysis = { status: "SAFE", risk_score: 0, reasons: [] };
  const safeEvent = createSecurityEvent(safeAnalysis, "https://safe.com");
  assert.ok(safeEvent, "SAFE analysis should create an event");
  assert.strictEqual(safeEvent.status, "SAFE");
  assert.strictEqual(safeEvent.protectionAction, "ALLOW");
  assert.strictEqual(safeEvent.hostname, "safe.com");
  assert.ok(safeEvent.id, "Event gets unique ID");
  assert.ok(safeEvent.timestamp > 0, "Timestamp exists");

  // SUSPICIOUS creates event
  const suspiciousAnalysis = { status: "SUSPICIOUS", risk_score: 50, reasons: [{rule: "R1", message: "M1"}] };
  const suspiciousEvent = createSecurityEvent(suspiciousAnalysis, "https://sus.com");
  assert.ok(suspiciousEvent, "SUSPICIOUS analysis should create an event");
  assert.strictEqual(suspiciousEvent.status, "SUSPICIOUS");
  assert.strictEqual(suspiciousEvent.protectionAction, "WARN");
  assert.strictEqual(suspiciousEvent.reasons.length, 1);
  assert.strictEqual(suspiciousEvent.riskScore, 50, "Original detection score unchanged");

  // DANGEROUS creates event
  const dangerousAnalysis = { 
    status: "DANGEROUS", 
    risk_score: 100, 
    reasons: [], 
    threat_context: {
      title: "T", summary: "S", technical_details: ["D"], user_impact: "U", recommended_action: "R"
    } 
  };
  const dangerousEvent = createSecurityEvent(dangerousAnalysis, testUrl);
  assert.ok(dangerousEvent, "DANGEROUS analysis should create an event");
  assert.strictEqual(dangerousEvent.status, "DANGEROUS");
  assert.strictEqual(dangerousEvent.protectionAction, "BLOCK");
  assert.strictEqual(dangerousEvent.hostname, "evil.com", "Sensitive URL parts must not be stored");
  assert.ok(dangerousEvent.threatContext);
  assert.strictEqual(dangerousEvent.threatContext.title, "T");

  // unavailable creates no event
  const unavailableAnalysis = { status: "ANALYSIS_UNAVAILABLE", risk_score: null, reasons: [] };
  const noEvent = createSecurityEvent(unavailableAnalysis, "https://unknown.com");
  assert.strictEqual(noEvent, null, "ANALYSIS_UNAVAILABLE should NOT create an event");

  console.log("All SecurityEvent 5A tests passed! ✅");
}

runTests().catch(err => {
  console.error("Test failed:");
  console.error(err);
  process.exit(1);
});
