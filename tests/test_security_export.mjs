import assert from 'assert';
import { exportSecurityHistory } from '../extension/background/security/export.js';
import { record, clear, getAll } from '../extension/background/security/historyStore.js';
import { createSecurityEvent } from '../extension/background/security/event.js';
import crypto from 'crypto';

if (typeof globalThis.crypto === 'undefined') {
  globalThis.crypto = crypto;
}

// Mock chrome.storage.local
const mockStorage = new Map();
globalThis.chrome = {
  storage: {
    local: {
      get: async (key) => {
        if (typeof key === 'string') {
          const val = mockStorage.get(key);
          return { [key]: val ? JSON.parse(JSON.stringify(val)) : undefined };
        }
        return {};
      },
      set: async (items) => {
        for (const [k, v] of Object.entries(items)) {
          mockStorage.set(k, JSON.parse(JSON.stringify(v)));
        }
      },
      remove: async (key) => {
        mockStorage.delete(key);
      }
    }
  }
};

async function runTests() {
  console.log("Running Security Export 5E tests...");

  await clear();

  // Test 1 & 4: Empty history & Envelope presence
  let jsonString = await exportSecurityHistory();
  let exportData = JSON.parse(jsonString);
  assert.strictEqual(exportData.version, 1);
  assert.strictEqual(exportData.events.length, 0);
  assert.ok(exportData.exportedAt);

  // Test 5: Valid timestamp
  const dateObj = new Date(exportData.exportedAt);
  assert.ok(!isNaN(dateObj.getTime()), "exportedAt must be a valid ISO string");

  // Test 14: No raw URL input API
  // The API is simply exportSecurityHistory() with 0 arguments.

  // Seed data for tests
  const rawUrl = "https://user:password@evil.com/login?token=SECRET#fragment";
  const analysisResult = {
    status: "DANGEROUS",
    risk_score: 99,
    reasons: [
      { rule: "MALWARE_1", message: "Malware detected" }
    ],
    threat_context: {
      title: "Malware Site",
      summary: "This site distributes malware.",
      technical_details: ["Known C2 server"],
      user_impact: "Can steal data",
      recommended_action: "Close immediately"
    }
  };
  
  const event1 = createSecurityEvent(analysisResult, rawUrl);
  event1.protectionAction = "BLOCK";
  await record(event1);

  const event2 = createSecurityEvent({ status: "SAFE", risk_score: 0, reasons: [] }, "https://google.com");
  event2.protectionAction = "ALLOW";
  await record(event2);

  // Test 2 & 3: Single event (we have multiple now) & Multiple events supported
  jsonString = await exportSecurityHistory();
  exportData = JSON.parse(jsonString);
  assert.strictEqual(exportData.events.length, 2);

  const exportedEv1 = exportData.events[0];
  
  // Verify all fields are preserved
  assert.strictEqual(exportedEv1.id, event1.id);
  assert.strictEqual(exportedEv1.timestamp, event1.timestamp);
  assert.strictEqual(exportedEv1.status, "DANGEROUS");
  assert.strictEqual(exportedEv1.riskScore, 99);
  assert.strictEqual(exportedEv1.protectionAction, "BLOCK");
  
  // Test 6 & 7: Privacy & Sensitive URL data
  assert.strictEqual(exportedEv1.hostname, "evil.com");
  assert.ok(!jsonString.includes("password"));
  assert.ok(!jsonString.includes("SECRET"));
  assert.ok(!jsonString.includes("token"));
  assert.ok(!jsonString.includes("fragment"));
  assert.ok(!jsonString.includes("/login"));

  // Test 8: Threat context preservation
  assert.ok(exportedEv1.threatContext);
  assert.strictEqual(exportedEv1.threatContext.title, "Malware Site");
  assert.strictEqual(exportedEv1.threatContext.summary, "This site distributes malware.");
  assert.deepStrictEqual(exportedEv1.threatContext.technicalDetails, ["Known C2 server"]);
  assert.strictEqual(exportedEv1.threatContext.userImpact, "Can steal data");
  assert.strictEqual(exportedEv1.threatContext.recommendedAction, "Close immediately");

  // Test 9: Reasons preservation
  assert.strictEqual(exportedEv1.reasons.length, 1);
  assert.strictEqual(exportedEv1.reasons[0].rule, "MALWARE_1");
  assert.strictEqual(exportedEv1.reasons[0].message, "Malware detected");

  // Test 10: No mutation of original history
  const historyBefore = await getAll();
  await exportSecurityHistory();
  const historyAfter = await getAll();
  assert.deepStrictEqual(historyBefore, historyAfter);

  // Test 11: Storage failure handling
  const originalGet = globalThis.chrome.storage.local.get;
  globalThis.chrome.storage.local.get = async () => { throw new Error("Simulated storage failure"); };
  
  let didThrow = false;
  try {
    await exportSecurityHistory();
  } catch (err) {
    didThrow = true;
    assert.strictEqual(err.message, "Storage failure during export");
  }
  assert.ok(didThrow, "Export should reject explicitly on storage failure");
  
  // Restore mock
  globalThis.chrome.storage.local.get = originalGet;

  // Test 12: Independent export (modifying exported data doesn't affect storage)
  jsonString = await exportSecurityHistory();
  exportData = JSON.parse(jsonString);
  exportData.events[0].status = "SAFE"; // mutate the parsed export
  
  const historyAfterMutation = await getAll();
  assert.strictEqual(historyAfterMutation[0].status, "DANGEROUS");

  // Test 13: Repeated exports
  const export1 = JSON.parse(await exportSecurityHistory());
  await new Promise(resolve => setTimeout(resolve, 5)); // ensure time tick
  const export2 = JSON.parse(await exportSecurityHistory());
  
  assert.deepStrictEqual(export1.events, export2.events);
  assert.notStrictEqual(export1.exportedAt, export2.exportedAt);

  console.log("All Security Export 5E tests passed! ✅");
}

runTests().catch(err => {
  console.error("Test failed:");
  console.error(err);
  process.exit(1);
});
