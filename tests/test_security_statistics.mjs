import assert from 'assert';
import { calculateStatistics, getSecurityStatistics } from '../extension/background/security/statistics.js';
import { record, clear } from '../extension/background/security/historyStore.js';
import { createSecurityEvent } from '../extension/background/security/event.js';
import crypto from 'crypto';

if (typeof globalThis.crypto === 'undefined') {
  globalThis.crypto = crypto;
}

// Mock chrome.storage.local for Test 9
const mockStorage = new Map();
globalThis.chrome = {
  storage: {
    local: {
      get: async (key) => {
        if (typeof key === 'string') {
          return { [key]: mockStorage.get(key) };
        }
        return {};
      },
      set: async (items) => {
        for (const [k, v] of Object.entries(items)) {
          mockStorage.set(k, v);
        }
      },
      remove: async (key) => {
        mockStorage.delete(key);
      }
    }
  }
};

async function runTests() {
  console.log("Running Security Statistics 5C tests...");

  // Helper to quickly create an event
  const makeEvent = (status, score, action, hostname, timestamp) => {
    return {
      id: crypto.randomUUID(),
      timestamp,
      hostname,
      status,
      riskScore: score,
      protectionAction: action,
      threatCategories: [],
      patterns: [],
      reasons: []
    };
  };

  // Test 1: Empty history
  const emptyStats = calculateStatistics([]);
  assert.strictEqual(emptyStats.totalEvents, 0);
  assert.strictEqual(emptyStats.safeCount, 0);
  assert.strictEqual(emptyStats.uniqueHostnames, 0);
  assert.strictEqual(emptyStats.averageRiskScore, null);
  assert.strictEqual(emptyStats.highestRiskScore, null);
  assert.strictEqual(emptyStats.lastEventTimestamp, null);

  // Test 2: Single SAFE event
  const safeStats = calculateStatistics([
    makeEvent("SAFE", 0, "ALLOW", "example.com", 1000)
  ]);
  assert.strictEqual(safeStats.totalEvents, 1);
  assert.strictEqual(safeStats.safeCount, 1);
  assert.strictEqual(safeStats.allowedCount, 1);

  // Test 3 & 4: Mixed statuses & Protection actions
  const mixedEvents = [
    makeEvent("SAFE", 0, "ALLOW", "a.com", 1000),
    makeEvent("SAFE", 0, "ALLOW", "b.com", 1000),
    makeEvent("SUSPICIOUS", 50, "WARN", "c.com", 1000),
    makeEvent("DANGEROUS", 100, "BLOCK", "d.com", 1000),
    makeEvent("DANGEROUS", 90, "BLOCK", "e.com", 1000)
  ];
  const mixedStats = calculateStatistics(mixedEvents);
  assert.strictEqual(mixedStats.safeCount, 2);
  assert.strictEqual(mixedStats.suspiciousCount, 1);
  assert.strictEqual(mixedStats.dangerousCount, 2);
  assert.strictEqual(mixedStats.allowedCount, 2);
  assert.strictEqual(mixedStats.warnedCount, 1);
  assert.strictEqual(mixedStats.blockedCount, 2);

  // Test 5: Repeated hostname
  const repEvents = [
    makeEvent("SAFE", 0, "ALLOW", "evil.com", 1000),
    makeEvent("DANGEROUS", 100, "BLOCK", "evil.com", 2000),
    makeEvent("SAFE", 0, "ALLOW", "google.com", 3000)
  ];
  const repStats = calculateStatistics(repEvents);
  assert.strictEqual(repStats.totalEvents, 3);
  assert.strictEqual(repStats.uniqueHostnames, 2);

  // Test 6 & 7: Risk calculation & null scores ignored
  const riskEvents = [
    makeEvent("SAFE", 20, "ALLOW", "a.com", 1000),
    makeEvent("SAFE", null, "ALLOW", "b.com", 2000), // null should be ignored
    makeEvent("SUSPICIOUS", 40, "WARN", "c.com", 3000),
    makeEvent("DANGEROUS", 80, "BLOCK", "d.com", 4000),
    makeEvent("DANGEROUS", 100, "BLOCK", "e.com", 5000),
    makeEvent("SAFE", undefined, "ALLOW", "f.com", 6000) // undefined should be ignored
  ];
  const riskStats = calculateStatistics(riskEvents);
  // Valid scores: 20, 40, 80, 100 -> Sum = 240 / 4 = 60
  assert.strictEqual(riskStats.averageRiskScore, 60);
  assert.strictEqual(riskStats.highestRiskScore, 100);

  // Test 8: Latest timestamp out of order
  const timeEvents = [
    makeEvent("SAFE", 0, "ALLOW", "a.com", 5000),
    makeEvent("SAFE", 0, "ALLOW", "a.com", 15000), // newest
    makeEvent("SAFE", 0, "ALLOW", "a.com", 1000)
  ];
  const timeStats = calculateStatistics(timeEvents);
  assert.strictEqual(timeStats.lastEventTimestamp, new Date(15000).toISOString());

  // Test 10: No mutation
  const origEvents = [
    makeEvent("SAFE", 0, "ALLOW", "a.com", 1000),
    makeEvent("DANGEROUS", 100, "BLOCK", "b.com", 2000)
  ];
  const eventsClone = JSON.parse(JSON.stringify(origEvents)); // deep copy
  calculateStatistics(origEvents);
  assert.deepStrictEqual(origEvents, eventsClone, "Events array must not be mutated");

  // Test 9: History integration
  await clear();
  await record(createSecurityEvent({ status: "SAFE", risk_score: 10, reasons: [] }, "https://foo.com"));
  await record(createSecurityEvent({ status: "DANGEROUS", risk_score: 90, reasons: [] }, "https://bar.com"));
  
  const integratedStats = await getSecurityStatistics();
  assert.strictEqual(integratedStats.totalEvents, 2);
  assert.strictEqual(integratedStats.safeCount, 1);
  assert.strictEqual(integratedStats.dangerousCount, 1);
  assert.strictEqual(integratedStats.averageRiskScore, 50);
  assert.strictEqual(integratedStats.uniqueHostnames, 2);

  console.log("All Security Statistics 5C tests passed! ✅");
}

runTests().catch(err => {
  console.error("Test failed:");
  console.error(err);
  process.exit(1);
});
