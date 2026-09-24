import assert from 'assert';
import { querySecurityHistory } from '../extension/background/security/historyQuery.js';
import { record, clear } from '../extension/background/security/historyStore.js';
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

// Helper to quickly create and directly modify an event to set exact timestamps for tests
const makeEvent = (status, score, action, hostname, timestamp) => {
  const ev = createSecurityEvent({ status, risk_score: score, reasons: [] }, `https://${hostname}`);
  if (ev) {
    ev.protectionAction = action;
    ev.timestamp = timestamp;
  }
  return ev;
};

async function runTests() {
  console.log("Running History Query 5D tests...");

  await clear();

  // Test 1: Empty history
  let results = await querySecurityHistory();
  assert.strictEqual(results.length, 0);

  // Seed history
  const eventsToSeed = [
    makeEvent("SAFE", 0, "ALLOW", "example.com", 1000),         // 0
    makeEvent("SUSPICIOUS", 50, "WARN", "example.com", 2000),   // 1
    makeEvent("DANGEROUS", 100, "BLOCK", "evil.com", 3000),     // 2
    makeEvent("SAFE", null, "ALLOW", "nullscore.com", 4000),    // 3
    makeEvent("DANGEROUS", 90, "BLOCK", "evil.com", 5000),      // 4
    makeEvent("SUSPICIOUS", 40, "WARN", "other.com", 6000)      // 5
  ];

  for (const ev of eventsToSeed) {
    await record(ev);
  }

  // Test 2: No filter -> all events (default newest sorting)
  results = await querySecurityHistory();
  assert.strictEqual(results.length, 6);
  assert.strictEqual(results[0].hostname, "other.com", "Default sort should be newest");

  // Test 3: SAFE filtering
  results = await querySecurityHistory({ status: "SAFE" });
  assert.strictEqual(results.length, 2);

  // Test 4: SUSPICIOUS filtering
  results = await querySecurityHistory({ status: "SUSPICIOUS" });
  assert.strictEqual(results.length, 2);

  // Test 5: DANGEROUS filtering
  results = await querySecurityHistory({ status: "DANGEROUS" });
  assert.strictEqual(results.length, 2);

  // Test 6: ALLOW/WARN/BLOCK filtering
  results = await querySecurityHistory({ protectionAction: "BLOCK" });
  assert.strictEqual(results.length, 2);

  // Test 7: Exact hostname filtering
  results = await querySecurityHistory({ hostname: "evil.com" });
  assert.strictEqual(results.length, 2);
  assert.strictEqual(results[0].hostname, "evil.com");

  // Test 8: Hostname case handling (we expect exact match because sanitizer lowercase domain)
  results = await querySecurityHistory({ hostname: "Evil.com" }); // Stored as evil.com
  assert.strictEqual(results.length, 0); 

  // Test 9 & 10 & 11: Timestamps
  const fromIso = new Date(2500).toISOString();
  const toIso = new Date(4500).toISOString();
  results = await querySecurityHistory({ fromTimestamp: fromIso, toTimestamp: toIso });
  assert.strictEqual(results.length, 2); // 3000, 4000
  assert.strictEqual(results[0].timestamp, 4000); // newest first

  // Test 12, 13, 14: Risk score filtering
  results = await querySecurityHistory({ minRiskScore: 50, maxRiskScore: 90 });
  assert.strictEqual(results.length, 2); // 50, 90 (null is ignored, 100 excluded, 40 excluded, 0 excluded)
  assert.strictEqual(results[0].riskScore, 90);

  // Test 15 & 16: Sorting
  results = await querySecurityHistory({ sort: "newest" });
  assert.strictEqual(results[0].timestamp, 6000);
  
  results = await querySecurityHistory({ sort: "oldest" });
  assert.strictEqual(results[0].timestamp, 1000);
  assert.strictEqual(results[5].timestamp, 6000);

  // Test 17 & 18 & 19 & 20: Pagination
  results = await querySecurityHistory({ sort: "oldest", limit: 2 });
  assert.strictEqual(results.length, 2);
  assert.strictEqual(results[0].timestamp, 1000);
  
  results = await querySecurityHistory({ sort: "oldest", offset: 2 });
  assert.strictEqual(results.length, 4);
  assert.strictEqual(results[0].timestamp, 3000);
  
  results = await querySecurityHistory({ sort: "oldest", limit: 2, offset: 2 });
  assert.strictEqual(results.length, 2);
  assert.strictEqual(results[0].timestamp, 3000);

  results = await querySecurityHistory({ limit: 0 });
  assert.strictEqual(results.length, 0);

  results = await querySecurityHistory({ limit: -5 }); // Should be treated as 0 based on implementation
  assert.strictEqual(results.length, 0);

  results = await querySecurityHistory({ offset: -5 }); // Should fallback to offset 0
  assert.strictEqual(results.length, 6);

  // Test 21: null risk scores
  results = await querySecurityHistory({ minRiskScore: 0 }); // Null score is not >= 0 in our logic, it is ignored
  assert.strictEqual(results.length, 5); // 0, 50, 100, 90, 40

  // Test 22: Combined filters
  results = await querySecurityHistory({ 
    status: "DANGEROUS", 
    hostname: "evil.com", 
    minRiskScore: 95 
  });
  assert.strictEqual(results.length, 1);
  assert.strictEqual(results[0].riskScore, 100);

  // Test 23 & 24: Original history remains unchanged & Returned array is independent
  const original = await querySecurityHistory({ sort: "oldest" });
  const independent = await querySecurityHistory({ sort: "oldest" });
  
  // Mutate independent to ensure it doesn't affect storage
  independent.push(makeEvent("SAFE", 0, "ALLOW", "fake.com", 9999));
  independent[0].status = "DANGEROUS";
  
  const fetchedAgain = await querySecurityHistory({ sort: "oldest" });
  assert.strictEqual(fetchedAgain.length, 6);
  assert.strictEqual(fetchedAgain[0].status, "SAFE");

  // Test 25: Storage failure safely contained
  const originalGet = globalThis.chrome.storage.local.get;
  globalThis.chrome.storage.local.get = async () => { throw new Error("Storage broken"); };
  results = await querySecurityHistory();
  assert.strictEqual(results.length, 0, "Storage failure returns empty array safely");
  globalThis.chrome.storage.local.get = originalGet;

  console.log("All History Query 5D tests passed! ✅");
}

runTests().catch(err => {
  console.error("Test failed:");
  console.error(err);
  process.exit(1);
});
