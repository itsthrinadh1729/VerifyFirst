import assert from 'assert';
import { record, getAll, getRecent, clear, MAX_HISTORY_EVENTS } from '../extension/background/security/historyStore.js';
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
  console.log("Running HistoryStore 5B tests...");

  await clear();

  // Test 1: Record and getAll
  const ev1 = createSecurityEvent({ status: "SAFE", risk_score: 0, reasons: [] }, "https://example.com");
  await record(ev1);
  let all = await getAll();
  assert.strictEqual(all.length, 1);
  assert.strictEqual(all[0].id, ev1.id);
  assert.strictEqual(all[0].hostname, "example.com");

  // Test 2: Multiple events & duplicate hostnames
  const ev2 = createSecurityEvent({ status: "DANGEROUS", risk_score: 100, reasons: [] }, "https://example.com");
  await record(ev2);
  all = await getAll();
  assert.strictEqual(all.length, 2);
  assert.strictEqual(all[1].id, ev2.id);
  assert.notStrictEqual(all[0].id, all[1].id, "Event IDs remain unique");
  assert.strictEqual(all[0].hostname, all[1].hostname, "Same hostname can have multiple events");

  // Test 3: getRecent(limit) works & ordering
  const recent1 = await getRecent(1);
  assert.strictEqual(recent1.length, 1);
  assert.strictEqual(recent1[0].id, ev2.id, "Newest event ordering works");

  const recent3 = await getRecent(5); // larger than history
  assert.strictEqual(recent3.length, 2);
  assert.strictEqual(recent3[0].id, ev2.id);
  assert.strictEqual(recent3[1].id, ev1.id);

  const recent0 = await getRecent(0);
  assert.strictEqual(recent0.length, 0, "limit <= 0 handled safely");

  // Test 4: Concurrency
  await clear();
  const promises = [];
  for (let i = 0; i < 50; i++) {
    const ev = createSecurityEvent({ status: "SUSPICIOUS", risk_score: 50, reasons: [] }, `https://site${i}.com`);
    promises.push(record(ev));
  }
  await Promise.all(promises);
  all = await getAll();
  assert.strictEqual(all.length, 50, "Concurrent writes don't lose events");

  // Test 5: MAX_HISTORY_EVENTS limit
  await clear();
  const maxPromises = [];
  for (let i = 0; i < 1050; i++) {
    const ev = createSecurityEvent({ status: "SAFE", risk_score: 0, reasons: [] }, `https://site${i}.com`);
    maxPromises.push(record(ev));
  }
  await Promise.all(maxPromises);
  all = await getAll();
  assert.strictEqual(all.length, MAX_HISTORY_EVENTS, "History capped at MAX_HISTORY_EVENTS");
  assert.strictEqual(all[0].hostname, "site50.com", "Oldest events removed first");

  // Test 6: Sanitization check
  await clear();
  const rawUrl = "https://user:password@evil.com/login?token=SECRET";
  const ev3 = createSecurityEvent({ status: "DANGEROUS", risk_score: 100, reasons: [] }, rawUrl);
  await record(ev3);
  all = await getAll();
  assert.strictEqual(all[0].hostname, "evil.com", "Sanitized hostname remains the only URL component");
  const storedJson = JSON.stringify(all[0]);
  assert.ok(!storedJson.includes("user"), "Raw URL components must not leak into storage");
  assert.ok(!storedJson.includes("password"), "Raw URL components must not leak into storage");
  assert.ok(!storedJson.includes("/login"), "Raw URL components must not leak into storage");
  assert.ok(!storedJson.includes("token=SECRET"), "Raw URL components must not leak into storage");

  // Test 7: Storage failure doesn't throw
  const originalSet = globalThis.chrome.storage.local.set;
  globalThis.chrome.storage.local.set = async () => {
    throw new Error("Simulated storage quota error");
  };
  try {
    const ev4 = createSecurityEvent({ status: "SAFE", risk_score: 0, reasons: [] }, "https://example.com");
    await record(ev4); // Should not throw
    assert.ok(true, "Storage failure didn't throw");
  } catch (e) {
    assert.fail("Storage failure threw an error!");
  } finally {
    globalThis.chrome.storage.local.set = originalSet; // Restore
  }

  console.log("All HistoryStore 5B tests passed! ✅");
}

runTests().catch(err => {
  console.error("Test failed:");
  console.error(err);
  process.exit(1);
});
