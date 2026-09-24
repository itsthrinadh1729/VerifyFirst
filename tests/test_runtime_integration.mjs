import assert from 'assert';

let backendCallCount = 0;
let backendResponseOverride = null;

// Setup globals before importing service-worker
const mockStorage = new Map();
let storageSetFails = false;

globalThis.chrome = {
  storage: {
    session: {
      get: async (key) => ({ [key]: mockStorage.get(key) }),
      set: async (items) => {
        for (const [k, v] of Object.entries(items)) mockStorage.set(k, JSON.parse(JSON.stringify(v)));
      }
    },
    local: {
      get: async (key) => {
        const val = mockStorage.get(key);
        return { [key]: val ? JSON.parse(JSON.stringify(val)) : undefined };
      },
      set: async (items) => {
        if (storageSetFails) throw new Error("Simulated storage failure");
        for (const [k, v] of Object.entries(items)) mockStorage.set(k, JSON.parse(JSON.stringify(v)));
      }
    }
  },
  runtime: {
    onMessage: {
      listeners: [],
      addListener: function(fn) { this.listeners.push(fn); }
    }
  },
  tabs: {
    sendMessage: async () => {},
    query: async () => [{id: 1}]
  }
};

globalThis.fetch = async (url, options) => {
  backendCallCount++;
  if (backendResponseOverride === 'ERROR') {
    throw new Error("Network error");
  }
  if (backendResponseOverride === 'UNAVAILABLE') {
    return { ok: false, status: 500 };
  }
  
  const body = JSON.parse(options.body);
  const u = body.url;
  
  let status = "SAFE";
  if (u.includes("evil")) status = "DANGEROUS";
  
  return {
    ok: true,
    json: async () => ({
      status: status,
      risk_score: status === "SAFE" ? 0 : 100,
      reasons: [{rule: "RULE", message: "MSG"}]
    })
  };
};

async function simulateMessage(message, tabId = 1) {
  const listener = globalThis.chrome.runtime.onMessage.listeners[0];
  return new Promise((resolve) => {
    listener(message, { tab: { id: tabId } }, resolve);
  });
}

async function runTests() {
  console.log("Running Runtime Integration 6D tests...");
  
  // Import dynamically so globals are bound first
  await import('../extension/background/service-worker.js');
  const { getAll, clear } = await import('../extension/background/security/historyStore.js');

  // Test 1: Normal DANGEROUS
  await clear();
  backendCallCount = 0;
  mockStorage.clear();
  
  let res = await simulateMessage({ type: "ANALYZE_URL", url: "https://evil.com" });
  assert.strictEqual(res.success, true);
  assert.strictEqual(res.record.status, "DANGEROUS");
  
  // allow history to write asynchronously
  await new Promise(r => setTimeout(r, 10));
  let history = await getAll();
  
  assert.strictEqual(backendCallCount, 1);
  assert.strictEqual(history.length, 1);
  assert.strictEqual(history[0].status, "DANGEROUS");
  assert.strictEqual(history[0].protectionAction, "BLOCK");
  
  // Test 2: 10 concurrent identical requests
  await clear();
  backendCallCount = 0;
  mockStorage.clear();
  
  let promises = [];
  for (let i = 0; i < 10; i++) {
    promises.push(simulateMessage({ type: "ANALYZE_URL", url: "https://concurrent.com" }));
  }
  const results = await Promise.all(promises);
  
  await new Promise(r => setTimeout(r, 10));
  history = await getAll();
  
  assert.strictEqual(results.length, 10);
  assert.strictEqual(backendCallCount, 1, "Should deduplicate 10 concurrent requests to 1 backend call");
  assert.strictEqual(history.length, 1, "Should only create 1 history event for deduplicated requests");
  
  // Test 3: Chat switch + same URL
  await clear();
  backendCallCount = 0;
  mockStorage.clear();
  
  await simulateMessage({ type: "ANALYZE_URL", url: "https://switch.com" });
  
  // Switch chat
  await simulateMessage({ type: "CHAT_SWITCHED", chatId: "chat_2" });
  
  await simulateMessage({ type: "ANALYZE_URL", url: "https://switch.com" });
  
  await new Promise(r => setTimeout(r, 10));
  history = await getAll();
  
  assert.strictEqual(backendCallCount, 2, "Should allow repeated analysis after chat switch");
  assert.strictEqual(history.length, 2, "Should create 2 legitimate history events");
  
  // Test 4: ANALYSIS_UNAVAILABLE
  await clear();
  backendCallCount = 0;
  mockStorage.clear();
  
  backendResponseOverride = 'UNAVAILABLE';
  res = await simulateMessage({ type: "ANALYZE_URL", url: "https://unknown.com" });
  backendResponseOverride = null; // reset
  
  assert.strictEqual(res.record.status, "ANALYSIS_UNAVAILABLE");
  
  await new Promise(r => setTimeout(r, 10));
  history = await getAll();
  
  assert.strictEqual(backendCallCount, 1);
  assert.strictEqual(history.length, 0, "ANALYSIS_UNAVAILABLE must not create a history event");
  
  // Test 5: Storage failure
  await clear();
  backendCallCount = 0;
  mockStorage.clear();
  
  storageSetFails = true;
  res = await simulateMessage({ type: "ANALYZE_URL", url: "https://evil.com/storage-fail" });
  storageSetFails = false;
  
  assert.strictEqual(res.success, true);
  assert.strictEqual(res.record.status, "DANGEROUS", "BLOCK (DANGEROUS) must still be returned to UI despite storage failure");
  
  // Test 6: Failed in-flight request can retry
  await clear();
  backendCallCount = 0;
  mockStorage.clear();
  
  backendResponseOverride = 'ERROR';
  res = await simulateMessage({ type: "ANALYZE_URL", url: "https://retry.com" });
  assert.strictEqual(res.record.status, "ANALYSIS_UNAVAILABLE");
  
  backendResponseOverride = null;
  res = await simulateMessage({ type: "ANALYZE_URL", url: "https://retry.com" }); // retry
  assert.strictEqual(res.record.status, "SAFE");
  
  assert.strictEqual(backendCallCount, 2, "Should allow new request because previous one failed and was not cached");
  
  // Test 7: Same URL in different tabs
  await clear();
  backendCallCount = 0;
  mockStorage.clear();
  
  const p1 = simulateMessage({ type: "ANALYZE_URL", url: "https://multitab.com" }, 1);
  const p2 = simulateMessage({ type: "ANALYZE_URL", url: "https://multitab.com" }, 2);
  
  await Promise.all([p1, p2]);
  
  assert.strictEqual(backendCallCount, 2, "Should allow concurrent identical URLs in DIFFERENT tabs");
  
  console.log("All Runtime Integration 6D tests passed! ✅");
}

runTests().catch(err => {
  console.error("Test failed:");
  console.error(err);
  process.exit(1);
});
