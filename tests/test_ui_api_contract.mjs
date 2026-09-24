import assert from 'assert';

let backendCallCount = 0;
const mockStorage = new Map();
let storageSetFails = false;
let storageGetFails = false;
let simulateBackendFail = false;

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
        if (storageGetFails) throw new Error("Simulated storage failure");
        const val = mockStorage.get(key);
        return { [key]: val ? JSON.parse(JSON.stringify(val)) : undefined };
      },
      set: async (items) => {
        if (storageSetFails) throw new Error("Simulated storage failure");
        for (const [k, v] of Object.entries(items)) mockStorage.set(k, JSON.parse(JSON.stringify(v)));
      },
      remove: async (key) => {
        mockStorage.delete(key);
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
  if (simulateBackendFail) throw new Error("Network error");
  
  return {
    ok: true,
    json: async () => ({
      status: "DANGEROUS",
      risk_score: 99,
      reasons: [{rule: "RULE", message: "MSG"}]
    })
  };
};

async function simulateMessage(message) {
  const listener = globalThis.chrome.runtime.onMessage.listeners[0];
  return new Promise((resolve) => {
    // If listener doesn't return true, it resolves synchronously. Wait, in service worker we return true for async.
    const keepsChannelOpen = listener(message, { tab: { id: 1 } }, resolve);
    if (!keepsChannelOpen) {
       // if it returned false, sendResponse might have been called synchronously before returning false. 
       // but just in case it didn't call sendResponse, we don't resolve.
       // actually, the listener in service worker always calls sendResponse for our cases.
    }
  });
}

async function runTests() {
  console.log("Running UI/API Contract 7A tests...");
  
  await import('../extension/background/service-worker.js');

  // Helper to populate some data
  async function populateData() {
    mockStorage.clear();
    const { record } = await import('../extension/background/security/historyStore.js');
    await record({
      id: "ev1",
      timestamp: Date.now(),
      hostname: "evil.com",
      status: "DANGEROUS",
      protectionAction: "BLOCK",
      threatCategories: [],
      patterns: [],
      reasons: [],
      riskScore: 99
    });
  }
  
  await populateData();

  // Test 1: GET_SECURITY_STATISTICS
  let res = await simulateMessage({ type: "GET_SECURITY_STATISTICS" });
  assert.strictEqual(res.success, true);
  assert.strictEqual(res.data.totalEvents, 1);
  assert.strictEqual(res.data.dangerousCount, 1);
  
  // Test 2: QUERY_SECURITY_HISTORY
  res = await simulateMessage({ type: "QUERY_SECURITY_HISTORY", query: { status: "DANGEROUS" } });
  assert.strictEqual(res.success, true);
  assert.strictEqual(res.data.length, 1);
  assert.strictEqual(res.data[0].hostname, "evil.com");
  
  // Test 3: EXPORT_SECURITY_HISTORY
  res = await simulateMessage({ type: "EXPORT_SECURITY_HISTORY" });
  assert.strictEqual(res.success, true);
  const parsedExport = JSON.parse(res.data);
  assert.strictEqual(parsedExport.events.length, 1);
  assert.strictEqual(parsedExport.events[0].hostname, "evil.com");
  
  // Test 5: Unknown message
  res = await simulateMessage({ type: "SOMETHING_UNKNOWN" });
  assert.strictEqual(res.success, false);
  assert.strictEqual(res.error, "Unknown message type.");

  // Test 6: Malformed history query
  res = await simulateMessage({ type: "QUERY_SECURITY_HISTORY", query: "not an object" });
  assert.strictEqual(res.success, false);
  assert.strictEqual(res.error, "Invalid security history query.");
  
  // Test 7: Client error propagation (mock service throw -> structured error returned)
  storageGetFails = true;
  res = await simulateMessage({ type: "EXPORT_SECURITY_HISTORY" });
  storageGetFails = false;
  assert.strictEqual(res.success, false);
  assert.strictEqual(res.error, "Security history could not be exported.");
  
  // Test 4 & 8: CLEAR_SECURITY_HISTORY + Clear integration
  res = await simulateMessage({ type: "CLEAR_SECURITY_HISTORY" });
  assert.strictEqual(res.success, true);
  
  // Check stats are 0
  res = await simulateMessage({ type: "GET_SECURITY_STATISTICS" });
  assert.strictEqual(res.success, true);
  assert.strictEqual(res.data.totalEvents, 0);
  
  // Check query is empty
  res = await simulateMessage({ type: "QUERY_SECURITY_HISTORY", query: {} });
  assert.strictEqual(res.success, true);
  assert.strictEqual(res.data.length, 0);

  console.log("All UI/API Contract 7A tests passed! ✅");
}

runTests().catch(err => {
  console.error("Test failed:");
  console.error(err);
  process.exit(1);
});
