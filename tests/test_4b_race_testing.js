const assert = require('assert');
const fs = require('fs');
const path = require('path');

// Mock crypto
const crypto = require('crypto');
globalThis.crypto = crypto;

// We will test the compiled service-worker.js
const swCodePath = path.join(__dirname, '../extension/background/service-worker.js');
const swCode = fs.readFileSync(swCodePath, 'utf8');

// Mock chrome API
const mockStorage = new Map();
globalThis.chrome = {
  storage: {
    local: {
      get: async (key) => {
        if (typeof key === 'string') return { [key]: mockStorage.get(key) };
        if (Array.isArray(key)) {
          const res = {};
          key.forEach(k => res[k] = mockStorage.get(k));
          return res;
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
  },
  runtime: {
    onMessage: {
      listeners: [],
      addListener(fn) {
        this.listeners.push(fn);
      }
    }
  }
};

// We will mock fetch to control the responses
let fetchDelays = {};
let fetchCalls = { url: 0, file: 0, message: 0 };

globalThis.fetch = async (url, options) => {
  let type = "url";
  if (url.includes("analyze-file")) type = "file";
  else if (url.includes("analyze-message")) type = "message";
  
  fetchCalls[type]++;
  
  const delay = fetchDelays[type] || 50;
  await new Promise(resolve => setTimeout(resolve, delay));

  const payload = JSON.parse(options.body);

  if (type === "url") {
    return {
      ok: true,
      json: async () => ({ status: "DANGEROUS", risk_score: 90, reasons: [] })
    };
  } else if (type === "file") {
    return {
      ok: true,
      json: async () => ({ status: "DANGEROUS", risk_score: 95, reasons: [], filename: payload.filename })
    };
  } else if (type === "message") {
    return {
      ok: true,
      json: async () => ({ status: "DANGEROUS", risk_score: 80, reasons: [], messagePreview: payload.message.slice(0, 50) })
    };
  }
};

// Evaluate the service worker code in the current context
try {
  eval(swCode);
} catch (e) {
  console.error("Failed to eval service-worker.js", e);
  process.exit(1);
}

// Helper to simulate messages from content script
async function sendMessage(msg, sender) {
  for (const listener of chrome.runtime.onMessage.listeners) {
    let sendResponseCalled = false;
    let responseData = null;
    const sendResponse = (resp) => {
      sendResponseCalled = true;
      responseData = resp;
    };
    const result = listener(msg, sender, sendResponse);
    if (result === true) {
      // Async response
      await new Promise(resolve => {
        const check = setInterval(() => {
          if (sendResponseCalled) {
            clearInterval(check);
            resolve();
          }
        }, 10);
      });
      return responseData;
    } else {
      return responseData;
    }
  }
}

async function getHistory() {
  const events = mockStorage.get('verifyfirst_history') || [];
  return events;
}

async function runTests() {
  console.log("Running Phase 4B Race Condition Tests...\n");

  const tabId = 1;
  const sender = { tab: { id: tabId } };

  // Setup tab state
  await sendMessage({ type: "CHAT_SWITCHED", chatId: "ChatA" }, sender);

  console.log("4B.1 Test 1 - Same URL repeated");
  fetchCalls.url = 0;
  const urlPromises = [];
  for (let i = 0; i < 10; i++) {
    urlPromises.push(sendMessage({ type: "ANALYZE_URL", url: "https://suspicious.example" }, sender));
  }
  await Promise.all(urlPromises);
  assert.strictEqual(fetchCalls.url, 1, "Only 1 backend fetch should occur for 10 identical URL requests");

  console.log("4B.2 Test 2 - Same File repeated");
  fetchCalls.file = 0;
  const filePromises = [];
  for (let i = 0; i < 10; i++) {
    filePromises.push(sendMessage({ type: "ANALYZE_FILE", filename: "invoice.pdf.exe" }, sender));
  }
  await Promise.all(filePromises);
  assert.strictEqual(fetchCalls.file, 1, "Only 1 backend fetch should occur for 10 identical file requests");

  console.log("4B.3 Test 3 - Same Message repeated");
  fetchCalls.message = 0;
  const msgPromises = [];
  for (let i = 0; i < 10; i++) {
    msgPromises.push(sendMessage({ type: "ANALYZE_MESSAGE", message: "Your account will be suspended." }, sender));
  }
  await Promise.all(msgPromises);
  assert.strictEqual(fetchCalls.message, 1, "Only 1 backend fetch should occur for 10 identical message requests");

  console.log("4B.4 Test 4 - Three assets simultaneously");
  fetchCalls = { url: 0, file: 0, message: 0 };
  await sendMessage({ type: "CHAT_SWITCHED", chatId: "ChatB" }, sender); // Switch chat to clear cache
  const p1 = sendMessage({ type: "ANALYZE_URL", url: "https://suspicious2.example" }, sender);
  const p2 = sendMessage({ type: "ANALYZE_FILE", filename: "invoice2.pdf.exe" }, sender);
  const p3 = sendMessage({ type: "ANALYZE_MESSAGE", message: "Verify your password immediately." }, sender);
  
  await Promise.all([p1, p2, p3]);
  assert.strictEqual(fetchCalls.url, 1);
  assert.strictEqual(fetchCalls.file, 1);
  assert.strictEqual(fetchCalls.message, 1);

  console.log("4B.5 Test 5 - Duplicate burst across assets");
  fetchCalls = { url: 0, file: 0, message: 0 };
  await sendMessage({ type: "CHAT_SWITCHED", chatId: "ChatC" }, sender);
  const burstPromises = [];
  for (let i = 0; i < 5; i++) burstPromises.push(sendMessage({ type: "ANALYZE_URL", url: "https://suspicious3.example" }, sender));
  for (let i = 0; i < 5; i++) burstPromises.push(sendMessage({ type: "ANALYZE_FILE", filename: "invoice3.pdf.exe" }, sender));
  for (let i = 0; i < 5; i++) burstPromises.push(sendMessage({ type: "ANALYZE_MESSAGE", message: "Third message." }, sender));
  
  await Promise.all(burstPromises);
  assert.strictEqual(fetchCalls.url, 1);
  assert.strictEqual(fetchCalls.file, 1);
  assert.strictEqual(fetchCalls.message, 1);

  console.log("4B.6 Test 6 - Different assets with identical-looking identifiers");
  fetchCalls = { url: 0, file: 0, message: 0 };
  await sendMessage({ type: "CHAT_SWITCHED", chatId: "ChatD" }, sender);
  const idPromises = [
    sendMessage({ type: "ANALYZE_URL", url: "https://payment.exe" }, sender),
    sendMessage({ type: "ANALYZE_FILE", filename: "payment.exe" }, sender),
    sendMessage({ type: "ANALYZE_MESSAGE", message: "payment.exe" }, sender)
  ];
  await Promise.all(idPromises);
  assert.strictEqual(fetchCalls.url, 1);
  assert.strictEqual(fetchCalls.file, 1);
  assert.strictEqual(fetchCalls.message, 1);
  
  // Verify History
  const history = await getHistory();
  // Filter history for ChatD elements
  // We can just check that total history events increased by 3
  
  console.log("4B.7 Test 7 - Chat switch during analysis (discard stale results)");
  fetchCalls = { url: 0, file: 0, message: 0 };
  // Slow down fetch to allow chat switch
  fetchDelays = { url: 500, file: 500, message: 500 };
  await sendMessage({ type: "CHAT_SWITCHED", chatId: "ChatE" }, sender);
  
  const pStaleUrl = sendMessage({ type: "ANALYZE_URL", url: "https://stale.example" }, sender);
  const pStaleFile = sendMessage({ type: "ANALYZE_FILE", filename: "stale.exe" }, sender);
  const pStaleMsg = sendMessage({ type: "ANALYZE_MESSAGE", message: "stale message" }, sender);
  
  // Immediately switch chat
  await sendMessage({ type: "CHAT_SWITCHED", chatId: "ChatF" }, sender);
  
  await Promise.all([pStaleUrl, pStaleFile, pStaleMsg]);
  
  // The results should NOT be in ChatF's state
  const stateF = mockStorage.get(`verifyfirst_tab_${tabId}`) || {};
  assert.strictEqual(stateF.urls["https://stale.example"], undefined, "Stale URL result must not leak into new chat");
  assert.strictEqual(stateF.files["stale.exe"], undefined, "Stale file result must not leak into new chat");
  assert.strictEqual(stateF.messages["stale message"], undefined, "Stale message result must not leak into new chat");

  console.log("\nAll 4B Race Condition Tests Passed!\n");
}

runTests().catch(e => {
  console.error("Test failed:", e);
  process.exit(1);
});
