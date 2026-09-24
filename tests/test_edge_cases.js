const fs = require('fs');
const path = require('path');

// We test service-worker edge cases directly
const swCodePath = path.join(__dirname, '../extension/background/service-worker.js');
let swCode = "";
try {
  swCode = fs.readFileSync(swCodePath, 'utf8');
} catch {}

function runTests() {
  let passed = 0;
  let failed = 0;

  function assertEqual(actual, expected, testName) {
    if (actual === expected) {
      passed++;
      console.log(`[PASS] ${testName}`);
    } else {
      failed++;
      console.error(`[FAIL] ${testName}: Expected ${expected}, got ${actual}`);
    }
  }

  if (!swCode) {
    console.error("[FAIL] service-worker.js not found.");
    process.exit(1);
  }

  // Setup global mock environment for service-worker
  global.chrome = {
    storage: {
      session: {
        get: async (key) => ({}),
        set: async (val) => {}
      }
    },
    runtime: {
      onMessage: {
        addListener: () => {}
      }
    }
  };

  let currentFetchMock = null;
  global.fetch = async (url, options) => {
    if (currentFetchMock) return currentFetchMock(url, options);
    return { ok: true, json: async () => ({}) };
  };

  // Evaluate the service worker in the global context
  eval(swCode + '; global.handleAnalyzeUrl = handleAnalyzeUrl;');

  // Test 1: Backend Timeout / Network Error fails safely
  (async () => {
    currentFetchMock = async () => {
      throw new Error("Network error");
    };
    // Call the function defined in service-worker.js
    const result = await handleAnalyzeUrl(1, "https://example.com/timeout");
    assertEqual(result.status, "ANALYSIS_UNAVAILABLE", "Network error maps to ANALYSIS_UNAVAILABLE");
    assertEqual(result.risk_score, null, "Risk score is null on network error");

    // Test 2: Malformed response fails safely
    currentFetchMock = async () => ({
      ok: true,
      json: async () => ({ status: "SAFE", risk_score: "not-a-number" })
    });
    const result2 = await handleAnalyzeUrl(1, "https://example.com/malformed");
    assertEqual(result2.status, "ANALYSIS_UNAVAILABLE", "Malformed response maps to ANALYSIS_UNAVAILABLE");

    currentFetchMock = async () => ({
      ok: true,
      json: async () => ({ something: "unexpected" })
    });
    const result3 = await handleAnalyzeUrl(1, "https://example.com/malformed2");
    assertEqual(result3.status, "ANALYSIS_UNAVAILABLE", "Unexpected object maps to ANALYSIS_UNAVAILABLE");

    console.log(`\nResults: ${passed} passed, ${failed} failed`);
    process.exit(failed > 0 ? 1 : 0);
  })();
}

runTests();
