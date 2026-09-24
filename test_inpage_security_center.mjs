import { createRequire } from "module";
const require = createRequire(import.meta.url);
const { JSDOM } = require("./extension/node_modules/jsdom");
import fs from "fs";
import path from "path";
import assert from "assert";

// Load the compiled JS
const securityCenterCode = fs.readFileSync(path.resolve("extension/content/security-center/securityCenter.js"), "utf8");

// Setup JSDOM
const dom = new JSDOM(`<!DOCTYPE html><html><head></head><body></body></html>`, {
  url: "https://web.whatsapp.com/"
});
const window = dom.window;
const document = window.document;

// Mock Chrome API
const listeners = [];
const mockChrome = {
  runtime: {
    id: "mock-extension-id",
    getURL: (p) => `chrome-extension://mock/${p}`,
    onMessage: {
      addListener: (fn) => {
        listeners.push(fn);
      }
    }
  }
};

global.window = window;
global.document = document;
global.HTMLElement = window.HTMLElement;
global.ShadowRoot = window.ShadowRoot;
global.requestAnimationFrame = (fn) => setTimeout(fn, 0);
global.chrome = mockChrome;
global.URL = window.URL;
global.Blob = window.Blob;

// Execute the content script in the global context
try {
  eval(securityCenterCode);
} catch (e) {
  console.error("Error executing securityCenter.js in test:", e);
}

async function runTests() {
  console.log("Starting test_inpage_security_center.mjs...");
  let passed = 0;
  let failed = 0;

  function runTest(name, fn) {
    try {
      fn();
      console.log(`✅ ${name}`);
      passed++;
    } catch (e) {
      console.error(`❌ ${name}`);
      console.error(e.message);
      failed++;
    }
  }

  runTest("1. Message listener registered", () => {
    assert(listeners.length > 0, "No listener registered for chrome.runtime.onMessage");
  });

  // Mock telemetry for the open call
  let fetchStatsCalled = false;
  let fetchHistoryCalled = false;
  let exportCalled = false;
  let wipeCalled = false;
  // We have to mock the dynamic import of telemetryClient.js, but eval() executes the code which has `import()`.
  // Node.js will try to resolve `chrome-extension://...` and fail.
  // Actually, since we're testing the DOM logic, the dynamic import might fail unless we mock `import`.
  // But standard node can't easily mock dynamic `import()` of arbitrary URLs.
  // Let's just check if the DOM elements are created before the import fails.
  
  // Since we can't fully mock dynamic imports easily in this simple eval script without a loader hook,
  // we'll simulate the message.
  
  const sendResponse = () => {};
  
  // Send OPEN_SECURITY_CENTER
  const onMsg = listeners[0];
  if (onMsg) {
    onMsg({ type: "OPEN_SECURITY_CENTER" }, {}, sendResponse);
  }

  // Wait a tick for async DOM updates
  await new Promise(r => setTimeout(r, 50));

  runTest("4. One host created", () => {
    const host = document.getElementById("verifyfirst-security-center-root");
    assert(host, "Host element not found");
  });

  runTest("5. Repeated open does not duplicate host", () => {
    if (onMsg) {
      onMsg({ type: "OPEN_SECURITY_CENTER" }, {}, sendResponse);
    }
    const hosts = document.querySelectorAll("#verifyfirst-security-center-root");
    assert.strictEqual(hosts.length, 1, "Multiple hosts found");
  });

  runTest("8. Shadow DOM is closed", () => {
    const host = document.getElementById("verifyfirst-security-center-root");
    assert(!host.shadowRoot, "Shadow DOM is not closed (shadowRoot is accessible)");
  });
  
  runTest("6. Escape closes the modal", () => {
    const host = document.getElementById("verifyfirst-security-center-root");
    assert(host, "Host element should exist before pressing Escape");
    
    // Dispatch escape
    const event = new window.KeyboardEvent('keydown', { key: 'Escape' });
    document.dispatchEvent(event);
  });

  // Wait for transition to complete
  await new Promise(r => setTimeout(r, 250));

  runTest("7. Close removes modal", () => {
    const host = document.getElementById("verifyfirst-security-center-root");
    assert(!host, "Host element still exists after pressing Escape and waiting for transition");
  });

  console.log(`\nTests finished. Passed: ${passed}, Failed: ${failed}`);
  if (failed > 0) process.exit(1);
}

runTests().catch(console.error);
