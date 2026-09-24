const fs = require('fs');
const path = require('path');
const { JSDOM } = require('../extension/node_modules/jsdom');

// We test the compiled JS file
const actionCodePath = path.join(__dirname, '../extension/content/protection/action.js');
const actionCode = fs.readFileSync(actionCodePath, 'utf8');

const guardCodePath = path.join(__dirname, '../extension/content/protection/navigationGuard.js');
const guardCode = fs.readFileSync(guardCodePath, 'utf8');

function createDOM() {
  const dom = new JSDOM(`<!DOCTYPE html><html><body><a id="test-link" href="https://example.com/safe-test">Click Me</a></body></html>`, {
    runScripts: "dangerously",
    url: "https://web.whatsapp.com/"
  });
  
  const window = dom.window;
  const document = window.document;

  window.eval(actionCode + '; window.getProtectionAction = getProtectionAction;');
  window.eval(guardCode + '; window.NavigationGuard = NavigationGuard;');
  
  return { dom, window, document };
}

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

  function setupGuard(window) {
    let warnCount = 0;
    let blockCount = 0;
    let unverifiedCount = 0;
    
    const guard = new window.NavigationGuard({
      onWarn: (record, event) => { warnCount++; },
      onBlock: (record, event) => { blockCount++; },
      onUnverified: (url, event) => { unverifiedCount++; },
      isCandidateUrl: (url) => {
        try {
          const parsed = new URL(url);
          if (parsed.hostname.includes("whatsapp.com")) return false;
          return true;
        } catch { return false; }
      }
    });
    guard.install();
    
    return {
      guard,
      getCounts: () => ({ warnCount, blockCount, unverifiedCount })
    };
  }

  // Test 1: SAFE -> ALLOW
  {
    const { window, document } = createDOM();
    const { guard, getCounts } = setupGuard(window);
    
    guard.setDecision({
      url: "https://example.com/safe-test",
      action: window.getProtectionAction("SAFE"),
      status: "SAFE",
      riskScore: 0,
      updatedAt: Date.now()
    });
    
    const link = document.getElementById('test-link');
    const event = new window.MouseEvent('click', { bubbles: true, cancelable: true });
    link.dispatchEvent(event);
    
    assertEqual(event.defaultPrevented, false, "SAFE click -> ALLOW (not prevented)");
    assertEqual(getCounts().warnCount, 0, "SAFE click -> no warn");
    assertEqual(getCounts().blockCount, 0, "SAFE click -> no block");
  }

  // Test 2: SUSPICIOUS -> WARN
  {
    const { window, document } = createDOM();
    const { guard, getCounts } = setupGuard(window);
    
    guard.setDecision({
      url: "https://example.com/safe-test",
      action: window.getProtectionAction("SUSPICIOUS"),
      status: "SUSPICIOUS",
      riskScore: 60,
      updatedAt: Date.now()
    });
    
    const link = document.getElementById('test-link');
    const event = new window.MouseEvent('click', { bubbles: true, cancelable: true });
    link.dispatchEvent(event);
    
    assertEqual(event.defaultPrevented, true, "SUSPICIOUS click -> WARN (prevented)");
    assertEqual(getCounts().warnCount, 1, "SUSPICIOUS click -> triggers onWarn");
  }

  // Test 3: DANGEROUS -> BLOCK
  {
    const { window, document } = createDOM();
    const { guard, getCounts } = setupGuard(window);
    
    guard.setDecision({
      url: "https://example.com/safe-test",
      action: window.getProtectionAction("DANGEROUS"),
      status: "DANGEROUS",
      riskScore: 95,
      updatedAt: Date.now()
    });
    
    const link = document.getElementById('test-link');
    const event = new window.MouseEvent('click', { bubbles: true, cancelable: true });
    link.dispatchEvent(event);
    
    assertEqual(event.defaultPrevented, true, "DANGEROUS click -> BLOCK (prevented)");
    assertEqual(getCounts().blockCount, 1, "DANGEROUS click -> triggers onBlock");
  }

  // Test 4: Unknown detection status -> BLOCK
  {
    const { window, document } = createDOM();
    const { guard, getCounts } = setupGuard(window);
    
    guard.setDecision({
      url: "https://example.com/safe-test",
      action: window.getProtectionAction("UNKNOWN_STATUS"),
      status: "UNKNOWN_STATUS",
      riskScore: 0,
      updatedAt: Date.now()
    });
    
    const link = document.getElementById('test-link');
    const event = new window.MouseEvent('click', { bubbles: true, cancelable: true });
    link.dispatchEvent(event);
    
    assertEqual(event.defaultPrevented, true, "Unknown status click -> BLOCK (prevented)");
    assertEqual(getCounts().blockCount, 1, "Unknown status click -> triggers onBlock");
  }

  // Test 5: UNVERIFIED -> WARN/prevented
  {
    const { window, document } = createDOM();
    const { guard, getCounts } = setupGuard(window);
    // No decision registered
    
    const link = document.getElementById('test-link');
    const event = new window.MouseEvent('click', { bubbles: true, cancelable: true });
    link.dispatchEvent(event);
    
    assertEqual(event.defaultPrevented, true, "UNVERIFIED click -> prevented");
    assertEqual(getCounts().unverifiedCount, 1, "UNVERIFIED click -> triggers onUnverified");
  }

  // Test 6: Modifiers
  const modifiers = [
    { name: "Ctrl+Click", props: { ctrlKey: true } },
    { name: "Cmd+Click", props: { metaKey: true } },
    { name: "Shift+Click", props: { shiftKey: true } },
    { name: "Alt+Click", props: { altKey: true } }
  ];

  modifiers.forEach(mod => {
    const { window, document } = createDOM();
    const { guard, getCounts } = setupGuard(window);
    guard.setDecision({
      url: "https://example.com/safe-test",
      action: window.getProtectionAction("DANGEROUS"),
      status: "DANGEROUS",
      riskScore: 95,
      updatedAt: Date.now()
    });
    
    const link = document.getElementById('test-link');
    const event = new window.MouseEvent('click', { bubbles: true, cancelable: true, ...mod.props });
    link.dispatchEvent(event);
    
    assertEqual(event.defaultPrevented, true, `${mod.name} -> prevented for DANGEROUS`);
    assertEqual(getCounts().blockCount, 1, `${mod.name} -> triggers onBlock for DANGEROUS`);
  });

  // Test 7: Middle-click
  {
    const { window, document } = createDOM();
    const { guard, getCounts } = setupGuard(window);
    guard.setDecision({
      url: "https://example.com/safe-test",
      action: window.getProtectionAction("DANGEROUS"),
      status: "DANGEROUS",
      riskScore: 95,
      updatedAt: Date.now()
    });
    
    const link = document.getElementById('test-link');
    const event = new window.MouseEvent('click', { bubbles: true, cancelable: true, button: 1 });
    link.dispatchEvent(event);
    
    assertEqual(event.defaultPrevented, true, `Middle-click -> prevented for DANGEROUS`);
    assertEqual(getCounts().blockCount, 1, `Middle-click -> triggers onBlock for DANGEROUS`);
  }
  
  // Test 8: Internal WhatsApp link (ignored)
  {
    const { window, document } = createDOM();
    const { guard, getCounts } = setupGuard(window);
    
    const link = document.getElementById('test-link');
    link.href = "https://web.whatsapp.com/some/path";
    const event = new window.MouseEvent('click', { bubbles: true, cancelable: true });
    link.dispatchEvent(event);
    
    assertEqual(event.defaultPrevented, false, "Internal link -> not prevented (allowed by default)");
    assertEqual(getCounts().unverifiedCount, 0, "Internal link -> no unverified callback");
  }

  // Test 9: URL normalization & duplicate decisions
  {
    const { window, document } = createDOM();
    const { guard, getCounts } = setupGuard(window);
    
    guard.setDecision({
      url: "HTTPS://EXAMPLE.COM/safe-test",
      action: window.getProtectionAction("SAFE"),
      status: "SAFE",
      riskScore: 0,
      updatedAt: Date.now()
    });
    
    guard.setDecision({
      url: "https://example.com/safe-test", // duplicate overriding with dangerous
      action: window.getProtectionAction("DANGEROUS"),
      status: "DANGEROUS",
      riskScore: 95,
      updatedAt: Date.now()
    });
    
    const link = document.getElementById('test-link');
    const event = new window.MouseEvent('click', { bubbles: true, cancelable: true });
    link.dispatchEvent(event);
    
    assertEqual(event.defaultPrevented, true, "Normalized duplicated URL used latest decision");
    assertEqual(getCounts().blockCount, 1, "Latest decision triggers onBlock");
  }

  // Test 10: Cache bounded
  {
    const { window, document } = createDOM();
    const { guard } = setupGuard(window);
    
    for (let i = 0; i < 505; i++) {
      guard.setDecision({
        url: `https://example.com/${i}`,
        action: window.getProtectionAction("SAFE"),
        status: "SAFE",
        riskScore: 0,
        updatedAt: Date.now()
      });
    }
    
    assertEqual(guard.records.size, 500, "Cache size is bounded to 500 max");
  }
  
  // Test 11: install idempotent & uninstall
  {
    const { window, document } = createDOM();
    const { guard, getCounts } = setupGuard(window);
    
    // Install again (idempotent)
    guard.install();
    
    const link = document.getElementById('test-link');
    let event = new window.MouseEvent('click', { bubbles: true, cancelable: true });
    link.dispatchEvent(event);
    assertEqual(getCounts().unverifiedCount, 1, "Works after double install");
    
    // Uninstall
    guard.uninstall();
    let event2 = new window.MouseEvent('click', { bubbles: true, cancelable: true });
    link.dispatchEvent(event2);
    assertEqual(event2.defaultPrevented, false, "Not prevented after uninstall");
    assertEqual(getCounts().unverifiedCount, 1, "No callback after uninstall");
  }

  // Test 12: executeOneTimeOverride for SUSPICIOUS
  {
    const { window, document } = createDOM();
    const { guard, getCounts } = setupGuard(window);
    
    // Mock window.open to track calls
    let openedUrl = null;
    window.open = (url) => { openedUrl = url; };

    guard.setDecision({
      url: "https://example.com/safe-test",
      action: window.getProtectionAction("SUSPICIOUS"),
      status: "SUSPICIOUS",
      riskScore: 60,
      updatedAt: Date.now()
    });
    
    // Attempt override
    guard.executeOneTimeOverride("https://example.com/safe-test");
    assertEqual(openedUrl, "https://example.com/safe-test", "executeOneTimeOverride should call window.open for SUSPICIOUS");
    
    // Next click should STILL warn because status hasn't changed to ALLOW
    const link = document.getElementById('test-link');
    const event = new window.MouseEvent('click', { bubbles: true, cancelable: true });
    link.dispatchEvent(event);
    
    assertEqual(event.defaultPrevented, true, "Second click after override is prevented");
    assertEqual(getCounts().warnCount, 1, "Second click triggers onWarn again");
  }
  
  // Test 13: executeOneTimeOverride for DANGEROUS/UNVERIFIED does nothing
  {
    const { window, document } = createDOM();
    const { guard, getCounts } = setupGuard(window);
    
    let openCount = 0;
    window.open = (url) => { openCount++; };

    guard.setDecision({
      url: "https://example.com/safe-test",
      action: window.getProtectionAction("DANGEROUS"),
      status: "DANGEROUS",
      riskScore: 90,
      updatedAt: Date.now()
    });
    
    guard.executeOneTimeOverride("https://example.com/safe-test");
    assertEqual(openCount, 0, "executeOneTimeOverride should NOT open for DANGEROUS");
    
    // Next click still blocked
    const link = document.getElementById('test-link');
    const event = new window.MouseEvent('click', { bubbles: true, cancelable: true });
    link.dispatchEvent(event);
    
    assertEqual(event.defaultPrevented, true, "Click on DANGEROUS is prevented");
    assertEqual(getCounts().blockCount, 1, "Click on DANGEROUS triggers onBlock");
  }

  // Test 14: Cache isolation - different URLs on same domain
  {
    const { window, document } = createDOM();
    const { guard, getCounts } = setupGuard(window);
    
    guard.setDecision({
      url: "https://evil.com/a",
      action: window.getProtectionAction("DANGEROUS"),
      status: "DANGEROUS",
      riskScore: 90,
      updatedAt: Date.now()
    });
    
    // Test exact match (blocked)
    let link = document.createElement("a");
    link.href = "https://evil.com/a";
    document.body.appendChild(link);
    let event = new window.MouseEvent('click', { bubbles: true, cancelable: true });
    link.dispatchEvent(event);
    assertEqual(event.defaultPrevented, true, "Exact match is blocked");
    
    // Test different path (unverified)
    link.href = "https://evil.com/b";
    event = new window.MouseEvent('click', { bubbles: true, cancelable: true });
    link.dispatchEvent(event);
    assertEqual(event.defaultPrevented, true, "Different path is prevented as UNVERIFIED");
    assertEqual(getCounts().unverifiedCount, 1, "Different path triggers onUnverified");
  }

  // Test 15: Cache isolation - different domains
  {
    const { window, document } = createDOM();
    const { guard, getCounts } = setupGuard(window);
    
    guard.setDecision({
      url: "https://evil.com",
      action: window.getProtectionAction("DANGEROUS"),
      status: "DANGEROUS",
      riskScore: 95,
      updatedAt: Date.now()
    });
    
    let link = document.createElement("a");
    link.href = "https://good.com";
    document.body.appendChild(link);
    let event = new window.MouseEvent('click', { bubbles: true, cancelable: true });
    link.dispatchEvent(event);
    
    assertEqual(event.defaultPrevented, true, "Different domain is prevented as UNVERIFIED");
    assertEqual(getCounts().unverifiedCount, 1, "Different domain triggers onUnverified");
  }

  console.log(`\nResults: ${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
}

runTests();
