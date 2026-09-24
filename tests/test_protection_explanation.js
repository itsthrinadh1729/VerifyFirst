const fs = require('fs');
const path = require('path');
const { JSDOM } = require('../extension/node_modules/jsdom');

const overlayCodePath = path.join(__dirname, '../extension/content/verifyFirstOverlay.js');
const overlayCode = fs.readFileSync(overlayCodePath, 'utf8');

function createDOM() {
  const dom = new JSDOM(`<!DOCTYPE html><html><body></body></html>`, {
    runScripts: "dangerously",
  });
  
  const window = dom.window;
  const document = window.document;

  window.eval(overlayCode);
  
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
  
  function getCard(document) {
      const host = document.getElementById("verifyfirst-overlay-host");
      if (!host) return null;
      return host.shadowRoot.querySelector(".overlay-card");
  }

  // Test 1: SUSPICIOUS rendering with ThreatContext
  {
    const { window, document } = createDOM();
    window.VerifyFirstOverlay.showVerifyFirstWarning({
        url: "https://example.com/sus",
        status: "SUSPICIOUS",
        risk_score: 55,
        reasons: [],
        threat_context: {
            title: "Redirect abuse detected",
            summary: "Uses a redirect to obscure the destination.",
            technical_details: [],
            user_impact: "Could trick you",
            recommended_action: "Do not click"
        }
    });
    
    const card = getCard(document);
    assertEqual(card !== null, true, "Overlay is rendered for SUSPICIOUS");
    assertEqual(card.className.includes("suspicious"), true, "Card has suspicious class");
    
    const title = card.querySelector(".status-title");
    assertEqual(title.textContent, "⚠ Redirect abuse detected", "Title uses threat_context");
    
    const explanation = card.querySelector(".explanation-text");
    assertEqual(explanation.innerHTML.includes("Uses a redirect to obscure the destination."), true, "Explanation uses summary");
    
    const continueBtn = Array.from(card.querySelectorAll("button")).find(b => b.textContent === "Continue");
    assertEqual(continueBtn !== undefined, true, "SUSPICIOUS warning has Continue button");
    
    window.VerifyFirstOverlay.clearVerifyFirstOverlay();
  }

  // Test 2: DANGEROUS rendering with ThreatContext
  {
    const { window, document } = createDOM();
    window.VerifyFirstOverlay.showVerifyFirstWarning({
        url: "https://example.com/evil",
        status: "DANGEROUS",
        risk_score: 95,
        reasons: [],
        threat_context: {
            title: "Domain impersonation",
            summary: "It impersonates a brand.",
            technical_details: [],
            user_impact: "Steals credentials",
            recommended_action: "Close the tab"
        }
    }, [], true);
    
    const card = getCard(document);
    assertEqual(card !== null, true, "Overlay is rendered for DANGEROUS");
    
    const continueBtn = Array.from(card.querySelectorAll("button")).find(b => b.textContent === "Continue");
    assertEqual(continueBtn === undefined, true, "DANGEROUS warning has NO Continue button");
    
    const explanations = Array.from(card.querySelectorAll(".explanation-text"));
    assertEqual(explanations.some(e => e.innerHTML.includes("Close the tab")), true, "DANGEROUS warning shows recommended action");
    
    window.VerifyFirstOverlay.clearVerifyFirstOverlay();
  }
  
  // Test 3: UNVERIFIED rendering
  {
    const { window, document } = createDOM();
    window.VerifyFirstOverlay.showUnverifiedWarning("https://example.com/checking");
    
    const card = getCard(document);
    assertEqual(card !== null, true, "Overlay is rendered for UNVERIFIED");
    
    const title = card.querySelector(".status-title");
    assertEqual(title.textContent, "⚠ Link not verified yet", "Title is correct for UNVERIFIED");
    
    const continueBtn = Array.from(card.querySelectorAll("button")).find(b => b.textContent === "Continue");
    assertEqual(continueBtn === undefined, true, "UNVERIFIED warning has NO Continue button");
    
    window.VerifyFirstOverlay.clearVerifyFirstOverlay();
  }

  console.log(`\nResults: ${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
}

runTests();
