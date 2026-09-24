const fs = require('fs');
const path = require('path');
const { JSDOM } = require('../extension/node_modules/jsdom');

const scannerCodePath = path.join(__dirname, '../extension/content/whatsappScanner.js');
const guardCodePath = path.join(__dirname, '../extension/content/protection/navigationGuard.js');
let scannerCode = fs.readFileSync(scannerCodePath, 'utf8');
let guardCode = fs.readFileSync(guardCodePath, 'utf8');

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

  const dom = new JSDOM(`
    <!DOCTYPE html>
    <html>
      <body>
        <div id="main">
          <header>
            <span dir="auto" title="Alice">Alice</span>
          </header>
          <div class="message-in" id="chat-messages">
          </div>
        </div>
      </body>
    </html>
  `, { url: "https://web.whatsapp.com/", runScripts: "dangerously" });

  const window = dom.window;
  const document = window.document;
  
  let capturedCb = null;
  let messages = [];

  window.chrome = {
    runtime: {
      id: "test-extension-id",
      sendMessage: (msg, cb) => {
        messages.push(msg);
        capturedCb = cb;
      }
    }
  };
  
  // Inject NavigationGuard
  window.eval(guardCode + '; window.NavigationGuard = NavigationGuard;');
  
  window.eval(`
    window.getProtectionAction = function(status) {
      if (status === "SAFE") return "ALLOW";
      if (status === "SUSPICIOUS") return "WARN";
      if (status === "DANGEROUS") return "BLOCK";
      return "BLOCK";
    };
  `);
  
  // Expose the guard instance that the scanner creates by modifying the code slightly
  // or we can just capture it if it's attached to window.
  let modifiedScannerCode = scannerCode.replace(
    'const navigationGuard = new NavigationGuard',
    'window.testGuard = new NavigationGuard'
  ).replace(
    'navigationGuard.install()',
    'window.testGuard.install()'
  ).replace(
    /navigationGuard\./g,
    'window.testGuard.'
  );

  window.eval(modifiedScannerCode);
  
  // Helper to wait a bit
  const delay = ms => new Promise(res => setTimeout(res, ms));

  (async () => {
      // Give scanner time to initialize
      await delay(100);

      // Test 1: ANALYSIS_UNAVAILABLE drops and does not record in NavigationGuard
      document.getElementById('chat-messages').innerHTML = '<a href="https://example.com/unavailable">Link</a>';
      
      // Wait for observer to pick it up and debounce
      await delay(250);
      
      const analyzeMsgs = messages.filter(m => m.type === "ANALYZE_URL");
      assertEqual(analyzeMsgs.length, 1, "Scanner dispatched message for new link");
      assertEqual(analyzeMsgs[0].url, "https://example.com/unavailable", "Message contains correct URL");
      
      // Simulate backend responding with ANALYSIS_UNAVAILABLE
      if (capturedCb) {
          capturedCb({
              success: true,
              record: {
                  url: "https://example.com/unavailable",
                  status: "ANALYSIS_UNAVAILABLE",
                  risk_score: null,
                  reasons: []
              }
          });
      }
      
      const record1 = window.testGuard.getDecision("https://example.com/unavailable");
      assertEqual(record1, undefined, "ANALYSIS_UNAVAILABLE is not recorded in NavigationGuard (remains UNVERIFIED)");

      // Test 2: Chat switch race condition (Stale analysis discarded)
      messages = [];
      capturedCb = null;
      
      // Change chat to Bob
      document.querySelector('header span').title = "Bob";
      document.querySelector('header span').textContent = "Bob";
      
      document.getElementById('chat-messages').innerHTML = '<a href="https://example.com/race">Link</a>';
      
      await delay(250); // wait for scanner
      
      assertEqual(messages.length > 0, true, "Scanner dispatched message for new chat");
      const raceMsg = messages.find(m => m.url === "https://example.com/race");
      assertEqual(raceMsg !== undefined, true, "Message for race URL found");
      
      // Change chat AGAIN to Charlie before callback returns
      const bobCallback = capturedCb;
      document.querySelector('header span').title = "Charlie";
      document.querySelector('header span').textContent = "Charlie";
      // Mutate chat container to trigger observer
      document.getElementById('chat-messages').innerHTML = '<a href="https://example.com/race2">Link2</a>';
      
      await delay(250); // wait for chat switch detection
      
      // Now return the callback for Bob's chat using the saved callback
      if (bobCallback) {
          bobCallback({
              success: true,
              record: {
                  url: "https://example.com/race",
                  status: "DANGEROUS",
                  risk_score: 95,
                  reasons: []
              }
          });
      }
      
      const record2 = window.testGuard.getDecision("https://example.com/race");
      assertEqual(record2, undefined, "Stale analysis from previous chat is discarded");

      console.log(`\nResults: ${passed} passed, ${failed} failed`);
      process.exit(failed > 0 ? 1 : 0);
  })();
}

runTests();
