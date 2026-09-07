const fs = require('fs');
const path = require('path');
const { JSDOM } = require('../extension/node_modules/jsdom');

const scannerCodePath = path.join(__dirname, '../extension/content/whatsappScanner.js');
const scannerCode = fs.readFileSync(scannerCodePath, 'utf8');

const overlayCodePath = path.join(__dirname, '../extension/content/verifyFirstOverlay.js');
const overlayCode = fs.readFileSync(overlayCodePath, 'utf8');

/**
 * Runs a single overlay integration test by loading both overlay and scanner.
 */
function runOverlayTest(testName, setupFn, expectFn, waitMs = 1500) {
  return new Promise((resolve, reject) => {
    const dom = new JSDOM(`<!DOCTYPE html><html><body></body></html>`, {
      runScripts: "dangerously",
      url: "https://web.whatsapp.com/"
    });

    const window = dom.window;
    const document = window.document;

    // Callbacks for mock extension
    let analyzeCallback = null;
    let pushResult = null;

    window.chrome = {
      runtime: {
        id: "mock-extension-id",
        sendMessage: (message, callback) => {
          if (message.type === "ANALYZE_URL") {
            analyzeCallback = { message, callback };
          }
        },
        onMessage: {
          addListener: (listener) => {
            pushResult = (record, chatId) => {
              listener({ type: "ANALYSIS_RESULT", record, chatId }, {}, () => {});
            };
          }
        },
        getURL: () => "mock-url"
      }
    };

    // Enable logs for debugging
    // window.console.log = () => {};
    // window.console.error = () => {};

    // Load overlay first, then scanner (same order as manifest.json)
    try {
      window.eval(overlayCode);
      window.eval(scannerCode);
    } catch (e) {
      reject(e);
      return;
    }

    // Give scanner a moment to initialize observer
    setTimeout(() => {
      try {
        setupFn({
          window,
          document,
          mockAnalyze: () => analyzeCallback,
          pushResult: pushResult,
        });

        setTimeout(() => {
          try {
            const passed = expectFn({ window, document });
            if (passed) {
              console.log(`[PASS] ${testName}`);
              resolve(true);
            } else {
              console.error(`[FAIL] ${testName}`);
              resolve(false);
            }
          } catch (e) {
            console.error(`[FAIL] ${testName} (Exception: ${e.message})`);
            resolve(false);
          }
        }, waitMs);
      } catch (e) {
        reject(e);
      }
    }, 100);
  });
}

// ═══════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════

function simulateChat(document, title, urls) {
  document.body.innerHTML = `
    <div id="main">
      <header>
        <div data-testid="conversation-info-header-chat-title" title="${title}">${title}</div>
      </header>
      <div data-testid="conversation-panel-body">
        ${urls.map(u => `<div class="message-in"><div class="copyable-text"><a href="${u}">${u}</a></div></div>`).join('')}
      </div>
    </div>
  `;
}

function hasOverlay(document) {
  return document.getElementById("verifyfirst-overlay-host") !== null;
}

function getOverlayStatus(document) {
  const host = document.getElementById("verifyfirst-overlay-host");
  if (!host || !host.shadowRoot) return null;
  const card = host.shadowRoot.querySelector('.overlay-card');
  if (!card) return null;
  if (card.classList.contains('suspicious')) return 'SUSPICIOUS';
  if (card.classList.contains('dangerous')) return 'DANGEROUS';
  if (card.classList.contains('analysis_unavailable')) return 'ANALYSIS_UNAVAILABLE';
  return 'UNKNOWN';
}

function clickDismiss(document) {
  const host = document.getElementById("verifyfirst-overlay-host");
  if (host && host.shadowRoot) {
    const btn = host.shadowRoot.querySelector('.btn-secondary');
    if (btn) btn.click();
  }
}

// ═══════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════

async function runAllTests() {
  let allPassed = true;
  let passCount = 0;
  let failCount = 0;

  function record(result) {
    if (result) passCount++;
    else { failCount++; allPassed = false; }
  }

  console.log("Running Overlay Integration Tests...\n");

  // 1. SAFE result -> no overlay
  record(await runOverlayTest(
    "1. SAFE result -> no overlay",
    ({ document, pushResult }) => {
      simulateChat(document, "Chat1", ["https://safe.com/"]);
      setTimeout(() => {
        pushResult({ url: "https://safe.com/", status: "SAFE", risk_score: 0 }, "Chat1");
      }, 300);
    },
    ({ document }) => !hasOverlay(document)
  ));

  // 2. SUSPICIOUS result -> overlay displayed
  record(await runOverlayTest(
    "2. SUSPICIOUS result -> overlay displayed",
    ({ document, pushResult }) => {
      simulateChat(document, "Chat1", ["https://suspicious.com/"]);
      setTimeout(() => {
        pushResult({ url: "https://suspicious.com/", status: "SUSPICIOUS", risk_score: 60 }, "Chat1");
      }, 300);
    },
    ({ document }) => hasOverlay(document) && getOverlayStatus(document) === 'SUSPICIOUS'
  ));

  // 3. DANGEROUS result -> overlay displayed
  record(await runOverlayTest(
    "3. DANGEROUS result -> overlay displayed",
    ({ document, pushResult }) => {
      simulateChat(document, "Chat1", ["https://dangerous.com/"]);
      setTimeout(() => {
        pushResult({ url: "https://dangerous.com/", status: "DANGEROUS", risk_score: 95 }, "Chat1");
      }, 350);
    },
    ({ document }) => hasOverlay(document) && getOverlayStatus(document) === 'DANGEROUS'
  ));

  // 4. ANALYSIS_UNAVAILABLE -> unavailable overlay displayed
  record(await runOverlayTest(
    "4. ANALYSIS_UNAVAILABLE -> unavailable overlay displayed",
    ({ document, pushResult }) => {
      simulateChat(document, "Chat1", ["https://error.com/"]);
      setTimeout(() => {
        pushResult({ url: "https://error.com/", status: "ANALYSIS_UNAVAILABLE", risk_score: null }, "Chat1");
      }, 350);
    },
    ({ document }) => hasOverlay(document) && getOverlayStatus(document) === 'ANALYSIS_UNAVAILABLE'
  ));

  // 5. Duplicate result -> only one overlay
  record(await runOverlayTest(
    "5. Duplicate result -> only one overlay",
    ({ document, pushResult }) => {
      simulateChat(document, "Chat1", ["https://dup.com/"]);
      setTimeout(() => {
        pushResult({ url: "https://dup.com/", status: "SUSPICIOUS", risk_score: 55 }, "Chat1");
        pushResult({ url: "https://dup.com/", status: "SUSPICIOUS", risk_score: 55 }, "Chat1");
      }, 350);
    },
    ({ document }) => document.querySelectorAll('#verifyfirst-overlay-host').length === 1
  ));

  // 6. Stale generation push -> no overlay (caught by discoveredUrls)
  record(await runOverlayTest(
    "6. Stale generation push -> no overlay",
    ({ document, pushResult }) => {
      simulateChat(document, "Chat2", ["https://new.com/"]);
      setTimeout(() => {
        // Push result for a URL that was never discovered in Chat2
        pushResult({ url: "https://old.com/", status: "DANGEROUS", risk_score: 90 }, "Chat1");
      }, 350);
    },
    ({ document }) => !hasOverlay(document)
  ));

  // 7. Wrong chat ID push (same URL) -> no leak
  record(await runOverlayTest(
    "7. Wrong chat ID push (same URL) -> no leak",
    ({ document, pushResult }) => {
      simulateChat(document, "ChatNew", ["https://leak-test.com/"]);
      setTimeout(() => {
        // Push result for the SAME URL, but with the OLD chat ID!
        // Should be discarded because resultChatId !== currentChatId
        pushResult({ url: "https://leak-test.com/", status: "DANGEROUS", risk_score: 90 }, "ChatOld");
      }, 350);
    },
    ({ document }) => !hasOverlay(document)
  ));

  // 8. Dismiss overlay -> cleanup works
  record(await runOverlayTest(
    "8. Dismiss overlay -> cleanup works",
    ({ document, pushResult }) => {
      simulateChat(document, "Chat1", ["https://dismiss.com/"]);
      setTimeout(() => {
        pushResult({ url: "https://dismiss.com/", status: "SUSPICIOUS", risk_score: 55 }, "Chat1");
        setTimeout(() => clickDismiss(document), 150);
      }, 350);
    },
    ({ document }) => !hasOverlay(document)
  ));

  // 9. New warning after dismissal -> overlay again
  record(await runOverlayTest(
    "9. New warning after dismissal -> overlay again",
    ({ document, pushResult }) => {
      simulateChat(document, "Chat1", ["https://first.com/"]);
      setTimeout(() => {
        pushResult({ url: "https://first.com/", status: "SUSPICIOUS", risk_score: 55 }, "Chat1");
        setTimeout(() => {
          clickDismiss(document);
          simulateChat(document, "Chat1", ["https://first.com/", "https://second.com/"]);
          setTimeout(() => {
            pushResult({ url: "https://second.com/", status: "DANGEROUS", risk_score: 90 }, "Chat1");
          }, 350);
        }, 150);
      }, 350);
    },
    ({ document }) => hasOverlay(document) && getOverlayStatus(document) === 'DANGEROUS'
  ));

  // 10. Same URL in new chat -> fresh overlay appears
  record(await runOverlayTest(
    "10. Same URL in new chat -> fresh overlay",
    ({ document, window, pushResult }) => {
      simulateChat(document, "ChatA", ["https://shared.com/"]);
      setTimeout(() => {
        pushResult({ url: "https://shared.com/", status: "SUSPICIOUS", risk_score: 55 }, "ChatA");
        
        setTimeout(() => {
          // Switch to ChatB with the SAME url
          simulateChat(document, "ChatB", ["https://shared.com/"]);
          setTimeout(() => {
            // Push for ChatB
            pushResult({ url: "https://shared.com/", status: "SUSPICIOUS", risk_score: 55 }, "ChatB");
          }, 350); // wait for observer to see it and add to discoveredUrls
        }, 150);
      }, 350);
    },
    ({ document }) => hasOverlay(document)
  ));

  console.log(`\n${"═".repeat(50)}`);
  console.log(`Results: ${passCount} passed, ${failCount} failed, ${passCount + failCount} total`);
  console.log(`${"═".repeat(50)}`);

  if (!allPassed) {
    console.error("\nSome tests failed.");
    process.exit(1);
  } else {
    console.log("\nAll overlay tests passed successfully!");
    process.exit(0);
  }
}

runAllTests();
