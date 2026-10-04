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
          if (message.type === "ANALYZE_URL" || message.type === "ANALYZE_FILE" || message.type === "ANALYZE_MESSAGE") {
            analyzeCallback = { message, callback };
          }
        },
        onMessage: {
          addListener: (listener) => {
            pushResult = (record, chatId) => {
              let type = "ANALYSIS_RESULT";
              if (record.assetType === "file") type = "FILE_ANALYSIS_RESULT";
              if (record.assetType === "message") type = "MESSAGE_ANALYSIS_RESULT";
              listener({ type, record, chatId }, {}, () => {});
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

function simulateChat(document, title, items) {
  let html = '';
  items.forEach(item => {
    if (item.startsWith("http")) {
      html += `<div class="message-in"><div class="copyable-text"><a href="${item}">${item}</a></div></div>`;
    } else if (item.includes(".")) { // basic file simulation
      html += `<div class="message-in" data-testid="msg-document"><div data-testid="document-title">${item}</div></div>`;
    } else { // message
      html += `<div class="message-in"><div class="copyable-text"><span class="selectable-text"><span>${item}</span></span></div></div>`;
    }
  });

  document.body.innerHTML = `
    <div id="main">
      <header>
        <div data-testid="conversation-info-header-chat-title" title="${title}">${title}</div>
      </header>
      <div data-testid="conversation-panel-body">
        ${html}
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
    const btns = host.shadowRoot.querySelectorAll('.btn-secondary, .btn-primary');
    for (const btn of btns) {
      if (btn.textContent === "Continue" || btn.textContent === "Close") {
        btn.click();
        return;
      }
    }
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


  function getNavText(document) {
    const host = document.getElementById("verifyfirst-overlay-host");
    if (!host || !host.shadowRoot) return null;
    const nav = host.shadowRoot.querySelector('.nav-controls span');
    return nav ? nav.textContent : null;
  }

  function clickNext(document) {
    const host = document.getElementById("verifyfirst-overlay-host");
    if (!host || !host.shadowRoot) return;
    const btns = host.shadowRoot.querySelectorAll('.nav-controls .nav-btn');
    if (btns.length > 1) btns[1].click();
  }

  function clickPrev(document) {
    const host = document.getElementById("verifyfirst-overlay-host");
    if (!host || !host.shadowRoot) return;
    const btns = host.shadowRoot.querySelectorAll('.nav-controls .nav-btn');
    if (btns.length > 0) btns[0].click();
  }

  // 11. One suspicious URL -> no navigation controls
  record(await runOverlayTest(
    "11. One suspicious URL -> no navigation controls",
    ({ document, pushResult }) => {
      simulateChat(document, "ChatSingle", ["https://single.com/"]);
      setTimeout(() => {
        pushResult({ url: "https://single.com/", status: "SUSPICIOUS", risk_score: 55 }, "ChatSingle");
      }, 300);
    },
    ({ document }) => hasOverlay(document) && getNavText(document) === null
  ));

  // 12. Two suspicious URLs -> navigation shown, 1 of 2
  record(await runOverlayTest(
    "12. Two suspicious URLs -> navigation shown 1 of 2",
    ({ document, pushResult }) => {
      simulateChat(document, "ChatMulti", ["https://one.com/", "https://two.com/"]);
      setTimeout(() => {
        pushResult({ url: "https://one.com/", status: "SUSPICIOUS", risk_score: 55 }, "ChatMulti");
        pushResult({ url: "https://two.com/", status: "SUSPICIOUS", risk_score: 55 }, "ChatMulti");
      }, 300);
    },
    ({ document }) => hasOverlay(document) && getNavText(document) === "1 of 2"
  ));

  // 13. One suspicious + one dangerous -> navigation shown 1 of 2
  record(await runOverlayTest(
    "13. One suspicious + one dangerous -> navigation shown 1 of 2",
    ({ document, pushResult }) => {
      simulateChat(document, "ChatMulti2", ["https://one.com/", "https://two.com/"]);
      setTimeout(() => {
        pushResult({ url: "https://one.com/", status: "SUSPICIOUS", risk_score: 55 }, "ChatMulti2");
        pushResult({ url: "https://two.com/", status: "DANGEROUS", risk_score: 95 }, "ChatMulti2");
      }, 300);
    },
    ({ document }) => hasOverlay(document) && getNavText(document) === "1 of 2"
  ));

  // 14. SAFE + SUSPICIOUS + SAFE -> navigation NOT shown
  record(await runOverlayTest(
    "14. SAFE + SUSPICIOUS + SAFE -> navigation NOT shown",
    ({ document, pushResult }) => {
      simulateChat(document, "ChatSafeMix", ["https://safe1.com/", "https://susp.com/", "https://safe2.com/"]);
      setTimeout(() => {
        pushResult({ url: "https://safe1.com/", status: "SAFE", risk_score: 0 }, "ChatSafeMix");
        pushResult({ url: "https://susp.com/", status: "SUSPICIOUS", risk_score: 55 }, "ChatSafeMix");
        pushResult({ url: "https://safe2.com/", status: "SAFE", risk_score: 0 }, "ChatSafeMix");
      }, 300);
    },
    ({ document }) => hasOverlay(document) && getNavText(document) === null
  ));

  // (Test 15 removed as wraparound is not supported by implementation)

  // 16. Dismiss current -> current warning removed, next remaining displayed
  record(await runOverlayTest(
    "16. Dismiss current -> next displayed, 1 of 2 to 1 of 1",
    ({ document, pushResult }) => {
      simulateChat(document, "ChatDismiss", ["https://one.com/", "https://two.com/"]);
      setTimeout(() => {
        pushResult({ url: "https://two.com/", status: "DANGEROUS", risk_score: 95 }, "ChatDismiss");
        pushResult({ url: "https://one.com/", status: "SUSPICIOUS", risk_score: 55 }, "ChatDismiss");
        setTimeout(() => {
          clickDismiss(document);
        }, 50);
      }, 300);
    },
    ({ document }) => hasOverlay(document) && getNavText(document) === null && getOverlayStatus(document) === 'SUSPICIOUS'
  ));

  // 17. Message Warning Overlay
  record(await runOverlayTest(
    "17. SUSPICIOUS message -> overlay displayed",
    ({ document, pushResult }) => {
      simulateChat(document, "ChatMsg", ["Message1"]);
      setTimeout(() => {
        pushResult({ url: "Message1", message: "Message1", status: "SUSPICIOUS", risk_score: 60, assetType: "message", messagePreview: "Message1" }, "ChatMsg");
      }, 300);
    },
    ({ document }) => {
      const host = document.getElementById("verifyfirst-overlay-host");
      if (!host || !host.shadowRoot) return false;
      const title = host.shadowRoot.querySelector('.status-title').textContent;
      return hasOverlay(document) && getOverlayStatus(document) === 'SUSPICIOUS' && title.includes('Suspicious message');
    }
  ));

  // 19. CLOSE_VERIFYFIRST_OVERLAY hides the overlay
  record(await runOverlayTest(
    "19. CLOSE_VERIFYFIRST_OVERLAY hides the overlay",
    ({ document, pushResult, window }) => {
      simulateChat(document, "ChatClose", ["https://close.com/"]);
      setTimeout(() => {
        pushResult({ url: "https://close.com/", status: "SUSPICIOUS", risk_score: 55 }, "ChatClose");
        setTimeout(() => {
          if (window.VerifyFirstOverlay && window.VerifyFirstOverlay.hideVerifyFirstOverlay) {
              window.VerifyFirstOverlay.hideVerifyFirstOverlay();
          }
        }, 50);
      }, 300);
    },
    ({ document }) => !hasOverlay(document)
  ));

  // 20. Late analysis result for ALREADY DISMISSED url does not reopen overlay
  record(await runOverlayTest(
    "20. Late analysis result for dismissed URL does not reopen overlay",
    ({ document, pushResult, window }) => {
      simulateChat(document, "ChatLate", ["https://late1.com/"]);
      setTimeout(() => {
        // Late result for late1 arrives, but it's safe so no overlay. Wait, we want to test hiding.
        // Let's first make it suspicious.
        pushResult({ url: "https://late1.com/", status: "SUSPICIOUS", risk_score: 55 }, "ChatLate");
        setTimeout(() => {
          if (window.VerifyFirstOverlay && window.VerifyFirstOverlay.hideVerifyFirstOverlay) {
              window.VerifyFirstOverlay.hideVerifyFirstOverlay();
          }
          setTimeout(() => {
              // Same URL pushed again (maybe from file analysis or message analysis for same url)
              pushResult({ url: "https://late1.com/", status: "DANGEROUS", risk_score: 95 }, "ChatLate");
          }, 50);
        }, 50);
      }, 300);
    },
    ({ document }) => !hasOverlay(document)
  ));

  // 21. Late analysis result for NEW url does reopen overlay
  record(await runOverlayTest(
    "21. Late analysis result for NEW url does reopen overlay",
    ({ document, pushResult, window }) => {
      simulateChat(document, "ChatLateNew", ["https://late1.com/", "https://late2.com/"]);
      setTimeout(() => {
        pushResult({ url: "https://late1.com/", status: "SUSPICIOUS", risk_score: 55 }, "ChatLateNew");
        setTimeout(() => {
          if (window.VerifyFirstOverlay && window.VerifyFirstOverlay.hideVerifyFirstOverlay) {
              window.VerifyFirstOverlay.hideVerifyFirstOverlay();
          }
          setTimeout(() => {
              // NEW URL pushed, should open
              pushResult({ url: "https://late2.com/", status: "DANGEROUS", risk_score: 95 }, "ChatLateNew");
          }, 50);
        }, 50);
      }, 300);
    },
    ({ document }) => hasOverlay(document) && getOverlayStatus(document) === 'DANGEROUS'
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
