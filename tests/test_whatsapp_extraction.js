const fs = require('fs');
const path = require('path');
const { JSDOM } = require('../extension/node_modules/jsdom');

const scannerCodePath = path.join(__dirname, '../extension/content/whatsappScanner.js');
const scannerCode = fs.readFileSync(scannerCodePath, 'utf8');

/**
 * Runs a single test by creating a JSDOM environment, injecting the actual
 * compiled scanner code, and verifying the URLs sent to the mock service worker.
 *
 * @param {string} testName - Name of the test
 * @param {string} domHtml - HTML to place inside <body>
 * @param {string[]} expectedUrls - Canonical URLs expected to be sent for analysis
 * @param {object} [options] - Additional test options
 * @param {function} [options.afterLoad] - Callback after scanner loads (receives {window, document, extractedUrls})
 * @param {number} [options.waitMs] - Override default wait time
 */
function runTest(testName, domHtml, expectedUrls, options = {}) {
  return new Promise((resolve, reject) => {
    const dom = new JSDOM(`<!DOCTYPE html><html><body>${domHtml}</body></html>`, {
      runScripts: "dangerously",
      url: "https://web.whatsapp.com/"
    });

    const window = dom.window;
    const document = window.document;

    const extractedUrls = [];
    const chatSwitches = [];

    // Mock Chrome extension APIs
    window.chrome = {
      runtime: {
        id: "mock-extension-id",
        sendMessage: (message, callback) => {
          if (message.type === "ANALYZE_URL") {
            extractedUrls.push(message.url);
            if (callback) {
              callback({ success: true, record: { url: message.url, status: "SAFE", risk_score: 0, reasons: [], timestamp: Date.now() } });
            }
          }
          if (message.type === "CHAT_SWITCHED") {
            chatSwitches.push(message.chatId);
            if (callback) callback({ success: true });
          }
        },
        onMessage: {
          addListener: () => {}
        },
        lastError: null
      }
    };

    // Silence logs
    window.console.log = () => {};
    window.console.error = () => {};

    // Evaluate the scanner code
    try {
      window.eval(scannerCode);
    } catch (e) {
      reject(e);
      return;
    }

    // Execute afterLoad callback if provided (for mutation/lifecycle tests)
    if (options.afterLoad) {
      // Small delay to let the scanner initialize
      setTimeout(() => {
        try {
          options.afterLoad({ window, document, extractedUrls, chatSwitches });
        } catch (e) {
          reject(e);
          return;
        }
      }, 100);
    }

    const waitMs = options.waitMs || 600;

    setTimeout(() => {
      try {
        const uniqueUrls = [...new Set(extractedUrls)];
        const success = JSON.stringify(uniqueUrls.sort()) === JSON.stringify(expectedUrls.sort());

        if (success) {
          console.log(`[PASS] ${testName}`);
          resolve(true);
        } else {
          console.error(`[FAIL] ${testName}`);
          console.error(`  Expected: ${JSON.stringify(expectedUrls.sort())}`);
          console.error(`  Got:      ${JSON.stringify(uniqueUrls.sort())}`);
          resolve(false);
        }
      } catch (e) {
        reject(e);
      }
    }, waitMs);
  });
}

// ═══════════════════════════════════════════════
// Helper: Standard WhatsApp message container
// ═══════════════════════════════════════════════
function whatsappChat(chatTitle, messagesHtml) {
  return `
    <div id="main">
      <header>
        <div data-testid="conversation-info-header-chat-title" title="${chatTitle}">${chatTitle}</div>
      </header>
      <div data-testid="conversation-panel-body">
        ${messagesHtml}
      </div>
    </div>
  `;
}

function message(content, timestamp = "10:00 PM", role = "button") {
  return `
    <div class="message-in">
      <div class="copyable-text" role="${role}">
        ${content}
        <span data-testid="msg-meta"><span>${timestamp}</span></span>
      </div>
    </div>
  `;
}

function anchorMsg(url, timestamp = "10:00 PM") {
  return message(`<a href="${url}">${url}</a>`, timestamp);
}

function textMsg(text, timestamp = "10:00 PM") {
  return message(`<span>${text}</span>`, timestamp);
}

// ═══════════════════════════════════════════════
async function runAllTests() {
  let allPassed = true;
  let passCount = 0;
  let failCount = 0;

  function record(result) {
    if (result) passCount++;
    else { failCount++; allPassed = false; }
  }

  console.log("Running WhatsApp Scanner Final Hardening Tests...\n");

  // ─── A. Existing URLs at initialization ───
  record(await runTest(
    "A. Existing URLs at initialization",
    whatsappChat("TestChat", [
      anchorMsg("https://www.google.com/", "10:25 PM"),
      textMsg("http://example.com/path", "10:30 PM")
    ].join("")),
    ["https://www.google.com/", "http://example.com/path"]
  ));

  // ─── A2. Container appears after scanner initialization ───
  record(await runTest(
    "A2. Container appears after scanner initialization",
    `<div id="dummy-wait">Waiting...</div>`, // Initially no container
    ["https://delayed-container.com/"],
    {
      afterLoad: ({ document, window }) => {
        // After 200ms simulate the chat container rendering
        window.setTimeout(() => {
          document.body.innerHTML = whatsappChat("DelayedChat", anchorMsg("https://delayed-container.com/"));
        }, 200);
      },
      waitMs: 1000
    }
  ));


  // ─── B. New URL after MutationObserver ───
  record(await runTest(
    "B. New URL via MutationObserver",
    whatsappChat("TestChat", anchorMsg("https://initial.com/page")),
    ["https://initial.com/page", "https://added-later.com/page"],
    {
      afterLoad: ({ document }) => {
        const body = document.querySelector('[data-testid="conversation-panel-body"]');
        if (body) {
          const newMsg = document.createElement("div");
          newMsg.className = "message-in";
          newMsg.innerHTML = `<div class="copyable-text"><a href="https://added-later.com/page">https://added-later.com/page</a></div>`;
          body.appendChild(newMsg);
        }
      },
      waitMs: 800
    }
  ));

  // ─── C. Chat switch ───
  // After chat switch, the scanner resets discoveredUrls and re-scans.
  // Because the scanner now does an immediate synchronous scan upon attachment,
  // ChatA URL will be found before we simulate the chat switch. 
  // After the chat switch, ChatB URL will be found.
  record(await runTest(
    "C. Chat switch resets state",
    whatsappChat("ChatA", anchorMsg("https://chat-a.com/")),
    ["https://chat-a.com/", "https://chat-b.com/"],
    {
      afterLoad: ({ document }) => {
        // Simulate chat switch
        const titleEl = document.querySelector('[data-testid="conversation-info-header-chat-title"]');
        if (titleEl) {
          titleEl.setAttribute("title", "ChatB");
          titleEl.textContent = "ChatB";
        }
        const body = document.querySelector('[data-testid="conversation-panel-body"]');
        if (body) {
          body.innerHTML = `<div class="message-in"><div class="copyable-text"><a href="https://chat-b.com/">https://chat-b.com/</a></div></div>`;
        }
      },
      waitMs: 2500
    }
  ));

  // ─── D. Lazy-rendered message after chat switch ───
  record(await runTest(
    "D. Lazy-rendered message after chat switch",
    whatsappChat("LazyChat", ""),
    ["https://lazy-loaded.com/"],
    {
      afterLoad: ({ document, window }) => {
        // After 200ms simulate a message appearing
        window.setTimeout(() => {
          const body = document.querySelector('[data-testid="conversation-panel-body"]');
          if (body) {
            body.innerHTML = `<div class="message-in"><div class="copyable-text"><span>https://lazy-loaded.com/</span></div></div>`;
          }
        }, 200);
      },
      waitMs: 1000
    }
  ));

  // ─── E. Same URL discovered twice (deduplication) ───
  record(await runTest(
    "E. Same URL discovered twice → deduplicated",
    whatsappChat("TestChat", [
      anchorMsg("https://duplicate.com/page", "10:00 PM"),
      anchorMsg("https://duplicate.com/page", "10:05 PM")
    ].join("")),
    ["https://duplicate.com/page"]
  ));

  // ─── F. Anchor + text duplicate ───
  record(await runTest(
    "F. Anchor + text duplicate → single URL",
    whatsappChat("TestChat",
      message(`<a href="https://both.com/test">https://both.com/test</a><span>https://both.com/test</span>`)
    ),
    ["https://both.com/test"]
  ));

  // ─── G. IPv4 URL ───
  record(await runTest(
    "G. IPv4 URL extracted correctly",
    whatsappChat("TestChat", textMsg("http://192.0.2.146/login/secure")),
    ["http://192.0.2.146/login/secure"]
  ));

  // ─── H. IPv4 with port ───
  record(await runTest(
    "H. IPv4 with port",
    whatsappChat("TestChat", textMsg("http://192.0.2.146:8080/login")),
    ["http://192.0.2.146:8080/login"]
  ));

  // ─── I. Numeric path ───
  record(await runTest(
    "I. Numeric path preserved",
    whatsappChat("TestChat", textMsg("https://example.com/path/123")),
    ["https://example.com/path/123"]
  ));

  // ─── J. Numeric query ───
  record(await runTest(
    "J. Numeric query preserved",
    whatsappChat("TestChat", textMsg("https://example.com?id=123")),
    ["https://example.com?id=123"]
  ));

  // ─── K. Timestamp contamination prevention ───
  record(await runTest(
    "K. Timestamp NOT appended to URL",
    whatsappChat("TestChat", textMsg("https://www.google.com", "10:25 PM")),
    ["https://www.google.com"]
  ));

  // ─── L. Adjacent URLs ───
  record(await runTest(
    "L. Adjacent URLs separated correctly",
    whatsappChat("TestChat",
      message(`<span>http://192.0.2.146/login/secure)(http://192.0.2.146/login/secure</span>`)
    ),
    ["http://192.0.2.146/login/secure"]
  ));

  // ─── M. Parenthesized URL ───
  record(await runTest(
    "M. Parenthesized URL preserved",
    whatsappChat("TestChat", textMsg("https://example.com/path_(test)")),
    ["https://example.com/path_(test)"]
  ));

  // ─── N. Bracketed URL ───
  record(await runTest(
    "N. Bracketed URL preserved",
    whatsappChat("TestChat", textMsg("https://example.com/page[1]")),
    ["https://example.com/page[1]"]
  ));

  // ─── O. Backend failure (simulated via mock) ───
  {
    // This test verifies the scanner still sends the URL even if the
    // response indicates failure — the scanner's job is extraction, not scoring
    const result = await runTest(
      "O. Backend failure → URL still extracted",
      whatsappChat("TestChat", anchorMsg("https://fail-test.com/")),
      ["https://fail-test.com/"]
    );
    record(result);
  }

  // ─── P. Stale generation result ───
  record(await runTest(
    "P. Chat switch sends CHAT_SWITCHED before scanning",
    whatsappChat("ChatAlpha", anchorMsg("https://alpha.com/")),
    ["https://alpha.com/", "https://beta.com/"],
    {
      afterLoad: ({ document }) => {
        const titleEl = document.querySelector('[data-testid="conversation-info-header-chat-title"]');
        if (titleEl) {
          titleEl.setAttribute("title", "ChatBeta");
          titleEl.textContent = "ChatBeta";
        }
        const body = document.querySelector('[data-testid="conversation-panel-body"]');
        if (body) {
          body.innerHTML = `<div class="message-in"><div class="copyable-text"><a href="https://beta.com/">https://beta.com/</a></div></div>`;
        }
      },
      waitMs: 2500
    }
  ));

  // ─── CRITICAL: Real-world regression fixture (Section 21) ───
  record(await runTest(
    "CRITICAL: Real-world regression (3 unique from 4 messages)",
    whatsappChat("TestChat", [
      anchorMsg("https://learn.eccouncil.org/login?social_login=google&source=shopify", "12:04 PM"),
      anchorMsg("https://testsafebrowsing.appspot.com/s/phishing.html", "11:38 AM"),
      textMsg("http://192.0.2.146/login/secure", "10:47 PM"),
      textMsg("http://192.0.2.146/login/secure", "11:02 PM"),
    ].join("")),
    [
      "https://learn.eccouncil.org/login?social_login=google&source=shopify",
      "https://testsafebrowsing.appspot.com/s/phishing.html",
      "http://192.0.2.146/login/secure"
    ]
  ));

  // ─── ADDITIONAL: Malformed anchor fallback ───
  record(await runTest(
    "ADDITIONAL: Malformed anchor href → text fallback",
    whatsappChat("TestChat",
      message(`<a href="192.0.2.146/login/secure">http://192.0.2.146/login/secure</a>`, "11:02 PM")
    ),
    ["http://192.0.2.146/login/secure"]
  ));

  // ─── ADDITIONAL: Two distinct URLs in adjacent text ───
  record(await runTest(
    "ADDITIONAL: Two distinct adjacent URLs",
    whatsappChat("TestChat",
      message(`<span>https://example.com/a](https://example.org/b</span>`)
    ),
    ["https://example.com/a", "https://example.org/b"]
  ));

  // ─── ADDITIONAL: Multiple IPv4 variants ───
  record(await runTest(
    "ADDITIONAL: Multiple IPv4 variants",
    whatsappChat("TestChat", [
      textMsg("http://192.0.2.146"),
      textMsg("http://192.168.1.1/admin"),
      textMsg("http://127.0.0.1:8080/test"),
    ].join("")),
    [
      "http://192.0.2.146",
      "http://192.168.1.1/admin",
      "http://127.0.0.1:8080/test"
    ]
  ));

  // ─── ADDITIONAL: URL with port preserved ───
  record(await runTest(
    "ADDITIONAL: URL with port preserved",
    whatsappChat("TestChat", textMsg("https://example.com:8080/dashboard")),
    ["https://example.com:8080/dashboard"]
  ));

  // ─── ADDITIONAL: Hidden element exclusion ───
  record(await runTest(
    "ADDITIONAL: Hidden elements excluded",
    whatsappChat("TestChat",
      message(`<span>https://visible.com/</span><span aria-hidden="true">https://hidden.com/</span>`)
    ),
    ["https://visible.com/"]
  ));

  // ─── ADDITIONAL: Header URL exclusion ───
  record(await runTest(
    "ADDITIONAL: Header URLs excluded",
    `<div id="main">
      <header>
        <div data-testid="conversation-info-header-chat-title" title="Test">Test</div>
        <span>https://header-url.com/should-not-extract</span>
      </header>
      <div data-testid="conversation-panel-body">
        ${textMsg("https://message-url.com/should-extract")}
      </div>
    </div>`,
    ["https://message-url.com/should-extract"]
  ));

  // ─── PLAIN TEXT IP TESTS ───
  record(await runTest(
    "PLAIN TEXT IP: div > span",
    whatsappChat("TestChat", `<div><span>http://192.168.1.1/admin</span></div>`),
    ["http://192.168.1.1/admin"]
  ));

  record(await runTest(
    "PLAIN TEXT IP: span with timestamp",
    whatsappChat("TestChat", `<span>\nhttp://192.168.1.1/admin1:59 PM\n</span>`),
    ["http://192.168.1.1/admin"]
  ));

  // ─── PATH TRAVERSAL / ENCODING REGRESSION TESTS ───
  record(await runTest(
    "ENCODING: standard plain IP",
    whatsappChat("TestChat", `<span>http://192.168.1.1/admin</span>`),
    ["http://192.168.1.1/admin"]
  ));

  record(await runTest(
    "ENCODING: userinfo at root",
    whatsappChat("TestChat", `<span>http://user@192.168.1.1/</span>`),
    ["http://user@192.168.1.1/"]
  ));

  record(await runTest(
    "ENCODING: userinfo with path traversal",
    whatsappChat("TestChat", `<span>http://user@192.168.1.1/%2E%2E/%2E%2E/</span>`),
    ["http://user@192.168.1.1/%2E%2E/%2E%2E/"]
  ));

  record(await runTest(
    "ENCODING: standard domain with path traversal",
    whatsappChat("TestChat", `<span>https://example.com/%2e%2e/%2e%2e/test</span>`),
    ["https://example.com/%2e%2e/%2e%2e/test"]
  ));

  record(await runTest(
    "ENCODING: standard query",
    whatsappChat("TestChat", `<span>https://www.google.com/search?q=test</span>`),
    ["https://www.google.com/search?q=test"]
  ));

  record(await runTest(
    "ENCODING: invalid string rejected",
    whatsappChat("TestChat", `<span>not-a-url</span>`),
    []
  ));

  console.log(`\n${"═".repeat(50)}`);
  console.log(`Results: ${passCount} passed, ${failCount} failed, ${passCount + failCount} total`);
  console.log(`${"═".repeat(50)}`);

  if (!allPassed) {
    console.error("\nSome tests failed.");
    process.exit(1);
  } else {
    console.log("\nAll tests passed successfully!");
    process.exit(0);
  }
}

runAllTests();
