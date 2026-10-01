const fs = require('fs');
const path = require('path');
const { JSDOM } = require('../extension/node_modules/jsdom');

const scannerCodePath = path.join(__dirname, '../extension/content/whatsappScanner.js');
const scannerCode = fs.readFileSync(scannerCodePath, 'utf8');

function runTest(testName, domHtml, expectedMessages, options = {}) {
  return new Promise((resolve, reject) => {
    const dom = new JSDOM(`<!DOCTYPE html><html><body>${domHtml}</body></html>`, {
      runScripts: "dangerously",
      url: "https://web.whatsapp.com/"
    });

    const window = dom.window;
    const document = window.document;

    const extractedMessages = [];
    const chatSwitches = [];

    window.chrome = {
      runtime: {
        id: "mock-extension-id",
        sendMessage: (message, callback) => {
          if (message.type === "ANALYZE_MESSAGE") {
            extractedMessages.push(message.message);
            if (callback) {
              callback({ success: true, record: { message: message.message, status: "SAFE", risk_score: 0, reasons: [], timestamp: Date.now() } });
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

    window.console.log = () => {};
    window.console.error = () => {};

    try {
      window.eval(scannerCode);
    } catch (e) {
      reject(e);
      return;
    }

    if (options.afterLoad) {
      setTimeout(() => {
        try {
          options.afterLoad({ window, document, extractedMessages, chatSwitches });
        } catch (e) {
          reject(e);
          return;
        }
      }, 100);
    }

    const waitMs = options.waitMs || 600;

    setTimeout(() => {
      try {
        const uniqueMessages = [...new Set(extractedMessages)];
        const success = JSON.stringify(uniqueMessages.sort()) === JSON.stringify(expectedMessages.sort());

        if (success) {
          console.log(`[PASS] ${testName}`);
          resolve(true);
        } else {
          console.error(`[FAIL] ${testName}`);
          console.error(`  Expected: ${JSON.stringify(expectedMessages.sort())}`);
          console.error(`  Got:      ${JSON.stringify(uniqueMessages.sort())}`);
          resolve(false);
        }
      } catch (e) {
        reject(e);
      }
    }, waitMs);
  });
}

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

function message(content, timestamp = "10:00 PM", role = "button", direction = "message-in") {
  return `
    <div class="${direction}">
      <div class="copyable-text" role="${role}">
        <span class="_11JPr selectable-text copyable-text">
          <span>${content}</span>
        </span>
        <span data-testid="msg-meta"><span>${timestamp}</span></span>
      </div>
    </div>
  `;
}

async function runAllTests() {
  let allPassed = true;
  let passCount = 0;
  let failCount = 0;

  function record(result) {
    if (result) passCount++;
    else { failCount++; allPassed = false; }
  }

  console.log("Running WhatsApp Message Extraction Tests...\n");

  record(await runTest(
    "A. Extract normal message text",
    whatsappChat("TestChat", message("Hello World")),
    ["Hello World"]
  ));

  record(await runTest(
    "B. Exclude outgoing messages",
    whatsappChat("TestChat", message("Outgoing text", "10:00", "button", "message-out")),
    [] // Should not extract outgoing messages
  ));

  record(await runTest(
    "C. Normalize whitespace",
    whatsappChat("TestChat", message("   Trim   me   ")),
    ["Trim me"] // Normalizer replaces all contiguous whitespace with single space
  ));

  record(await runTest(
    "D. Ignore system messages",
    whatsappChat("TestChat", `
      <div class="message-in">
        <div class="copyable-text">
          <span>Not a selectable text message</span>
        </div>
      </div>
    `),
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
