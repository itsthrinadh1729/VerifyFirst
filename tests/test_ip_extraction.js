const fs = require('fs');
const path = require('path');
const { JSDOM } = require('../extension/node_modules/jsdom');
const assert = require('assert');

const scannerCodePath = path.join(__dirname, '../extension/content/whatsappScanner.js');
let scannerCode = fs.readFileSync(scannerCodePath, 'utf8');

function runExtractionTest(testName, htmlString, expectedUrls) {
  const dom = new JSDOM(`<!DOCTYPE html><html><body></body></html>`, {
    runScripts: "dangerously",
    url: "https://web.whatsapp.com/"
  });

  const window = dom.window;
  const document = window.document;
  
  let extractedUrls = [];

  window.chrome = {
    runtime: {
      id: "mock-extension-id",
      sendMessage: (message, callback) => {
        if (message.type === "ANALYZE_URL") {
          extractedUrls.push(message.url);
        }
      },
      onMessage: {
        addListener: () => {}
      },
      lastError: null
    }
  };

  window.eval(scannerCode);

  document.body.innerHTML = `
    <div id="main">
      <header>
        <div data-testid="conversation-info-header-chat-title" title="Chat">Chat</div>
      </header>
      <div data-testid="conversation-panel-messages">
        <!-- Simulate WhatsApp Web's clickable message bubble using a button tag -->
        <button class="message-in">
          ${htmlString}
        </button>
      </div>
    </div>
  `;
  
  return new Promise((resolve) => {
    setTimeout(() => {
      try {
        assert.deepStrictEqual(extractedUrls, expectedUrls);
        console.log(`[PASS] ${testName}`);
        resolve(true);
      } catch (err) {
        console.error(`[FAIL] ${testName}`);
        console.error(`  Expected:`, expectedUrls);
        console.error(`  Got:     `, extractedUrls);
        resolve(false);
      }
    }, 500);
  });
}

async function runAllTests() {
  console.log("Running IP Extraction Tests...");
  let passed = 0;
  let failed = 0;

  const testCases = [
    {
      name: "TEST 1: http://192.168.1.1/admin",
      html: `<div>http://192.168.1.1/admin</div>`,
      expected: ["http://192.168.1.1/admin"]
    },
    {
      name: "TEST 2: http://192.168.1.1/admin7:08 PM",
      html: `<div>http://192.168.1.1/admin7:08 PM</div>`,
      expected: ["http://192.168.1.1/admin"] // Assuming it strips "7:08 PM" based on Unicode or timestamp logic.
    },
    {
      name: "TEST 3: nested span",
      html: `<span>http://192.168.1.1/admin</span>`,
      expected: ["http://192.168.1.1/admin"]
    },
    {
      name: "TEST 4: anchor",
      html: `<a href="http://192.168.1.1/admin">link</a>`,
      expected: ["http://192.168.1.1/admin"]
    },
    {
      name: "TEST 5: multiple private URLs",
      html: `<div>http://192.168.1.1/admin and http://10.0.0.1/admin</div>`,
      expected: ["http://192.168.1.1/admin", "http://10.0.0.1/admin"]
    },
    {
      name: "TEST 6: localhost",
      html: `<div>http://localhost:8000/test</div>`,
      expected: ["http://localhost:8000/test"]
    },
    {
      name: "TEST 7: loopback",
      html: `<div>http://127.0.0.1/test</div>`,
      expected: ["http://127.0.0.1/test"]
    },
    {
      name: "TEST 8: normal public URL",
      html: `<div>https://open.spotify.com/track/123</div>`,
      expected: ["https://open.spotify.com/track/123"]
    },
    {
      name: "TEST 9: invalid URL",
      html: `<div>http://192.168.1.1:99999/admin</div>`,
      expected: []
    },
    {
      name: "TEST 10: unsupported protocol",
      html: `<div>ftp://192.168.1.1/admin</div>`,
      expected: []
    },
    {
      name: "TEST 11: private URL followed by timestamp",
      html: `<div>http://192.168.1.1/admin\u200E11:48 PM</div>`,
      expected: ["http://192.168.1.1/admin"]
    },
    {
      name: "TEST 12: duplicate private URL",
      html: `<div>http://192.168.1.1/admin and http://192.168.1.1/admin</div>`,
      expected: ["http://192.168.1.1/admin"]
    }
  ];

  for (const tc of testCases) {
    const isPass = await runExtractionTest(tc.name, tc.html, tc.expected);
    if (isPass) passed++;
    else failed++;
  }

  console.log(`\nResults: ${passed} passed, ${failed} failed, ${testCases.length} total`);
  if (failed > 0) {
    process.exit(1);
  }
}

runAllTests();
