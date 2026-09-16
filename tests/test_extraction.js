const fs = require('fs');
const path = require('path');
const { JSDOM } = require('../extension/node_modules/jsdom');
const assert = require('assert');

const scannerCodePath = path.join(__dirname, '../extension/content/whatsappScanner.js');
let scannerCode = fs.readFileSync(scannerCodePath, 'utf8');

// Helper to run a test
function runExtractionTest(testName, htmlString, expectedUrls) {
  const dom = new JSDOM(`<!DOCTYPE html><html><body></body></html>`, {
    runScripts: "dangerously",
    url: "https://web.whatsapp.com/"
  });

  const window = dom.window;
  const document = window.document;
  
  let extractedUrls = [];

  // Mock chrome
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
      }
    }
  };

  // Run the scanner code in this JSDOM context
  window.eval(scannerCode);

  // Set up the DOM
  document.body.innerHTML = `
    <div id="main">
      <header>
        <div data-testid="conversation-info-header-chat-title" title="Chat">Chat</div>
      </header>
      <div data-testid="conversation-panel-body">
        ${htmlString}
      </div>
    </div>
  `;
  
  // Wait for the mutation observer to trigger scan
  return new Promise((resolve) => {
    setTimeout(() => {
      try {
        // Assert deep equality
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
  console.log("Running Extraction Tests...");
  let passed = 0;
  let failed = 0;

  const testCases = [
    {
      name: "1. <a href='https://open.spotify.com/...'>",
      html: `
        <div class="message-in">
          <a href="https://open.spotify.com/track/123" class="selectable-text copyable-text" rel="noopener noreferrer" target="_blank">https://open.spotify.com/track/123...</a>
        </div>
      `,
      expected: ["https://open.spotify.com/track/123"]
    },
    {
      name: "2. Plain text URL",
      html: `
        <div class="message-in">
          <span dir="ltr">Check this out: https://open.spotify.com/track/abc</span>
        </div>
      `,
      expected: ["https://open.spotify.com/track/abc"]
    },
    {
      name: "3. URL inside nested <span>",
      html: `
        <div class="message-in">
          <span dir="ltr">
            <span>Look at this:</span>
            <span>https://open.spotify.com/track/nested</span>
          </span>
        </div>
      `,
      expected: ["https://open.spotify.com/track/nested"]
    },
    {
      name: "4. URL + U+200E + timestamp",
      html: `
        <div class="message-in">
          <span dir="ltr">
            <span>https://open.spotify.com/track/2gOQU...\u200E11:48 PM</span>
          </span>
        </div>
      `,
      expected: ["https://open.spotify.com/track/2gOQU"]
    },
    {
      name: "5. URL + U+200F + timestamp",
      html: `
        <div class="message-in">
          <span dir="ltr">
            <span>https://open.spotify.com/track/rlm\u200F12:00</span>
          </span>
        </div>
      `,
      expected: ["https://open.spotify.com/track/rlm"]
    },
    {
      name: "6. URL + U+202A/U+202C formatting",
      html: `
        <div class="message-in">
          <span dir="ltr">
            <span>\u202Ahttps://open.spotify.com/track/embed\u202Ctext</span>
          </span>
        </div>
      `,
      expected: ["https://open.spotify.com/track/embed"]
    },
    {
      name: "7. URL followed by ...",
      html: `
        <div class="message-in">
          <span dir="ltr">https://example.com/dots...</span>
        </div>
      `,
      expected: ["https://example.com/dots"]
    },
    {
      name: "8. URL followed by punctuation",
      html: `
        <div class="message-in">
          <span dir="ltr">Hey, go to https://example.com/test! It's cool.</span>
        </div>
      `,
      expected: ["https://example.com/test"]
    },
    {
      name: "9. Multiple URLs",
      html: `
        <div class="message-in">
          <span dir="ltr">https://one.com and https://two.com</span>
        </div>
      `,
      expected: ["https://one.com", "https://two.com"]
    },
    {
      name: "10. Duplicate URL",
      html: `
        <div class="message-in">
          <span dir="ltr">https://dup.com and https://dup.com</span>
        </div>
      `,
      expected: ["https://dup.com"]
    },
    {
      name: "11. URL containing legitimate punctuation",
      html: `
        <div class="message-in">
          <span dir="ltr">https://example.com/path?q=1&b=2#hash! (wait)</span>
        </div>
      `,
      expected: ["https://example.com/path?q=1&b=2#hash"] 
    },
    {
      name: "12. Timestamp never becomes part of URL",
      html: `
        <div class="message-in">
          <span dir="ltr">https://open.spotify.com/track/time\u200E11:48 PM</span>
        </div>
      `,
      expected: ["https://open.spotify.com/track/time"]
    },
    {
      name: "A. Adjacent inline URLs",
      html: `
        <div class="message-in">
          <span dir="ltr"><span>https://one.com</span><span>https://two.com</span></span>
        </div>
      `,
      expected: ["https://one.com", "https://two.com"]
    },
    {
      name: "B. Anchor containing nested markup",
      html: `
        <div class="message-in">
          <span dir="ltr"><a href="https://example.com">https://<span>example</span>.com</a></span>
        </div>
      `,
      expected: ["https://example.com"]
    },
    {
      name: "C. Anchor + identical visible URL",
      html: `
        <div class="message-in">
          <span dir="ltr"><a href="https://both.com/test">https://both.com/test</a></span>
        </div>
      `,
      expected: ["https://both.com/test"]
    },
    {
      name: "D. Anchor + different visible text",
      html: `
        <div class="message-in">
          <span dir="ltr"><a href="https://example.com">Click https://other.com</a></span>
        </div>
      `,
      expected: ["https://example.com"]
    },
    {
      name: "E. Two independent plain-text URLs",
      html: `
        <div class="message-in">
          <span dir="ltr">https://one.com https://two.com</span>
        </div>
      `,
      expected: ["https://one.com", "https://two.com"]
    },
    {
      name: "F. Duplicate plain-text URL",
      html: `
        <div class="message-in">
          <span dir="ltr">https://one.com https://one.com</span>
        </div>
      `,
      expected: ["https://one.com"]
    },
    {
      name: "G. URL + WhatsApp timestamp",
      html: `
        <div class="message-in">
          <span dir="ltr">http://192.168.1.1 10:45 AM</span>
        </div>
      `,
      expected: ["http://192.168.1.1"]
    },
    {
      name: "H. Encoded URL",
      html: `
        <div class="message-in">
          <span dir="ltr">http://user@192.168.1.1/%2E%2E/%2E%2E/</span>
        </div>
      `,
      expected: ["http://user@192.168.1.1/%2E%2E/%2E%2E/"]
    },
    {
      name: "I. URL + multiple spaces + timestamp",
      html: `
        <div class="message-in">
          <span dir="ltr">http://192.168.1.1    10:45 AM</span>
        </div>
      `,
      expected: ["http://192.168.1.1"]
    },
    {
      name: "J. URL + space + PM timestamp",
      html: `
        <div class="message-in">
          <span dir="ltr">http://example.com 10:45 PM</span>
        </div>
      `,
      expected: ["http://example.com"]
    },
    {
      name: "K. Fragmented IP URL + timestamp",
      html: `
        <div class="message-in" data-testid="msg-container">
          <div class="copyable-text" data-pre-plain-text="[10:45 AM, 9/8/2026] User: ">
            <div dir="ltr"><span dir="ltr">http://</span><span dir="ltr">192.168.1.1</span></div>
          </div>
          <div><span dir="auto">10:45 AM</span></div>
        </div>
      `,
      expected: ["http://192.168.1.1"]
    },
    {
      name: "L. Two fragmented URLs in same bubble",
      html: `
        <div class="message-out" data-testid="msg-container">
          <span dir="ltr">http://</span><span dir="ltr">10.0.0.1</span>
          <span dir="ltr"> and </span>
          <span dir="ltr">http://</span><span dir="ltr">10.0.0.2</span>
        </div>
      `,
      expected: ["http://10.0.0.1", "http://10.0.0.2"]
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
