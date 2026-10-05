const fs = require('fs');
const path = require('path');
const { JSDOM } = require('../extension/node_modules/jsdom');

const scannerCodePath = path.join(__dirname, '../extension/content/whatsappScanner.js');
const scannerCode = fs.readFileSync(scannerCodePath, 'utf8');

// The actual test script
async function runE2ETest() {
  console.log("==================================================");
  console.log("1. CLEAN EXISTING HISTORY");
  console.log("==================================================");
  
  // We'll simulate the chrome storage and runtime
  const chromeStorage = { verifyfirst_security_history: [] };
  let analyzeUrlCount = 0;
  
  const dom = new JSDOM(`<!DOCTYPE html><html><body></body></html>`, {
    runScripts: "dangerously",
    url: "https://web.whatsapp.com/"
  });

  const window = dom.window;
  const document = window.document;

  window.chrome = {
    runtime: {
      id: "mock-extension",
      sendMessage: (msg, cb) => {
        if (msg.type === "ANALYZE_URL") {
          analyzeUrlCount++;
          console.log(`[Scanner] Sent ANALYZE_URL for ${msg.url}`);
          if (cb) cb({ success: true });
        }
        if (msg.type === "CHAT_SWITCHED") {
          console.log(`[Scanner] Sent CHAT_SWITCHED to ${msg.chatId}`);
        }
      }
    }
  };

  // Helper to wait
  const delay = ms => new Promise(res => setTimeout(res, ms));

  // Load scanner
  window.eval(scannerCode);
  await delay(100);

  function simulateChat(title, url) {
    document.body.innerHTML = `
      <div id="main">
        <header>
          <div data-testid="conversation-info-header-chat-title" title="${title}">${title}</div>
        </header>
        <div data-testid="conversation-panel-body">
          <div class="message-in"><div class="copyable-text"><a href="${url}">${url}</a></div></div>
        </div>
      </div>
    `;
  }

  console.log("==================================================");
  console.log("2. EXACT SINGLE URL TEST");
  console.log("==================================================");
  
  analyzeUrlCount = 0;
  simulateChat("Alice", "http://192.168.1.1/");
  
  // Allow observer to catch it
  await delay(200);
  console.log(`ANALYZE_URL count: ${analyzeUrlCount}`);

  console.log("==================================================");
  console.log("4. WAIT (Simulating DOM mutation / re-render)");
  console.log("==================================================");
  
  // Simulate WhatsApp re-rendering #main (DOM container replacement)
  const oldMain = document.getElementById("main");
  const newMain = oldMain.cloneNode(true);
  oldMain.parentNode.replaceChild(newMain, oldMain);
  
  // Wait for observer
  await delay(200);
  // Also trigger a random mutation inside the chat
  newMain.querySelector('.message-in').innerHTML += '<span>read</span>';
  await delay(200);
  
  console.log(`ANALYZE_URL count after DOM mutations: ${analyzeUrlCount}`);

  console.log("==================================================");
  console.log("5. OPEN THE SAME URL AGAIN WITHOUT CHAT SWITCH");
  console.log("==================================================");
  
  // Simulating user clicking away or doing nothing, just a re-render
  // Already done above. analyzeUrlCount should still be 1!

  console.log("==================================================");
  console.log("6. SECOND EXACT-URL ENCOUNTER (different chat)");
  console.log("==================================================");
  
  simulateChat("Bob", "http://192.168.1.1/");
  await delay(200);
  
  console.log(`ANALYZE_URL count after chat switch: ${analyzeUrlCount}`);

  console.log("==================================================");
  console.log("7. EXACT SAME HOST — DIFFERENT URL");
  console.log("==================================================");
  
  simulateChat("Charlie", "http://192.168.1.1/admin");
  await delay(200);
  simulateChat("Charlie", "http://192.168.1.1/login");
  await delay(200);
  
  console.log(`ANALYZE_URL count after different paths: ${analyzeUrlCount}`);
  
  console.log("Done.");
}

runE2ETest().catch(e => console.error(e));
