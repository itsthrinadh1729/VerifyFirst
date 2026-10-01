import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const { JSDOM } = require('../extension/node_modules/jsdom');

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const scannerCodePath = path.join(__dirname, '../extension/content/whatsappScanner.js');
const scannerCode = fs.readFileSync(scannerCodePath, 'utf8');

async function runPerformanceTest() {
  console.log("Running Phase 4F Performance tests...");

  // Setup mock DOM
  const dom = new JSDOM(`<!DOCTYPE html><html><body><div id="main"></div></body></html>`, {
    runScripts: "dangerously",
    url: "https://web.whatsapp.com/"
  });

  const window = dom.window;
  const document = window.document;

  let requestCount = 0;
  let requests = [];

  window.chrome = {
    runtime: {
      id: "mock-ext",
      getURL: (p) => "mock://" + p,
      sendMessage: (msg) => {
        if (msg.type === "ANALYZE_URL" || msg.type === "ANALYZE_FILE" || msg.type === "ANALYZE_MESSAGE") {
          requestCount++;
          requests.push(msg);
        }
      },
      onMessage: {
        addListener: () => {}
      }
    }
  };

  // 4F.2 MutationObserver stress test
  window.eval(scannerCode);

  const main = document.getElementById("main");
  
  // Simulate a chat container
  const chatContainer = document.createElement("div");
  chatContainer.setAttribute("role", "region");
  chatContainer.setAttribute("aria-label", "Chat List");
  const msgList = document.createElement("div");
  msgList.setAttribute("role", "application");
  chatContainer.appendChild(msgList);
  main.appendChild(chatContainer);

  await new Promise(r => setTimeout(r, 100)); // allow observer to attach

  const stressCounts = [10, 50, 100, 500, 1000];
  
  for (const count of stressCounts) {
    requestCount = 0;
    requests = [];
    
    // Switch chat (to clear state)
    const existingHeader = document.querySelector("header");
    if (existingHeader) existingHeader.remove();
    
    const header = document.createElement("header");
    header.innerHTML = `<div title="Chat${count}"></div>`;
    main.appendChild(header);
    await new Promise(r => setTimeout(r, 10));
    
    const startTime = process.hrtime.bigint();
    
    // Add messages
    for (let i = 0; i < count; i++) {
      const msg = document.createElement("div");
      msg.className = "message-in";
      msg.innerHTML = `
        <div class="selectable-text">
          <span class="selectable-text">Hello world ${i} https://example${i}.com/</span>
        </div>
      `;
      msgList.appendChild(msg);
    }
    
    // Wait for mutation observer
    await new Promise(r => setTimeout(r, 50));
    
    const endTime = process.hrtime.bigint();
    const elapsedMs = Number(endTime - startTime) / 1000000.0;
    
    console.log(`\n--- 4F.2 MutationObserver + IPC Flooding: ${count} items ---`);
    console.log(`Elapsed: ${elapsedMs.toFixed(2)} ms`);
    console.log(`Requests generated: ${requestCount}`);
    
    // Clean up
    msgList.innerHTML = '';
  }

  // 4F.3 IPC Deduplication Stress
  console.log(`\n--- 4F.3 Deduplication (100 identical URLs/Files/Messages) ---`);
  requestCount = 0;
  requests = [];
  
  // Switch chat
  const existingHeader2 = document.querySelector("header");
  if (existingHeader2) existingHeader2.remove();

  const header2 = document.createElement("header");
  header2.innerHTML = `<div title="ChatDedup"></div>`;
  main.appendChild(header2);
  await new Promise(r => setTimeout(r, 10));

  const dedupStart = process.hrtime.bigint();
  for (let i = 0; i < 100; i++) {
    const msg = document.createElement("div");
    msg.className = "message-in";
    msg.innerHTML = `
      <div class="selectable-text">
        <span class="selectable-text">URGENT! https://same-url.example/</span>
      </div>
      <div>
        <span title="same-file.exe"></span>
      </div>
    `;
    msgList.appendChild(msg);
  }
  await new Promise(r => setTimeout(r, 50));
  const dedupEnd = process.hrtime.bigint();
  
  console.log(`Elapsed: ${(Number(dedupEnd - dedupStart) / 1000000.0).toFixed(2)} ms`);
  console.log(`Requests generated: ${requestCount} (Expected: 3 - URL, File, Message)`);
  
  if (requestCount > 3) {
    console.error("[FAIL] Deduplication failed under volume!");
    process.exit(1);
  } else {
    console.log("[PASS] Volume deduplication works.");
  }
}

runPerformanceTest().catch(console.error);
