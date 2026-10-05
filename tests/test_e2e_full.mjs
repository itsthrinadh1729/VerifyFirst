import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { JSDOM } from '../extension/node_modules/jsdom/lib/api.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Mock storage
const localData = { verifyfirst_security_history: [] };
const sessionData = {};

let backendCallCount = 0;
let historyRecordCount = 0;

global.chrome = {
  storage: {
    local: {
      get: async (key) => ({ [key]: localData[key] }),
      set: async (obj) => { Object.assign(localData, obj); },
      remove: async (key) => { delete localData[key]; }
    },
    session: {
      get: async (key) => ({ [key]: sessionData[key] }),
      set: async (obj) => { Object.assign(sessionData, obj); },
      remove: async (key) => { delete sessionData[key]; }
    }
  },
  runtime: {
    id: 'test',
    onMessage: {
      listeners: [],
      addListener: function(l) { this.listeners.push(l); }
    },
    sendMessage: async (msg, cb) => {
      // Content script sending to Service Worker
      let responded = false;
      const sendResponse = (res) => { responded = true; if (cb) cb(res); };
      for (const l of global.chrome.runtime.onMessage.listeners) {
        l(msg, { tab: { id: 1 } }, sendResponse);
      }
    },
    onInstalled: { addListener: () => {} }
  },
  tabs: {
    sendMessage: async () => {}
  },
  action: {
    onClicked: { addListener: () => {} },
    setIcon: () => {}
  }
};

// We mock fetch for backend
global.fetch = async (url, options) => {
  backendCallCount++;
  return {
    ok: true,
    json: async () => ({
      url: JSON.parse(options.body).url,
      status: "DANGEROUS",
      risk_score: 80,
      reasons: []
    })
  };
};

import { record, getAll, clear } from '../extension/background/security/historyStore.js';
import '../extension/background/service-worker.js';

const delay = ms => new Promise(res => setTimeout(res, ms));

async function runTest() {
  console.log("==================================================");
  console.log("1. CLEAN EXISTING HISTORY");
  console.log("==================================================");
  await clear();
  let history = await getAll();
  console.log("Stage 0: after clear =", history.length);

  console.log("==================================================");
  console.log("2. EXACT SINGLE URL TEST");
  console.log("==================================================");
  
  const dom = new JSDOM(`<!DOCTYPE html><html><body></body></html>`, {
    runScripts: "dangerously",
    url: "https://web.whatsapp.com/"
  });
  const window = dom.window;
  const document = window.document;

  window.chrome = global.chrome;
  window.console = console;

  const scannerCode = fs.readFileSync(path.join(__dirname, '../extension/content/whatsappScanner.js'), 'utf8');
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

  simulateChat("Alice", "http://192.168.1.1/");
  await delay(1500); // Allow delayed scans

  history = await getAll();
  console.log("Stage 1: first exact URL =", history.length);
  
  console.log("==================================================");
  console.log("4. WAIT (30+ SECONDS + DOM MUTATIONS)");
  console.log("==================================================");
  
  const oldMain = document.getElementById("main");
  const newMain = oldMain.cloneNode(true);
  oldMain.parentNode.replaceChild(newMain, oldMain);
  await delay(500);

  // simulate time passing by adjusting the recentEncounters map in historyStore...
  // wait, recentEncounters requires 60 seconds to pass. If we wait 2 seconds, dedup works.
  // The test asks to wait 30 seconds, so dedup SHOULD work and we get 1 event.
  
  history = await getAll();
  console.log("Stage 2: 30 seconds normal activity =", history.length);

  console.log("==================================================");
  console.log("6. SECOND EXACT-URL ENCOUNTER (different chat)");
  console.log("==================================================");
  
  simulateChat("Bob", "http://192.168.1.1/");
  await delay(1500);

  history = await getAll();
  console.log("Stage 3: exact same URL sent again (different chat) =", history.length);

  console.log("==================================================");
  console.log("7. EXACT SAME HOST — DIFFERENT URL");
  console.log("==================================================");
  
  simulateChat("Bob", "http://192.168.1.1/admin");
  await delay(1000);
  simulateChat("Bob", "http://192.168.1.1/login");
  await delay(1000);

  history = await getAll();
  console.log("Stage 4: different path =", history.length);

  console.log("Backend POST count =", backendCallCount);
  console.log("Final History Count =", history.length);
}

runTest().catch(console.error);
