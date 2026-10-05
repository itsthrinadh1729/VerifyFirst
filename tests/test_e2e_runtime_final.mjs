import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { JSDOM } from '../extension/node_modules/jsdom/lib/api.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const delay = ms => new Promise(res => setTimeout(res, ms));

async function runE2E() {
  const dom = new JSDOM(`<!DOCTYPE html><html><body></body></html>`, {
    runScripts: "dangerously",
    url: "https://web.whatsapp.com/"
  });
  const window = dom.window;
  
  // MOCK CHROME STORAGE & RUNTIME
  const localData = { verifyfirst_security_history: [] };
  const sessionData = {};
  
  let msgListeners = [];
  
  window.chrome = {
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
      onMessage: { addListener: (l) => msgListeners.push(l) },
      sendMessage: async (msg, cb) => {
        // route to service worker
        const sendResponse = (res) => { if (cb) cb(res); };
        for (let l of msgListeners) {
          l(msg, { tab: { id: 1 } }, sendResponse);
        }
      },
      onInstalled: { addListener: () => {} }
    },
    tabs: { sendMessage: async () => {} },
    action: { onClicked: { addListener: () => {} }, setIcon: () => {} }
  };
  
  // Load background scripts inside the SAME window to share the chrome mock
  const eventCode = fs.readFileSync(path.join(__dirname, '../extension/background/security/event.js'), 'utf8');
  const historyStoreCode = fs.readFileSync(path.join(__dirname, '../extension/background/security/historyStore.js'), 'utf8');
  const swCode = fs.readFileSync(path.join(__dirname, '../extension/background/service-worker.js'), 'utf8');
  const scannerCode = fs.readFileSync(path.join(__dirname, '../extension/content/whatsappScanner.js'), 'utf8');

  const stripExports = code => code.replace(/export /g, '').replace(/import .*? from .*?;/g, '');
  
  window.eval(stripExports(eventCode));
  window.eval(stripExports(historyStoreCode));
  
  window.eval(`
    let backendCallCount = 0;
    window.fetch = async (url, options) => {
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
  `);
  
  window.eval(stripExports(swCode));
  window.eval(stripExports(scannerCode));
  
  await delay(100);

  function simulateChat(title, url) {
    window.document.body.innerHTML = `
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
  
  console.log("Stage 0: after clear = " + localData.verifyfirst_security_history.length);

  simulateChat("Alice", "http://192.168.1.1/");
  await delay(1500); // Allow scan + backend + store
  
  console.log("Stage 1: first exact URL = " + localData.verifyfirst_security_history.length);
  
  const oldMain = window.document.getElementById("main");
  const newMain = oldMain.cloneNode(true);
  oldMain.parentNode.replaceChild(newMain, oldMain);
  
  await delay(1000); // Allow MutationObserver to fire and process
  
  console.log("Stage 2: 30 seconds normal activity = " + localData.verifyfirst_security_history.length);

  simulateChat("Bob", "http://192.168.1.1/");
  await delay(1500);
  
  console.log("Stage 3: exact same URL sent again = " + localData.verifyfirst_security_history.length);

  simulateChat("Bob", "http://192.168.1.1/admin");
  await delay(1500);
  simulateChat("Bob", "http://192.168.1.1/login");
  await delay(1500);
  
  console.log("Stage 4: different path = " + localData.verifyfirst_security_history.length);
}

runE2E().catch(console.error);
