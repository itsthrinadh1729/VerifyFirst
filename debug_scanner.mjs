import { JSDOM } from "jsdom";
import fs from "fs";
import path from "path";

const tsPath = path.join(process.cwd(), "extension", "content", "whatsappScanner.ts");
const tsContent = fs.readFileSync(tsPath, "utf-8");

// Mock the DOM
const dom = new JSDOM(`
<!DOCTYPE html>
<html>
<body>
  <div id="main">
    <header>
      <div role="button"><span title="Test Chat" dir="auto">Test Chat</span></div>
    </header>
    <div data-testid="conversation-panel-messages">
      <div class="copyable-text" data-testid="msg-container">
        <span>Here is a link: http://192.168.1.1/admin please check it</span>
      </div>
      <div>
        <a href="http://192.168.1.1/admin">http://192.168.1.1/admin</a>
      </div>
    </div>
  </div>
</body>
</html>
`, { runScripts: "dangerously" });

// Expose DOM to global scope
global.window = dom.window;
global.document = dom.window.document;
global.NodeFilter = dom.window.NodeFilter;
global.HTMLElement = dom.window.HTMLElement;

// Mock chrome API
dom.window.chrome = {
  runtime: {
    id: "test-id",
    sendMessage: (msg, cb) => {
      console.log("MOCK sendMessage:", msg);
      if (cb) cb({ success: true, record: { url: msg.url, status: "SUSPICIOUS", risk_score: 40 } });
    },
    lastError: null
  }
};

// Mock NavigationGuard
dom.window.NavigationGuard = class {
  constructor(cbs) { this.cbs = cbs; }
  setDecision(d) { console.log("MOCK NavigationGuard setDecision:", d); }
  install() { console.log("MOCK NavigationGuard install"); }
  uninstall() { console.log("MOCK NavigationGuard uninstall"); }
};

// Mock window.VerifyFirstOverlay
dom.window.VerifyFirstOverlay = {
  showVerifyFirstWarning: (record) => console.log("MOCK showVerifyFirstWarning:", record),
  resetDisplayedWarnings: () => console.log("MOCK resetDisplayedWarnings")
};

// Assume whatsappScanner.js is already compiled

const jsPath = path.join(process.cwd(), "extension", "content", "whatsappScanner.js");
const jsContent = fs.readFileSync(jsPath, "utf-8");

console.log("--- Executing whatsappScanner.js ---");
try {
  dom.window.eval(jsContent);
  console.log("Scanner executed successfully.");
} catch (e) {
  console.error("Error executing scanner:", e);
}

// Manually trigger the body observer since we inject after load
console.log("Triggering body mutation to start scan...");
const main = dom.window.document.getElementById("main");
const textNode = dom.window.document.createTextNode("trigger");
main.appendChild(textNode);

setTimeout(() => {
  console.log("Done waiting.");
}, 2000);
