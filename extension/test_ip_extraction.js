const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const scannerCodePath = path.join(__dirname, 'content', 'whatsappScanner.js');
let scannerCode = fs.readFileSync(scannerCodePath, 'utf8');

// Strip the IIFE wrapper so we can access functions globally inside JSDOM
scannerCode = scannerCode.replace(/^\(function \(\) \{/m, '');
scannerCode = scannerCode.replace(/\}\)\(\);\s*$/m, '');
scannerCode += `\nwindow.discoverUrlsInContainer = discoverUrlsInContainer; window.cleanUrlString = cleanUrlString; window.isCandidateUrl = isCandidateUrl;`;

const virtualConsole = new (require("jsdom").VirtualConsole)();
virtualConsole.on("log", (message) => {
    console.log(message);
});
const dom = new JSDOM(`<!DOCTYPE html><html><body></body></html>`, {
    runScripts: "dangerously",
    virtualConsole: virtualConsole
});

// Polyfill chrome API required by whatsappScanner
dom.window.chrome = {
    runtime: {
        id: "mock_id",
        onMessage: { addListener: () => {} }
    }
};
dom.window.extensionContextInvalid = false;

// Evaluate the stripped script inside JSDOM context
const scriptEl = dom.window.document.createElement('script');
scriptEl.textContent = scannerCode;
dom.window.document.body.appendChild(scriptEl);

const discoverUrls = dom.window.discoverUrlsInContainer;

console.log("\n=================================");
console.log("TEST CASE 1: Standard raw text nested in spans");
console.log("=================================");
const container1 = dom.window.document.createElement('div');
container1.innerHTML = `
<div id="main">
  <div>
    <div>
      <div>
        <span>http://192.168.1.1/admin</span>
        <span>7:08 PM</span>
      </div>
    </div>
  </div>
</div>
`;
discoverUrls(container1);

console.log("\n=================================");
console.log("TEST CASE 2: URL inside an <a> tag");
console.log("=================================");
const container2 = dom.window.document.createElement('div');
container2.innerHTML = `
<a href="http://192.168.1.1/admin">
  <span>http://192.168.1.1/admin</span>
</a>
`;
discoverUrls(container2);


console.log("\n=================================");
console.log("TEST CASE 3: URL appended with timestamp");
console.log("=================================");
const container3 = dom.window.document.createElement('div');
container3.innerHTML = `
<span>http://192.168.1.1/admin7:08 PM</span>
`;
discoverUrls(container3);
