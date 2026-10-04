/**
 * VerifyFirst — Legacy UI Regression Test
 *
 * Ensures that the obsolete popup UI implementations do not re-appear
 * in the active extension source or generated files.
 *
 * Run:  node tests/test_no_legacy_ui.js
 */

const fs = require("fs");
const path = require("path");

const extDir = path.join(__dirname, "..", "extension");

let passed = 0;
let failed = 0;

function assert(condition, testName) {
  if (condition) {
    passed++;
    console.log(`  ✅ ${testName}`);
  } else {
    failed++;
    console.log(`  ❌ ${testName}`);
  }
}

console.log("\n🚫  VerifyFirst Legacy UI Regression Tests\n");
console.log("─".repeat(55));

// ── Test 1: popup directory must not exist ──────────────────────────

console.log("\n📂 PART A — File Structure\n");

assert(
  !fs.existsSync(path.join(extDir, "popup")),
  "1. extension/popup/ directory does not exist"
);

assert(
  !fs.existsSync(path.join(extDir, "popup", "popup.html")),
  "2. popup.html does not exist"
);

assert(
  !fs.existsSync(path.join(extDir, "popup", "popup.ts")),
  "3. popup.ts does not exist"
);

assert(
  !fs.existsSync(path.join(extDir, "popup", "popup.js")),
  "4. popup.js does not exist"
);

assert(
  !fs.existsSync(path.join(extDir, "popup", "popup.css")),
  "5. popup.css does not exist"
);

// ── Test 2: manifest.json must NOT have default_popup ───────────────

console.log("\n📋 PART B — Manifest\n");

const manifest = JSON.parse(
  fs.readFileSync(path.join(extDir, "manifest.json"), "utf-8")
);

assert(
  !manifest.action || !manifest.action.default_popup,
  "6. manifest.json has no default_popup"
);

// ── Test 3: Forbidden legacy UI strings must not appear ─────────────

console.log("\n🔍 PART C — Forbidden Strings in Active Source/JS\n");

const FORBIDDEN_STRINGS = [
  "Protection Active",
  "Scanning links in real-time",
  "LINKS ANALYZED",
  "Navigate to web.whatsapp.com to activate",
  "btn-open-center",
  "launcher-status",
  "launcher-stats",
  "launcher-footer",
  "launcher-brand",
  "launcher-subtitle",
  "default_popup",
  "popup/",
  "popup.html",
  "Open Security Center launcher",
  "View Details",
];

/**
 * Recursively collect all .ts, .js, .html, .css files
 * (excluding node_modules)
 */
function collectFiles(dir, result) {
  result = result || [];
  if (!fs.existsSync(dir)) return result;

  const entries = fs.readdirSync(dir);
  for (const entry of entries) {
    if (entry === "node_modules" || entry === ".git") continue;
    const full = path.join(dir, entry);
    const stat = fs.statSync(full);
    if (stat.isDirectory()) {
      collectFiles(full, result);
    } else if (/\.(ts|js|html|css)$/.test(entry)) {
      result.push(full);
    }
  }
  return result;
}

const sourceFiles = collectFiles(extDir);
let testIndex = 7;

for (const forbidden of FORBIDDEN_STRINGS) {
  let found = [];
  for (const filePath of sourceFiles) {
    const content = fs.readFileSync(filePath, "utf-8");
    if (content.includes(forbidden)) {
      found.push(path.relative(extDir, filePath));
    }
  }

  assert(
    found.length === 0,
    `${testIndex}. "${forbidden}" absent from all extension files${
      found.length > 0 ? ` (found in: ${found.join(", ")})` : ""
    }`
  );
  testIndex++;
}

// ── Test 4: Service worker must have onClicked handler ──────────────

console.log("\n⚙️  PART D — Service Worker\n");

const swTs = fs.readFileSync(
  path.join(extDir, "background", "service-worker.ts"),
  "utf-8"
);

assert(
  swTs.includes("chrome.action.onClicked.addListener"),
  `${testIndex++}. Service worker has chrome.action.onClicked handler`
);

assert(
  swTs.includes('type: "OPEN_SECURITY_CENTER"'),
  `${testIndex++}. onClicked handler sends OPEN_SECURITY_CENTER`
);

// ── Summary ─────────────────────────────────────────────────────────

console.log("\n" + "─".repeat(55));
console.log(`\n  Total: ${passed + failed}  |  ✅ ${passed}  |  ❌ ${failed}\n`);

if (failed > 0) {
  console.error("❌ Legacy UI regression test FAILED\n");
  process.exit(1);
} else {
  console.log("✅ All legacy UI regression tests passed\n");
}
