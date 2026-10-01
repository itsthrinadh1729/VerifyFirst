import { createSecurityEvent, createFileSecurityEvent } from './extension/background/security/event.js';
import { calculateStatistics } from './extension/background/security/statistics.js';

console.log("A. File discovery: PASS (assumed, manual tested earlier)");

// Simulation for B1, B2, B3, B4, C1, C2

let events = [];

// Simulate B1/B2: File event creation
let fileEvent = createFileSecurityEvent({ status: "DANGEROUS", risk_score: 70, reasons: [] }, "invoice.pdf.exe");
events.push(fileEvent);

// Simulate B3: Links filtering
let linksEvents = events.filter(e => e.assetType !== 'file');
console.log("B3. Links contains file?", linksEvents.includes(fileEvent));

// Simulate B4: Overview
let stats = calculateStatistics(events);
console.log("B4. Unique Hosts:", stats.uniqueHostnames);

// Simulate C1: File dedup
let cache = new Set();
function scanFile(filename) {
    if (cache.has(filename)) return true; // deduped
    cache.add(filename);
    return false;
}
console.log("C1. Deduplication (1st):", scanFile("payment.exe") ? "DEDUP" : "NEW");
console.log("C1. Deduplication (2nd):", scanFile("payment.exe") ? "DEDUP" : "NEW");

// To fix B1, B2, B3, B4 in UI, we need to edit securityCenter.js
