"use strict";
const MAX_CACHE_SIZE = 500;
function normalizeUrl(url) {
    try {
        const parsed = new URL(url);
        parsed.protocol = parsed.protocol.toLowerCase();
        parsed.hostname = parsed.hostname.toLowerCase();
        return parsed.toString();
    }
    catch {
        return url.trim();
    }
}
class NavigationGuard {
    constructor(callbacks) {
        this.records = new Map();
        this.installed = false;
        this.handleClick = (event) => {
            if (event.defaultPrevented) {
                return;
            }
            if (event.button !== 0 && event.button !== 1) { // Only handle left and middle clicks
                return;
            }
            const target = event.target;
            if (!(target instanceof Element)) {
                return;
            }
            const anchor = target.closest("a[href]");
            if (!(anchor instanceof HTMLAnchorElement)) {
                return;
            }
            const href = anchor.href;
            if (!href) {
                return;
            }
            // Ignore if it's not a candidate URL (e.g. internal WhatsApp links)
            if (!this.callbacks.isCandidateUrl(href)) {
                return;
            }
            const record = this.getDecision(href);
            if (!record) {
                // UNVERIFIED
                event.preventDefault();
                event.stopPropagation();
                event.stopImmediatePropagation();
                this.callbacks.onUnverified(href, event);
                return;
            }
            switch (record.action) {
                case "ALLOW":
                    return;
                case "WARN":
                    event.preventDefault();
                    event.stopPropagation();
                    event.stopImmediatePropagation();
                    this.callbacks.onWarn(record, event);
                    return;
                case "BLOCK":
                    event.preventDefault();
                    event.stopPropagation();
                    event.stopImmediatePropagation();
                    this.callbacks.onBlock(record, event);
                    return;
                default:
                    event.preventDefault();
                    event.stopPropagation();
                    event.stopImmediatePropagation();
                    this.callbacks.onBlock(record, event);
            }
        };
        this.callbacks = callbacks;
    }
    setDecision(record) {
        const key = normalizeUrl(record.url);
        if (this.records.has(key)) {
            this.records.delete(key);
        }
        this.records.set(key, {
            ...record,
            url: key,
            updatedAt: Date.now(),
        });
        this.trimCache();
    }
    getDecision(url) {
        return this.records.get(normalizeUrl(url));
    }
    removeDecision(url) {
        this.records.delete(normalizeUrl(url));
    }
    clear() {
        this.records.clear();
    }
    install() {
        if (this.installed) {
            return;
        }
        document.addEventListener("click", this.handleClick, true);
        this.installed = true;
    }
    uninstall() {
        if (!this.installed) {
            return;
        }
        document.removeEventListener("click", this.handleClick, true);
        this.installed = false;
    }
    executeOneTimeOverride(url) {
        const record = this.getDecision(url);
        // Only allow override for SUSPICIOUS links.
        // UNVERIFIED and DANGEROUS remain strictly blocked.
        if (!record || record.status !== "SUSPICIOUS") {
            return;
        }
        // Controlled one-time navigation
        window.open(url, "_blank", "noopener,noreferrer");
    }
    trimCache() {
        while (this.records.size > MAX_CACHE_SIZE) {
            const oldestKey = this.records.keys().next().value;
            if (!oldestKey) {
                break;
            }
            this.records.delete(oldestKey);
        }
    }
}
