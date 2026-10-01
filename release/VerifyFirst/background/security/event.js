import { sanitizeUrlToHostname } from "./sanitizer.js";
/**
 * Creates a normalized SecurityEvent from an analysis response.
 * Returns null if the analysis is UNAVAILABLE, as we do not record those in history.
 */
export function createSecurityEvent(analysis, url) {
    if (!analysis || !analysis.status || analysis.status === "ANALYSIS_UNAVAILABLE") {
        return null;
    }
    const hostname = sanitizeUrlToHostname(url);
    if (!hostname) {
        return null;
    }
    let protectionAction = "BLOCK";
    if (analysis.status === "SAFE")
        protectionAction = "ALLOW";
    else if (analysis.status === "SUSPICIOUS")
        protectionAction = "WARN";
    else if (analysis.status === "DANGEROUS")
        protectionAction = "BLOCK";
    const reasons = (analysis.reasons || []).map((r) => ({
        rule: r.rule || "",
        message: r.message || ""
    }));
    let threatContext = undefined;
    if (analysis.threat_context) {
        threatContext = {
            title: analysis.threat_context.title || "",
            summary: analysis.threat_context.summary || "",
            technicalDetails: Array.isArray(analysis.threat_context.technical_details)
                ? [...analysis.threat_context.technical_details]
                : (Array.isArray(analysis.threat_context.technicalDetails) ? [...analysis.threat_context.technicalDetails] : []),
            userImpact: analysis.threat_context.user_impact || analysis.threat_context.userImpact || "",
            recommendedAction: analysis.threat_context.recommended_action || analysis.threat_context.recommendedAction || ""
        };
    }
    return {
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        hostname,
        status: analysis.status,
        riskScore: analysis.risk_score !== undefined ? analysis.risk_score : (analysis.riskScore !== undefined ? analysis.riskScore : null),
        protectionAction,
        threatCategories: [],
        patterns: [],
        reasons,
        threatContext
    };
}
/**
 * Creates a normalized SecurityEvent from a file analysis response.
 * Separate from createSecurityEvent() — file events use assetType "file"
 * and store the filename instead of a hostname.
 * Returns null if the analysis result is invalid.
 */
export function createFileSecurityEvent(analysis, filename) {
    if (!analysis || !analysis.status) {
        return null;
    }
    if (!filename || typeof filename !== "string" || !filename.trim()) {
        return null;
    }
    let protectionAction = "BLOCK";
    if (analysis.status === "SAFE")
        protectionAction = "ALLOW";
    else if (analysis.status === "SUSPICIOUS")
        protectionAction = "WARN";
    else if (analysis.status === "DANGEROUS")
        protectionAction = "BLOCK";
    const reasons = (analysis.reasons || []).map((r) => ({
        rule: r.rule || "",
        message: r.message || ""
    }));
    return {
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        hostname: "",
        assetType: "file",
        filename: filename.trim(),
        status: analysis.status,
        riskScore: analysis.risk_score !== undefined ? analysis.risk_score : (analysis.riskScore !== undefined ? analysis.riskScore : null),
        protectionAction,
        threatCategories: [],
        patterns: [],
        reasons,
    };
}
/**
 * Creates a normalized SecurityEvent from a message analysis response.
 * Returns null if the analysis result is invalid.
 */
export function createMessageSecurityEvent(analysis, message) {
    if (!analysis || !analysis.status) {
        return null;
    }
    if (!message || typeof message !== "string" || !message.trim()) {
        return null;
    }
    let protectionAction = "BLOCK";
    if (analysis.status === "SAFE")
        protectionAction = "ALLOW";
    else if (analysis.status === "SUSPICIOUS")
        protectionAction = "WARN";
    else if (analysis.status === "DANGEROUS")
        protectionAction = "BLOCK";
    const reasons = (analysis.reasons || []).map((r) => {
        if (typeof r === "string") {
            return { rule: r, message: r };
        }
        return {
            rule: r.rule || "",
            message: r.message || ""
        };
    });
    return {
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        hostname: "",
        assetType: "message",
        messagePreview: analysis.messagePreview || message.slice(0, 100),
        status: analysis.status,
        riskScore: analysis.risk_score !== undefined ? analysis.risk_score : (analysis.riskScore !== undefined ? analysis.riskScore : null),
        protectionAction,
        threatCategories: [],
        patterns: [],
        reasons,
    };
}
