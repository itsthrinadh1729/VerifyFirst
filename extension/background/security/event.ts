import { SecurityEvent, SecurityEventReason, SecurityEventThreatContext } from "./types.js";
import { sanitizeUrlToHostname } from "./sanitizer.js";

/**
 * Creates a normalized SecurityEvent from an analysis response.
 * Returns null if the analysis is UNAVAILABLE, as we do not record those in history.
 */
export function createSecurityEvent(
  analysis: any, 
  url: string
): SecurityEvent | null {
  if (!analysis || !analysis.status || analysis.status === "ANALYSIS_UNAVAILABLE") {
    return null;
  }

  const hostname = sanitizeUrlToHostname(url);
  if (!hostname) {
    return null;
  }

  let protectionAction: "ALLOW" | "WARN" | "BLOCK" = "BLOCK";
  if (analysis.status === "SAFE") protectionAction = "ALLOW";
  else if (analysis.status === "SUSPICIOUS") protectionAction = "WARN";
  else if (analysis.status === "DANGEROUS") protectionAction = "BLOCK";

  const reasons: SecurityEventReason[] = (analysis.reasons || []).map((r: any) => ({
    rule: r.rule || "",
    message: r.message || ""
  }));

  let threatContext: SecurityEventThreatContext | undefined = undefined;
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
    status: analysis.status as "SAFE" | "SUSPICIOUS" | "DANGEROUS",
    riskScore: analysis.risk_score !== undefined ? analysis.risk_score : (analysis.riskScore !== undefined ? analysis.riskScore : null),
    protectionAction,
    threatCategories: [], 
    patterns: [],
    reasons,
    threatContext
  };
}
