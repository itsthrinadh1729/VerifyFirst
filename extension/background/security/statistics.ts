import { SecurityEvent, SecurityStatistics } from "./types.js";
import { getAll } from "./historyStore.js";

/**
 * Calculates security statistics from an array of security events.
 * Does not mutate the input array.
 */
export function calculateStatistics(events: SecurityEvent[]): SecurityStatistics {
  let safeCount = 0;
  let suspiciousCount = 0;
  let dangerousCount = 0;

  let allowedCount = 0;
  let warnedCount = 0;
  let blockedCount = 0;

  const hostnames = new Set<string>();
  
  let totalValidScores = 0;
  let scoreSum = 0;
  let highestRiskScore: number | null = null;
  let latestTimestampMs = 0;

  for (const event of events) {
    // Status counts (do not infer unknown statuses)
    if (event.status === "SAFE") safeCount++;
    else if (event.status === "SUSPICIOUS") suspiciousCount++;
    else if (event.status === "DANGEROUS") dangerousCount++;

    // Action counts
    if (event.protectionAction === "ALLOW") allowedCount++;
    else if (event.protectionAction === "WARN") warnedCount++;
    else if (event.protectionAction === "BLOCK") blockedCount++;

    // Unique hostnames
    if (event.hostname) {
      hostnames.add(event.hostname);
    }

    // Risk scores (ignoring null/undefined)
    if (event.riskScore !== null && event.riskScore !== undefined) {
      totalValidScores++;
      scoreSum += event.riskScore;
      if (highestRiskScore === null || event.riskScore > highestRiskScore) {
        highestRiskScore = event.riskScore;
      }
    }

    // Latest timestamp
    if (event.timestamp > latestTimestampMs) {
      latestTimestampMs = event.timestamp;
    }
  }

  let averageRiskScore: number | null = null;
  if (totalValidScores > 0) {
    const rawAverage = scoreSum / totalValidScores;
    averageRiskScore = Math.round(rawAverage * 100) / 100;
  }

  let lastEventTimestamp: string | null = null;
  if (latestTimestampMs > 0) {
    lastEventTimestamp = new Date(latestTimestampMs).toISOString();
  }

  return {
    totalEvents: events.length,
    safeCount,
    suspiciousCount,
    dangerousCount,
    allowedCount,
    warnedCount,
    blockedCount,
    uniqueHostnames: hostnames.size,
    averageRiskScore,
    highestRiskScore,
    lastEventTimestamp
  };
}

/**
 * Retrieves the calculated security statistics backed by the history store.
 */
export async function getSecurityStatistics(): Promise<SecurityStatistics> {
  try {
    const events = await getAll();
    return calculateStatistics(events);
  } catch (err) {
    // Failsafe if storage completely breaks - statistics are auxiliary
    console.error("[VerifyFirst] Failed to get security statistics", err);
    return calculateStatistics([]);
  }
}
