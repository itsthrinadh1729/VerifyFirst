export interface SecurityEventReason {
  rule: string;
  message: string;
}

export interface SecurityEventThreatContext {
  title: string;
  summary: string;
  technicalDetails: string[];
  userImpact: string;
  recommendedAction: string;
}

export interface SecurityEvent {
  id: string;
  timestamp: number;

  hostname: string;

  status: "SAFE" | "SUSPICIOUS" | "DANGEROUS";

  riskScore: number | null;

  protectionAction: "ALLOW" | "WARN" | "BLOCK";

  threatCategories: string[];
  patterns: string[];

  reasons: SecurityEventReason[];

  threatContext?: SecurityEventThreatContext;
}

export interface SecurityStatistics {
  totalEvents: number;

  safeCount: number;
  suspiciousCount: number;
  dangerousCount: number;

  allowedCount: number;
  warnedCount: number;
  blockedCount: number;

  uniqueHostnames: number;

  averageRiskScore: number | null;
  highestRiskScore: number | null;

  lastEventTimestamp: string | null;
}

export interface SecurityHistoryQuery {
  status?: SecurityEvent["status"];
  protectionAction?: SecurityEvent["protectionAction"];
  hostname?: string;

  fromTimestamp?: string;
  toTimestamp?: string;

  minRiskScore?: number;
  maxRiskScore?: number;

  sort?: "newest" | "oldest";

  limit?: number;
  offset?: number;
}

export type TelemetryResponse<T> = 
  | { success: true; data: T; }
  | { success: false; error: string; };
