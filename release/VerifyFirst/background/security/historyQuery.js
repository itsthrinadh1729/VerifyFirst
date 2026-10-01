import { getAll } from "./historyStore.js";
/**
 * Queries the security history based on the provided filters.
 * Returns a new, independent array of SecurityEvents to prevent mutation.
 */
export async function querySecurityHistory(query) {
    try {
        const allEvents = await getAll();
        if (!query) {
            // Default behavior: sort newest first, no filters
            return [...allEvents].reverse();
        }
        // 1. Filter
        const filtered = allEvents.filter(event => {
            // Status
            if (query.status && event.status !== query.status)
                return false;
            // Protection action
            if (query.protectionAction && event.protectionAction !== query.protectionAction)
                return false;
            // Hostname (exact match, consistent with stored sanitized data)
            if (query.hostname && event.hostname !== query.hostname)
                return false;
            // Date/time filtering
            if (query.fromTimestamp) {
                const fromMs = new Date(query.fromTimestamp).getTime();
                if (!isNaN(fromMs) && event.timestamp < fromMs)
                    return false;
            }
            if (query.toTimestamp) {
                const toMs = new Date(query.toTimestamp).getTime();
                if (!isNaN(toMs) && event.timestamp > toMs)
                    return false;
            }
            // Risk score filtering
            if (query.minRiskScore !== undefined) {
                if (event.riskScore === null || event.riskScore < query.minRiskScore)
                    return false;
            }
            if (query.maxRiskScore !== undefined) {
                if (event.riskScore === null || event.riskScore > query.maxRiskScore)
                    return false;
            }
            return true;
        });
        // 2. Sort
        // allEvents are returned oldest to newest natively.
        if (query.sort === "oldest") {
            // already oldest-first, do nothing since filter retains order
        }
        else {
            // Default to "newest"
            filtered.reverse();
        }
        // 3. Pagination
        let offset = 0;
        if (query.offset !== undefined && query.offset > 0) {
            offset = query.offset;
        }
        let limit = filtered.length;
        if (query.limit !== undefined) {
            if (query.limit <= 0)
                return [];
            limit = query.limit;
        }
        // slice returns a new array
        if (offset > 0 || limit < filtered.length) {
            return filtered.slice(offset, offset + limit);
        }
        return filtered;
    }
    catch (err) {
        console.error("[VerifyFirst] Failed to query security history:", err);
        return [];
    }
}
