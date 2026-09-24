/**
 * Extracts only the hostname from a URL.
 * Intentionally discards protocol, path, query parameters, fragment, and user info
 * to prevent sensitive information from being persisted in the security history.
 */
export function sanitizeUrlToHostname(url: string): string {
  if (!url || typeof url !== "string") {
    return "";
  }
  
  try {
    let urlObj: URL;
    const trimmed = url.trim();
    if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
      urlObj = new URL(`https://${trimmed}`);
    } else {
      urlObj = new URL(trimmed);
    }
    return urlObj.hostname;
  } catch (error) {
    return "";
  }
}
