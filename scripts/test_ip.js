const rawUrl = "http://192.168.1.1/admin";
const URL_TEXT_PATTERN = /https?:\/\/[^\s<>"'\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF\u00A0]+/gi;

const WHATSAPP_INTERNAL_DOMAINS = [
    "whatsapp.com",
    "web.whatsapp.com",
    "faq.whatsapp.com",
    "api.whatsapp.com",
    "v.whatsapp.net",
    "wa.me",
    "whatsapp.net",
    "dyn.web.whatsapp.com",
];

function isCandidateUrl(rawUrl) {
    if (!rawUrl || typeof rawUrl !== "string") {
      return false;
    }

    const trimmed = rawUrl.trim();
    if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
      return false;
    }

    if (trimmed.length > 2048) {
      return false;
    }

    try {
      const parsed = new URL(trimmed);
      const hostname = parsed.hostname.toLowerCase();

      // Check if it's a valid external domain (must have at least one dot, no spaces)
      if (!hostname.includes(".") || hostname.startsWith(".") || hostname.endsWith(".")) {
          return false;
      }

      // Filter out internal WhatsApp domains
      for (const domain of WHATSAPP_INTERNAL_DOMAINS) {
        if (hostname === domain || hostname.endsWith("." + domain)) {
          return false;
        }
      }

      return true;
    } catch {
      return false;
    }
}

console.log(isCandidateUrl(rawUrl));
