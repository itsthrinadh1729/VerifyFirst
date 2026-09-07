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

  function cleanUrlString(raw) {
    // 1. Remove invisible Unicode formatting characters (defense-in-depth)
    let urlStr = raw.replace(/[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF\u00A0]/g, "");
    
    // 2. Remove leading/trailing parenthesis
    urlStr = urlStr.replace(/^[)\](]+/, "");
    
    while (/[.,;:!?\)\]\(\[]+$/.test(urlStr)) {
      const lastChar = urlStr.slice(-1);
      if (lastChar === ')') {
        const openCount = (urlStr.match(/\(/g) || []).length;
        const closeCount = (urlStr.match(/\)/g) || []).length;
        if (openCount >= closeCount) break; 
      } else if (lastChar === ']') {
        const openCount = (urlStr.match(/\[/g) || []).length;
        const closeCount = (urlStr.match(/\]/g) || []).length;
        if (openCount >= closeCount) break; 
      }
      urlStr = urlStr.slice(0, -1);
    }
    return urlStr;
  }

  function processExtractedString(rawStr) {
    const cleaned = cleanUrlString(rawStr);
    if (isCandidateUrl(cleaned)) {
      try {
        return new URL(cleaned).href;
      } catch {
        return null;
      }
    }
    return null;
  }

  const URL_TEXT_PATTERN = /https?:\/\/[^\s<>"'\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF\u00A0]+/gi;
  const text = "http://192.168.1.1/admin";
  let match;
  while ((match = URL_TEXT_PATTERN.exec(text)) !== null) {
      console.log("Match:", match[0]);
      console.log("Processed:", processExtractedString(match[0]));
  }
