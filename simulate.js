const { JSDOM } = require('jsdom');
const dom = new JSDOM(`<body><div data-testid='conversation-panel-body'><div role='row'><span dir='ltr'>http://192.168.1.1/admin</span></div></div></body>`);
global.document = dom.window.document;
global.NodeFilter = dom.window.NodeFilter;

const URL_TEXT_PATTERN = /https?:\/\/[^\s<>"'\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF\u00A0]+/gi;
const WHATSAPP_INTERNAL_DOMAINS = ['whatsapp.com', 'web.whatsapp.com', 'faq.whatsapp.com', 'api.whatsapp.com', 'v.whatsapp.net', 'wa.me', 'whatsapp.net', 'dyn.web.whatsapp.com'];

function isCandidateUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') return false;
  const trimmed = rawUrl.trim();
  if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) return false;
  if (trimmed.length > 2048) return false;
  try {
    const parsed = new URL(trimmed);
    const hostname = parsed.hostname.toLowerCase();
    for (const domain of WHATSAPP_INTERNAL_DOMAINS) {
      if (hostname === domain || hostname.endsWith('.' + domain)) return false;
    }
    return true;
  } catch {
    return false;
  }
}

function cleanUrlString(raw) {
  let urlStr = raw.replace(/[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF\u00A0]/g, '');
  urlStr = urlStr.replace(/^[)\](]+/, '');
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

function discoverUrlsInContainer(chatContainer) {
  const found = [];
  const seen = new Set();
  const rejectedAnchors = new Set();
  const messageArea = chatContainer.querySelector('[data-testid="conversation-panel-body"]') || chatContainer.querySelector('[role="application"]') || chatContainer;
  const anchors = messageArea.querySelectorAll('a[href]');
  anchors.forEach((el) => {
    let href = el.getAttribute('href') || '';
    const canonicalUrl = processExtractedString(href);
    if (canonicalUrl) {
      if (!seen.has(canonicalUrl)) {
        seen.add(canonicalUrl);
        found.push(canonicalUrl);
      }
    } else {
      rejectedAnchors.add(el);
    }
  });

  const treeWalker = document.createTreeWalker(messageArea, NodeFilter.SHOW_TEXT, {
    acceptNode: (node) => {
      const text = node.nodeValue || '';
      if (!text.includes('http://') && !text.includes('https://')) return NodeFilter.FILTER_REJECT;
      const parent = node.parentElement;
      if (!parent) return NodeFilter.FILTER_REJECT;
      const closestAnchor = parent.closest('a[href]');
      if (closestAnchor && !rejectedAnchors.has(closestAnchor)) {
        return NodeFilter.FILTER_REJECT;
      }
      if (parent.closest('header, footer, button, [role="menuitem"], script, style, noscript, [hidden], [aria-hidden="true"]')) {
        return NodeFilter.FILTER_REJECT;
      }
      return NodeFilter.FILTER_ACCEPT;
    }
  });

  let currentNode;
  while ((currentNode = treeWalker.nextNode())) {
    const text = currentNode.nodeValue || '';
    URL_TEXT_PATTERN.lastIndex = 0;
    let match;
    while ((match = URL_TEXT_PATTERN.exec(text)) !== null) {
      const spaced = match[0].replace(/([)\](]+)(https?:\/\/)/gi, '$1 $2');
      const pieces = spaced.split(' ');
      for (let piece of pieces) {
        const canonicalUrl = processExtractedString(piece);
        if (canonicalUrl) {
          if (!seen.has(canonicalUrl)) {
            seen.add(canonicalUrl);
            found.push(canonicalUrl);
          }
        }
      }
    }
  }
  return found;
}

console.log("Found:", discoverUrlsInContainer(document.body));
