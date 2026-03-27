// background.js — PhishGuard service worker
// Handles URL scanning, scoring, and icon updates

// ─── Phishing Detection Engine ───────────────────────────────────────────────

const SUSPICIOUS_TLDS = [
  '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click',
  '.link', '.work', '.party', '.review', '.trade', '.date', '.racing'
];

const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm',
  'banking', 'paypal', 'password', 'credential', 'wallet', 'support',
  'helpdesk', 'suspended', 'unusual', 'alert', 'notification'
];

const TRUSTED_DOMAINS = [
  'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
  'linkedin.com', 'github.com', 'microsoft.com', 'apple.com', 'amazon.com',
  'netflix.com', 'wikipedia.org', 'reddit.com', 'stackoverflow.com',
  'cloudflare.com', 'mozilla.org', 'w3.org', 'openai.com'
];

const KNOWN_PHISHING_PATTERNS = [
  /paypa[l1]-/i, /g[o0]{2}gle/i, /arnazon|amaz[o0]n/i, /micr[o0]s[o0]ft/i,
  /app[l1]e-/i, /faceb[o0]{2}k/i, /netfl[i1]x/i, /[a-z]+-secure-/i,
  /verify-account/i, /confirm-identity/i, /update-billing/i,
];

function parseURL(url) {
  try {
    const u = new URL(url);
    return {
      protocol: u.protocol,
      hostname: u.hostname,
      pathname: u.pathname,
      search: u.search,
      port: u.port,
      full: url,
    };
  } catch {
    return null;
  }
}

function getRootDomain(hostname) {
  const parts = hostname.split('.');
  if (parts.length >= 2) return parts.slice(-2).join('.');
  return hostname;
}

function analyzeURL(url) {
  const parsed = parseURL(url);
  if (!parsed) return { score: 0, flags: [], info: {} };

  const { protocol, hostname, pathname, search } = parsed;
  const rootDomain = getRootDomain(hostname);
  const fullPath = pathname + search;

  let score = 0;
  const flags = [];
  const goodFlags = [];

  // ── Check 1: HTTPS ──────────────────────────────────────
  if (protocol === 'http:') {
    score += 20;
    flags.push({ type: 'bad', msg: 'No HTTPS — connection is unencrypted' });
  } else {
    goodFlags.push({ type: 'good', msg: 'HTTPS encryption is active' });
  }

  // ── Check 2: Trusted domain ──────────────────────────────
  const isTrusted = TRUSTED_DOMAINS.some(d => rootDomain === d || hostname.endsWith('.' + d));
  if (isTrusted) {
    goodFlags.push({ type: 'good', msg: 'Known trusted domain' });
    // Trusted domains get a big score reduction
    score = Math.max(0, score - 30);
  }

  // ── Check 3: Suspicious TLD ──────────────────────────────
  const hasSuspTLD = SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld));
  if (hasSuspTLD) {
    const tld = SUSPICIOUS_TLDS.find(t => hostname.endsWith(t));
    score += 25;
    flags.push({ type: 'bad', msg: `Suspicious TLD detected: ${tld}` });
  }

  // ── Check 4: IP address as hostname ──────────────────────
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    score += 30;
    flags.push({ type: 'bad', msg: 'IP address used instead of domain name' });
  }

  // ── Check 5: Very long URL ──────────────────────────────
  if (url.length > 100) {
    score += 10;
    flags.push({ type: 'warn', msg: `Unusually long URL (${url.length} chars)` });
  }
  if (url.length > 200) {
    score += 10;
    flags.push({ type: 'bad', msg: 'Extremely long URL — common phishing trick' });
  }

  // ── Check 6: Too many subdomains ──────────────────────────
  const subdomains = hostname.split('.').length - 2;
  if (subdomains >= 3) {
    score += 15;
    flags.push({ type: 'bad', msg: `Too many subdomains (${subdomains}) — suspicious structure` });
  } else if (subdomains === 2) {
    score += 5;
    flags.push({ type: 'warn', msg: 'Multiple subdomains detected' });
  }

  // ── Check 7: Known phishing patterns ──────────────────────
  const matchedPattern = KNOWN_PHISHING_PATTERNS.find(p => p.test(hostname + fullPath));
  if (matchedPattern) {
    score += 35;
    flags.push({ type: 'bad', msg: 'Brand impersonation pattern detected in URL' });
  }

  // ── Check 8: Suspicious keywords in domain ─────────────────
  const suspKw = SUSPICIOUS_KEYWORDS.filter(kw => hostname.toLowerCase().includes(kw));
  if (suspKw.length > 0) {
    score += Math.min(suspKw.length * 8, 24);
    flags.push({ type: 'warn', msg: `Sensitive keywords in domain: ${suspKw.slice(0, 3).join(', ')}` });
  }

  // ── Check 9: Hyphens in domain ──────────────────────────
  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    score += 15;
    flags.push({ type: 'bad', msg: `Many hyphens in domain (${hyphenCount}) — typosquatting signal` });
  } else if (hyphenCount >= 1) {
    score += 5;
    flags.push({ type: 'warn', msg: 'Hyphens in domain name' });
  }

  // ── Check 10: Numbers in domain ──────────────────────────
  const numMatches = hostname.match(/\d+/g);
  if (numMatches && numMatches.join('').length > 3) {
    score += 10;
    flags.push({ type: 'warn', msg: 'Unusual numbers in domain name' });
  }

  // ── Check 11: @ symbol in URL ──────────────────────────
  if (url.includes('@')) {
    score += 25;
    flags.push({ type: 'bad', msg: '@ symbol in URL — classic phishing redirect trick' });
  }

  // ── Check 12: Double slash redirect ──────────────────────
  if (pathname.includes('//')) {
    score += 20;
    flags.push({ type: 'bad', msg: 'Double slash in path — possible redirect manipulation' });
  }

  // ── Check 13: Punycode / unicode domain ─────────────────
  if (hostname.startsWith('xn--')) {
    score += 20;
    flags.push({ type: 'bad', msg: 'Internationalized domain — possible homograph attack' });
  }

  // ── Check 14: Non-standard port ──────────────────────────
  if (parsed.port && !['80', '443', ''].includes(parsed.port)) {
    score += 15;
    flags.push({ type: 'warn', msg: `Non-standard port: ${parsed.port}` });
  }

  // ── Check 15: Path has sensitive words ───────────────────
  const pathKw = ['verify', 'secure', 'update', 'confirm', 'login', 'signin'];
  const pathMatches = pathKw.filter(k => pathname.toLowerCase().includes(k));
  if (pathMatches.length >= 2) {
    score += 12;
    flags.push({ type: 'warn', msg: `Sensitive words in path: ${pathMatches.join(', ')}` });
  }

  // Cap at 100
  score = Math.min(100, Math.max(0, score));

  // Combine good + bad flags (bad first)
  const allFlags = [...flags, ...goodFlags];

  // Build info object
  const info = {
    'Domain':    hostname,
    'Protocol':  protocol,
    'Root Domain': rootDomain,
    'Path':      pathname || '/',
    'URL Length': url.length + ' chars',
    'Subdomains': subdomains,
    'Risk Score': score + ' / 100',
    'Status':    score <= 30 ? 'Safe' : score <= 65 ? 'Suspicious' : 'Dangerous',
  };

  return { score, flags: allFlags, info, url };
}

// ─── Try Python backend first, fallback to local analysis ─────────────────

async function scanURL(url) {
  // Try calling local Python ML backend
  try {
    const resp = await fetch('http://localhost:5000/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(2000),  // 2s timeout
    });
    if (resp.ok) {
      const data = await resp.json();
      // Merge ML score with local analysis flags
      const local = analyzeURL(url);
      data.flags = [...(data.flags || []), ...local.flags];
      data.info = { ...local.info, 'ML Score': data.ml_score || 'N/A', ...data.info };
      return data;
    }
  } catch {
    // Backend not running — use local analysis only
  }

  // Fallback: local heuristic analysis
  return analyzeURL(url);
}

// ─── Update browser icon based on risk ───────────────────────────────────────

function updateIcon(tabId, score) {
  let color, text;
  if (score <= 30)      { color = '#3fb950'; text = 'OK'; }
  else if (score <= 65) { color = '#e3b341'; text = '!';  }
  else                  { color = '#f85149'; text = '!!'; }

  chrome.action.setBadgeText({ text, tabId });
  chrome.action.setBadgeBackgroundColor({ color, tabId });
}

// ─── Save to history ─────────────────────────────────────────────────────────

function saveToHistory(result) {
  chrome.storage.local.get(['history'], (data) => {
    const history = data.history || [];
    // Avoid duplicates
    const filtered = history.filter(h => h.url !== result.url);
    filtered.unshift({ url: result.url, score: result.score, time: Date.now() });
    // Keep only last 50
    chrome.storage.local.set({ history: filtered.slice(0, 50) });
  });
}

// ─── Message listener ────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'SCAN_URL') {
    scanURL(msg.url).then(result => {
      // Cache result
      chrome.storage.local.set({ lastResult: result });
      saveToHistory(result);

      // Update icon on active tab
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]) updateIcon(tabs[0].id, result.score);
      });

      sendResponse(result);
    });
    return true; // Keep channel open for async response
  }
});

// ─── Auto-scan on tab update ──────────────────────────────────────────────────

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
    scanURL(tab.url).then(result => {
      chrome.storage.local.set({ lastResult: result });
      saveToHistory(result);
      updateIcon(tabId, result.score);
     chrome.tabs.sendMessage(tabId, {
    type: "SHOW_RESULT",
    score: result.score
});

      // Inject warning for very high-risk sites
      if (result.score >= 80) {
        chrome.tabs.sendMessage(tabId, {
          type: 'HIGH_RISK',
          score: result.score,
          url: tab.url,
        }).catch(() => {}); // ignore if content script not ready
      }
    });
  }
});
// Auto scan when page fully loads
chrome.webNavigation.onCompleted.addListener((details) => {
    if (details.frameId === 0) {
        console.log("Page loaded:", details.url);

        // call your existing scan function
        if (typeof scanURL === "function") {
            scanURL(details.url);
        }
    }
});

// Extra fallback (tab update)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab.url) {
        console.log("Tab updated:", tab.url);

        if (typeof scanURL === "function") {
            scanURL(tab.url);
        }
    }
});
