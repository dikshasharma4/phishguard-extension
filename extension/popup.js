// popup.js — PhishGuard extension UI logic

const COLORS = {
  safe:    { hex: '#3fb950', bg: 'rgba(63,185,80,.15)',   badge: '#0d2810', label: 'Safe',       sub: 'This site appears safe' },
  warn:    { hex: '#e3b341', bg: 'rgba(210,153,34,.12)',  badge: '#2d1f00', label: 'Suspicious', sub: 'Proceed with caution'   },
  danger:  { hex: '#f85149', bg: 'rgba(248,81,73,.15)',   badge: '#2d0a09', label: 'Dangerous',  sub: 'Likely a phishing site' },
};

function getLevel(score) {
  if (score <= 30) return 'safe';
  if (score <= 65) return 'warn';
  return 'danger';
}

function renderScore(score, url, flags, info) {
  document.getElementById('loading-state').style.display = 'none';
  document.getElementById('results-state').style.display = 'block';

  const level = getLevel(score);
  const c = COLORS[level];

  // Header badge
  const badge = document.getElementById('header-badge');
  badge.textContent = c.label;
  badge.style.background = c.bg;
  badge.style.color = c.hex;

  // Logo icon background
  document.getElementById('logo-icon').style.background = c.bg;

  // Score ring animation
  const ring = document.getElementById('ring-fill');
  ring.style.stroke = c.hex;
  const circumference = 251.2;
  const offset = circumference - (score / 100) * circumference;
  setTimeout(() => { ring.style.strokeDashoffset = offset; }, 100);

  // Score number
  let cur = 0;
  const target = score;
  const el = document.getElementById('score-num');
  el.style.color = c.hex;
  const counter = setInterval(() => {
    cur = Math.min(cur + 3, target);
    el.textContent = cur;
    if (cur >= target) clearInterval(counter);
  }, 20);

  // Labels
  document.getElementById('score-label').textContent = c.label;
  document.getElementById('score-label').style.color = c.hex;
  document.getElementById('score-sub').textContent = c.sub;

  // Risk bar
  const bar = document.getElementById('risk-bar');
  bar.style.background = c.hex;
  setTimeout(() => { bar.style.width = score + '%'; }, 50);

  // Alert banner
  const banner = document.getElementById('alert-banner');
  if (level === 'danger') {
    banner.className = 'alert-banner show alert-danger';
    document.getElementById('alert-text').textContent = 'High phishing risk! Avoid entering any personal data.';
  } else if (level === 'warn') {
    banner.className = 'alert-banner show alert-warn';
    document.getElementById('alert-text').textContent = 'Suspicious patterns detected. Be careful.';
  }

  // Flags
  const flagsList = document.getElementById('flags-list');
  if (flags && flags.length > 0) {
    flagsList.innerHTML = flags.map(f => `
      <div class="flag-item ${f.type}">
        <div class="flag-dot"></div>
        <span>${f.msg}</span>
      </div>
    `).join('');
  } else {
    flagsList.innerHTML = `<div class="flag-item good"><div class="flag-dot"></div><span>No suspicious patterns found</span></div>`;
  }

  // Info tab
  const infoEl = document.getElementById('info-list');
  if (info) {
    infoEl.innerHTML = Object.entries(info).map(([k, v]) => `
      <div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid #21262d;font-size:12px">
        <span style="color:#7d8590">${k}</span>
        <span style="color:#c9d1d9;font-weight:500;text-align:right;max-width:180px;word-break:break-all">${v}</span>
      </div>
    `).join('');
  }
}

function renderHistory() {
  chrome.storage.local.get(['history'], (result) => {
    const history = result.history || [];
    const el = document.getElementById('history-list');
    if (history.length === 0) {
      el.innerHTML = '<div class="empty-history">No sites scanned yet</div>';
      return;
    }
    el.innerHTML = history.slice(0, 15).map(item => {
      const level = getLevel(item.score);
      const cls = level === 'safe' ? 'hs-safe' : level === 'warn' ? 'hs-warn' : 'hs-danger';
      const shortUrl = item.url.replace(/^https?:\/\//, '').slice(0, 35);
      return `
        <div class="history-item">
          <div class="history-url" title="${item.url}">${shortUrl}</div>
          <div class="history-score ${cls}">${item.score}</div>
        </div>
      `;
    }).join('');
  });
}

function switchTab(tabId, el) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  el.classList.add('active');
  document.getElementById('tab-' + tabId).classList.add('active');
  if (tabId === 'history') renderHistory();
}

function rescan() {
  document.getElementById('loading-state').style.display = 'flex';
  document.getElementById('results-state').style.display = 'none';
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]) {
      chrome.runtime.sendMessage({ type: 'SCAN_URL', url: tabs[0].url }, handleResult);
    }
  });
}

function handleResult(result) {
  if (!result) return;
  renderScore(result.score, result.url, result.flags, result.info);

  // Update scan count
  chrome.storage.local.get(['scanCount'], (data) => {
    const count = (data.scanCount || 0) + 1;
    chrome.storage.local.set({ scanCount: count });
    document.getElementById('scan-count').textContent = count;
  });
}

// Init
document.addEventListener('DOMContentLoaded', () => {
  chrome.storage.local.get(['scanCount'], (data) => {
    document.getElementById('scan-count').textContent = data.scanCount || 0;
  });

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs[0]) return;
    const url = tabs[0].url;
    document.getElementById('current-url').textContent = url;

    // Check cache first
    chrome.storage.local.get(['lastResult'], (data) => {
      if (data.lastResult && data.lastResult.url === url) {
        handleResult(data.lastResult);
      } else {
        chrome.runtime.sendMessage({ type: 'SCAN_URL', url }, handleResult);
      }
    });
  });
});
