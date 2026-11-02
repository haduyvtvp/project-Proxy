/**
 * Secure Proxy Admin — app.js
 * Vanilla JS SPA — No frameworks
 */

'use strict';

/* ========================================================
   CONFIG
   ======================================================== */
const API_BASE = '/api';

/* ========================================================
   UTILITIES
   ======================================================== */

function $(sel, ctx = document) { return ctx.querySelector(sel); }
function $$(sel, ctx = document) { return [...ctx.querySelectorAll(sel)]; }

function showToast(msg, type = 'info', duration = 3500) {
  const container = $('#toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = msg;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.animation = 'fadeOut .3s ease forwards';
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

async function apiFetch(path, options = {}) {
  const res = await fetch(API_BASE + path, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options
  });
  if (!res.ok) {
    let detail = `${res.status}: ${res.statusText}`;
    try {
      const body = await res.json();
      if (body.message) detail = body.message;
    } catch { /* use HTTP status when the response is not JSON */ }
    throw new Error(detail);
  }
  const ct = res.headers.get('Content-Type') || '';
  if (ct.includes('application/json')) return res.json();
  return res.text();
}

function escHtml(str) {
  if (!str) return '';
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function resultBadge(result) {
  const r = (result || '').toUpperCase();
  const cls = r === 'ALLOWED' ? 'badge-allowed' : r === 'BLOCKED' ? 'badge-blocked' : 'badge-error';
  return `<span class="badge ${cls}">${escHtml(result)}</span>`;
}

/* ========================================================
   NAVIGATION / TABS
   ======================================================== */

function initNavigation() {
  $$('.nav-item').forEach(item => {
    item.addEventListener('click', e => {
      e.preventDefault();
      const tab = item.dataset.tab;
      switchTab(tab);
      // Close sidebar on mobile
      if (window.innerWidth <= 768) {
        $('#sidebar').classList.remove('open');
      }
    });
  });

  // Mobile menu button
  $('#menu-btn').addEventListener('click', () => {
    $('#sidebar').classList.toggle('open');
  });

  // Close sidebar on outside click (mobile)
  document.addEventListener('click', e => {
    const sidebar = $('#sidebar');
    const menuBtn = $('#menu-btn');
    if (window.innerWidth <= 768 && sidebar.classList.contains('open')
        && !sidebar.contains(e.target) && !menuBtn.contains(e.target)) {
      sidebar.classList.remove('open');
    }
  });
}

function switchTab(tabName) {
  // Update nav items
  $$('.nav-item').forEach(item => {
    item.classList.toggle('active', item.dataset.tab === tabName);
  });
  // Update panes
  $$('.tab-pane').forEach(pane => {
    pane.classList.toggle('active', pane.id === `tab-${tabName}`);
  });
  // Load data for tab
  if (tabName === 'dashboard') {
    loadMonitoring();
    startWebSocket();
  }
  if (tabName === 'logs') initLogs();
  if (tabName === 'policy') loadPolicy();
  if (tabName === 'blocklist') loadBlocklist();
}

/* ========================================================
   PROXY STATUS
   ======================================================== */

async function checkProxyStatus() {
  const dot = $('#proxy-status-dot');
  const txt = $('#proxy-status-text');
  try {
    const data = await apiFetch('/status');
    const running = data.status === 'running';
    dot.className = 'status-dot ' + (running ? 'running' : 'stopped');
    txt.textContent = running ? 'Proxy running' : 'Proxy stopped';
  } catch {
    dot.className = 'status-dot stopped';
    txt.textContent = 'API unreachable';
  }
}

/* ========================================================
   DASHBOARD / STATS
   ======================================================== */

function localDateTime(date) {
  const pad = value => String(value).padStart(2, '0');
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Asia/Ho_Chi_Minh',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23'
  }).formatToParts(date).reduce((result, part) => {
    result[part.type] = part.value;
    return result;
  }, {});
  return `${parts.year}-${parts.month}-${parts.day}T${pad(parts.hour)}:${pad(parts.minute)}:${pad(parts.second)}`;
}

function parseWallDateTime(value) {
  return new Date(value.replace(' ', 'T') + 'Z');
}

async function loadMonitoring() {
  try {
    const hours = Number($('#monitoring-range').value || 24);
    const to = new Date();
    const from = new Date(to.getTime() - hours * 60 * 60 * 1000);
    const bucketMinutes = hours <= 1 ? 1 : hours <= 24 ? 15 : 60;
    const query = new URLSearchParams({
      from: localDateTime(from),
      to: localDateTime(to),
      bucketMinutes: String(bucketMinutes)
    });
    const snapshot = await apiFetch('/monitoring?' + query.toString());
    $('#stat-total').textContent = snapshot.total ?? 0;
    $('#stat-allowed').textContent = snapshot.allowed ?? 0;
    $('#stat-blocked').textContent = snapshot.blocked ?? 0;
    $('#stat-error').textContent = snapshot.errors ?? 0;
    const decided = (snapshot.allowed || 0) + (snapshot.blocked || 0);
    $('#allowed-percent').textContent = decided ? `(${Math.round(snapshot.allowed * 100 / decided)}%)` : '(0%)';
    $('#blocked-percent').textContent = decided ? `(${Math.round(snapshot.blocked * 100 / decided)}%)` : '(0%)';
    renderTrafficChart(snapshot.timeline || [], from, to, bucketMinutes);
    renderTrafficRatio(snapshot);
    renderRankedList('#top-domains-container', snapshot.topDomains || [], 'No domains in this period.');
    renderRankedList('#top-clients-container', snapshot.topClients || [], 'No clients in this period.');
    renderLogRows($('#monitoring-log-tbody'), (await apiFetch('/logs?limit=10')).slice().reverse(), false);
  } catch (err) {
    showToast('Failed to load monitoring data: ' + err.message, 'error');
  }
}

function renderTrafficChart(entries, from, to, bucketMinutes) {
  const container = $('#traffic-chart');
  const bucketMs = bucketMinutes * 60_000;
  const firstBucket = Math.floor(parseWallDateTime(localDateTime(from)).getTime() / bucketMs) * bucketMs;
  const lastBucket = Math.floor(parseWallDateTime(localDateTime(to)).getTime() / bucketMs) * bucketMs;
  const points = [];
  const indexed = new Map(entries.map(entry => [
    Math.floor(parseWallDateTime(entry.timestamp).getTime() / bucketMs) * bucketMs,
    entry
  ]));
  for (let at = firstBucket; at <= lastBucket; at += bucketMs) {
    points.push(indexed.get(at) || { total: 0, allowed: 0, blocked: 0 });
  }
  if (points.length < 2) points.unshift({ total: 0, allowed: 0, blocked: 0 });

  const width = 720;
  const height = 220;
  const padX = 38;
  const padY = 18;
  const max = Math.max(1, ...points.map(point => point.total));
  const plotWidth = width - padX * 2;
  const plotHeight = height - padY * 2;
  const pathFor = key => points.map((point, index) => {
    const x = padX + index * plotWidth / Math.max(1, points.length - 1);
    const y = padY + plotHeight - (point[key] / max) * plotHeight;
    return `${index ? 'L' : 'M'}${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  const grid = [0, 0.5, 1].map(fraction => {
    const y = padY + plotHeight * fraction;
    const value = Math.round(max * (1 - fraction));
    return `<line class="traffic-grid-line" x1="${padX}" y1="${y}" x2="${width - padX}" y2="${y}"></line>
      <text class="traffic-axis-label" x="2" y="${y + 4}">${value}</text>`;
  }).join('');
  const labels = [0, Math.floor((points.length - 1) / 2), points.length - 1]
    .filter((index, pos, all) => all.indexOf(index) === pos)
    .map(index => {
      const x = padX + index * plotWidth / Math.max(1, points.length - 1);
      const label = new Date(firstBucket + index * bucketMs).toLocaleTimeString([], {
        timeZone: 'UTC',
        hour: '2-digit', minute: '2-digit'
      });
      return `<text class="traffic-axis-label" text-anchor="middle" x="${x}" y="${height}">${escHtml(label)}</text>`;
    }).join('');

  container.innerHTML = `<svg class="traffic-chart" viewBox="0 0 ${width} ${height}" role="img" aria-label="Requests over time">
    ${grid}${labels}
    <path class="traffic-line-total" d="${pathFor('total')}"></path>
    <path class="traffic-line-allowed" d="${pathFor('allowed')}"></path>
    <path class="traffic-line-blocked" d="${pathFor('blocked')}"></path>
  </svg>
  <div class="traffic-legend">
    <span><i class="legend-total"></i>Total</span>
    <span><i class="legend-allowed"></i>Allowed</span>
    <span><i class="legend-blocked"></i>Blocked</span>
  </div>`;
}

function renderTrafficRatio(snapshot) {
  const container = $('#traffic-ratio');
  const total = (snapshot.allowed || 0) + (snapshot.blocked || 0);
  if (!total) {
    container.innerHTML = '<p class="empty-state">No allowed or blocked requests in this period.</p>';
    return;
  }
  const radius = 65;
  const circumference = 2 * Math.PI * radius;
  const allowedLength = circumference * snapshot.allowed / total;
  const blockedLength = circumference * snapshot.blocked / total;
  container.innerHTML = `<svg class="ratio-chart" viewBox="0 0 180 180" role="img" aria-label="Allowed and blocked request ratio">
    <circle class="ratio-track" cx="90" cy="90" r="${radius}"></circle>
    <circle class="ratio-allowed" cx="90" cy="90" r="${radius}" stroke-dasharray="${allowedLength} ${circumference - allowedLength}"></circle>
    <circle class="ratio-blocked" cx="90" cy="90" r="${radius}" stroke-dasharray="${blockedLength} ${circumference - blockedLength}" stroke-dashoffset="${-allowedLength}"></circle>
    <text class="ratio-total" x="90" y="88">${total}</text>
    <text class="ratio-caption" x="90" y="106">requests</text>
  </svg>
  <div class="ratio-legend">
    <span>Allowed ${Math.round(snapshot.allowed * 100 / total)}%</span>
    <span>Blocked ${Math.round(snapshot.blocked * 100 / total)}%</span>
  </div>`;
}

function renderRankedList(selector, entries, emptyMessage) {
  const container = $(selector);
  if (!entries.length) {
    container.innerHTML = `<p class="empty-state">${escHtml(emptyMessage)}</p>`;
    return;
  }
  const maxCount = Math.max(1, entries[0].count);
  container.innerHTML = `<ul class="ranked-list">${entries.map(entry => `
    <li class="ranked-item">
      <span class="ranked-name" title="${escHtml(entry.value)}">${escHtml(entry.value)}</span>
      <span class="ranked-count">${entry.count}</span>
      <span class="ranked-bar"><span style="width:${Math.round(entry.count * 100 / maxCount)}%"></span></span>
    </li>`).join('')}</ul>`;
}

$('#refresh-stats-btn')?.addEventListener('click', loadMonitoring);
$('#monitoring-range')?.addEventListener('change', loadMonitoring);

/* ========================================================
   ACCESS LOGS
   ======================================================== */

let logSocket = null;
let wsReconnectTimer = null;
let logsInitialized = false;
let monitoringRefreshTimer = null;
let logRefreshTimer = null;

function initLogs() {
  if (logsInitialized) return;
  logsInitialized = true;
  initializeLogFilters();
  fetchRecentLogs();
  startWebSocket();
}

async function fetchRecentLogs() {
  logPage = 0;
  await loadFilteredLogs();
}

function initializeLogFilters() {
  const to = new Date();
  const from = new Date(to.getTime() - 24 * 60 * 60 * 1000);
  $('#log-filter-from').value = localDateTime(from).slice(0, 16);
  $('#log-filter-to').value = localDateTime(to).slice(0, 16);
}

let logPage = 0;
const LOG_PAGE_SIZE = 50;

async function loadFilteredLogs() {
  try {
    const query = new URLSearchParams({
      page: String(logPage),
      size: String(LOG_PAGE_SIZE),
      client: $('#log-filter-client').value.trim(),
      host: $('#log-filter-host').value.trim()
    });
    const from = $('#log-filter-from').value;
    const to = $('#log-filter-to').value;
    if (from) query.set('from', from + ':00');
    if (to) query.set('to', to + ':00');
    const result = await apiFetch('/logs/search?' + query.toString());
    renderLogRows($('#log-tbody'), result.entries, false);
    const start = result.total ? result.page * result.size + 1 : 0;
    const end = Math.min((result.page + 1) * result.size, result.total);
    $('#log-page-info').textContent = `${start}-${end} of ${result.total}`;
    $('#log-page-prev').disabled = result.page === 0;
    $('#log-page-next').disabled = end >= result.total;
    if (result.entries.length) {
      $('#log-table-wrapper').scrollTop = 0;
    }
  } catch (err) {
    showToast('Failed to search logs: ' + err.message, 'error');
  }
}

function startWebSocket() {
  if (logSocket && (logSocket.readyState === WebSocket.CONNECTING
      || logSocket.readyState === WebSocket.OPEN)) {
    return;
  }

  const wsUrl = new URL('/ws/logs', window.location.href);
  wsUrl.protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  logSocket = new WebSocket(wsUrl);

  logSocket.onmessage = event => {
    try {
      const entry = JSON.parse(event.data);
      if ($('#tab-logs')?.classList.contains('active')) {
        scheduleLogRefresh();
      }
      if ($('#tab-dashboard')?.classList.contains('active')) {
        scheduleMonitoringRefresh();
      }
    } catch (err) {
      console.error('Failed to parse WebSocket log message:', err);
    }
  };

  logSocket.onopen = () => {
    setWebSocketStatus(true);
  };

  logSocket.onclose = () => {
    setWebSocketStatus(false);
    if (logsInitialized && !wsReconnectTimer) {
      wsReconnectTimer = setTimeout(() => {
        wsReconnectTimer = null;
        if (logsInitialized) startWebSocket();
      }, 5000);
    }
  };

  logSocket.onerror = () => {
    logSocket.close();
  };
}

function setWebSocketStatus(connected) {
  $$('.ws-badge').forEach(badge => {
    badge.textContent = connected ? '● Live' : '○ Disconnected';
    badge.className = connected ? 'badge badge-ws ws-badge' : 'badge badge-ws ws-badge disconnected';
  });
}

function scheduleMonitoringRefresh() {
  if (monitoringRefreshTimer) return;
  monitoringRefreshTimer = setTimeout(() => {
    monitoringRefreshTimer = null;
    if ($('#tab-dashboard')?.classList.contains('active')) loadMonitoring();
  }, 1000);
}

function scheduleLogRefresh() {
  if (logRefreshTimer) return;
  logRefreshTimer = setTimeout(() => {
    logRefreshTimer = null;
    if ($('#tab-logs')?.classList.contains('active')) loadFilteredLogs();
  }, 500);
}

const MAX_LOG_ROWS = 500;

function appendLogRow(entry, isNew) {
  const tbody = $('#log-tbody');
  appendLogRowTo(tbody, entry, isNew);
}

function appendLogRowTo(tbody, entry, isNew) {
  // Remove empty state row if present
  const emptyRow = tbody.querySelector('.empty-state');
  if (emptyRow) emptyRow.closest('tr')?.remove();

  const tr = document.createElement('tr');
  if (isNew) tr.classList.add('new-row');

  tr.innerHTML = `
    <td>${escHtml(entry.timestamp || '')}</td>
    <td>${escHtml(entry.client   || '')}</td>
    <td title="${escHtml(entry.host || '')}">${escHtml(entry.host || '')}</td>
    <td><code>${escHtml(entry.method || '')}</code></td>
    <td>${resultBadge(entry.result)}</td>
  `;

  tbody.appendChild(tr);

  // Enforce max rows
  while (tbody.rows.length > MAX_LOG_ROWS) {
    tbody.deleteRow(0);
  }

  // Auto-scroll
  if ($('#auto-scroll-toggle')?.checked) scrollToBottom();
}

function renderLogRows(tbody, entries, highlightLast) {
  tbody.innerHTML = '';
  if (!entries.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No matching logs.</td></tr>';
    return;
  }
  entries.forEach((entry, index) => appendLogRowTo(tbody, entry, highlightLast && index === entries.length - 1));
}

function scrollToBottom() {
  const wrapper = $('#log-table-wrapper');
  if (wrapper) wrapper.scrollTop = wrapper.scrollHeight;
}

$('#clear-logs-btn')?.addEventListener('click', () => {
  const tbody = $('#log-tbody');
  tbody.innerHTML = '<tr><td colspan="5" class="empty-state">Logs cleared (display only).</td></tr>';
});

$('#log-filter-form')?.addEventListener('submit', event => {
  event.preventDefault();
  logPage = 0;
  loadFilteredLogs();
});

$('#reset-log-filter')?.addEventListener('click', () => {
  $('#log-filter-client').value = '';
  $('#log-filter-host').value = '';
  initializeLogFilters();
  logPage = 0;
  loadFilteredLogs();
});

$('#log-page-prev')?.addEventListener('click', () => {
  if (logPage > 0) {
    logPage--;
    loadFilteredLogs();
  }
});

$('#log-page-next')?.addEventListener('click', () => {
  logPage++;
  loadFilteredLogs();
});

$$('#log-filter-client, #log-filter-host').forEach(input => {
  input.addEventListener('input', () => {
    if (input.searchTimer) clearTimeout(input.searchTimer);
    input.searchTimer = setTimeout(() => {
      logPage = 0;
      loadFilteredLogs();
    }, 350);
  });
});

$$('[data-open-logs]').forEach(button => {
  button.addEventListener('click', () => switchTab('logs'));
});

/* ========================================================
   SMART POLICIES
   ======================================================== */

let policyConfig = null;

async function loadPolicy() {
  try {
    policyConfig = await apiFetch('/policy');
    $('#policy-mode').value = policyConfig.mode || 'BLOCKLIST';
    $('#policy-timezone').value = policyConfig.timezone || 'Asia/Ho_Chi_Minh';
    $('#policy-allow').value = (policyConfig.allow || []).join('\n');
    renderPolicyCategories();
    setPolicyMessage('');
  } catch (err) {
    setPolicyMessage('Failed to load policies: ' + err.message, true);
  }
}

function scheduleToText(schedules) {
  return (schedules || []).map(schedule => {
    const days = schedule.days?.length ? schedule.days.join(',') : '*';
    const from = schedule.from || '00:00';
    const to = schedule.to || '00:00';
    return `${days} ${from}-${to}`;
  }).join('\n');
}

function renderPolicyCategories() {
  const container = $('#policy-categories');
  const categories = policyConfig?.categories || [];
  if (!categories.length) {
    container.innerHTML = '<div class="card"><p class="empty-state">No categories. Add one to create scheduled or pattern-based rules.</p></div>';
    return;
  }

  container.innerHTML = categories.map((category, index) => `
    <article class="card policy-category-card" data-policy-category="${index}">
      <div class="card-header">
        <h2>Category ${index + 1}</h2>
        <button class="domain-delete policy-remove-category" type="button" aria-label="Remove category">
          <i data-feather="trash-2"></i> Remove
        </button>
      </div>
      <div class="card-body policy-settings">
        <label class="policy-field">
          <span>Category ID</span>
          <input data-policy-field="id" type="text" required maxlength="80"
            value="${escHtml(category.id || '')}" placeholder="social" />
          <small>Use letters, numbers, underscore, or hyphen.</small>
        </label>
        <label class="policy-field">
          <span>Name</span>
          <input data-policy-field="name" type="text" required maxlength="120"
            value="${escHtml(category.name || '')}" placeholder="Social media" />
        </label>
        <label class="policy-enabled">
          <input data-policy-field="enabled" type="checkbox" ${category.enabled !== false ? 'checked' : ''} />
          <span>Enabled</span>
        </label>
        <label class="policy-field policy-field-wide">
          <span>Domain patterns</span>
          <textarea data-policy-field="patterns" rows="4" spellcheck="false"
            placeholder="facebook.com&#10;*.fbcdn.net&#10;regex:^.*\\.example\\.com$">${escHtml((category.patterns || []).join('\n'))}</textarea>
          <small>One per line. example.com matches itself and subdomains; *.example.com matches subdomains only; regex: uses Java regular expressions.</small>
        </label>
        <label class="policy-field policy-field-wide">
          <span>Active schedule</span>
          <textarea data-policy-field="schedule" rows="3" spellcheck="false"
            placeholder="MON,TUE,WED,THU,FRI 07:30-17:00&#10;* 22:00-06:00">${escHtml(scheduleToText(category.schedule))}</textarea>
          <small>One schedule per line: days HH:mm-HH:mm. Use * for every day. Empty means the category is active all day. Overnight ranges are supported.</small>
        </label>
      </div>
    </article>
  `).join('');
  if (window.feather) feather.replace();
}

function linesToList(value) {
  return value.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
}

function parseSchedules(value, categoryId) {
  return linesToList(value).map((line, index) => {
    const match = line.match(/^(\*|[A-Za-z]{3}(?:\s*,\s*[A-Za-z]{3})*)\s+(\d{2}:\d{2})-(\d{2}:\d{2})$/);
    if (!match) {
      throw new Error(`Category "${categoryId}", schedule line ${index + 1}: use DAYS HH:mm-HH:mm.`);
    }
    return {
      days: match[1] === '*' ? [] : match[1].split(',').map(day => day.trim().toUpperCase()),
      from: match[2],
      to: match[3]
    };
  });
}

function setPolicyMessage(message, isError = false) {
  const status = $('#policy-message');
  status.textContent = message;
  status.className = isError ? 'form-hint form-msg error' : 'form-hint form-msg success';
}

$('#reload-policy-btn')?.addEventListener('click', loadPolicy);

$('#add-policy-category')?.addEventListener('click', () => {
  if (!policyConfig) return;
  policyConfig.categories = policyConfig.categories || [];
  policyConfig.categories.push({
    id: `category-${policyConfig.categories.length + 1}`,
    name: 'New category',
    enabled: true,
    patterns: [],
    schedule: []
  });
  renderPolicyCategories();
});

$('#policy-categories')?.addEventListener('click', event => {
  const button = event.target.closest('.policy-remove-category');
  if (!button || !policyConfig) return;
  const card = button.closest('[data-policy-category]');
  policyConfig.categories.splice(Number(card.dataset.policyCategory), 1);
  renderPolicyCategories();
});

$('#policy-form')?.addEventListener('submit', async event => {
  event.preventDefault();
  const button = event.submitter || $('button[type="submit"]', event.currentTarget);
  button.disabled = true;
  setPolicyMessage('Saving policy…');

  try {
    const categories = $$('#policy-categories [data-policy-category]').map(card => {
      const field = name => $(`[data-policy-field="${name}"]`, card);
      const id = field('id').value.trim();
      return {
        id,
        name: field('name').value.trim(),
        enabled: field('enabled').checked,
        patterns: linesToList(field('patterns').value),
        schedule: parseSchedules(field('schedule').value, id)
      };
    });
    const policy = {
      mode: $('#policy-mode').value,
      timezone: $('#policy-timezone').value.trim(),
      allow: linesToList($('#policy-allow').value),
      categories
    };
    policyConfig = await apiFetch('/policy', {
      method: 'PUT',
      body: JSON.stringify(policy)
    });
    renderPolicyCategories();
    setPolicyMessage('Saved. The proxy will apply this policy within about 5 seconds.');
    showToast('Policy saved', 'success');
  } catch (err) {
    setPolicyMessage(err.message, true);
  } finally {
    button.disabled = false;
  }
});

/* ========================================================
   BLOCKLIST
   ======================================================== */

let allDomains = [];

async function loadBlocklist() {
  try {
    const domains = await apiFetch('/blocklist');
    allDomains = Array.isArray(domains) ? [...domains].sort() : [...domains].sort();
    renderBlocklist(allDomains);
  } catch (err) {
    showToast('Failed to load blocklist: ' + err.message, 'error');
  }
}

function renderBlocklist(domains) {
  const container = $('#blocklist-container');
  $('#blocklist-count').textContent = domains.length;

  if (!domains.length) {
    container.innerHTML = '<p class="empty-state">Blocklist is empty.</p>';
    return;
  }

  container.innerHTML = `
    <ul class="domain-list">
      ${domains.map(d => `
        <li class="domain-item" data-domain="${escHtml(d)}">
          <span class="domain-name">${escHtml(d)}</span>
          <button class="domain-delete" data-domain="${escHtml(d)}" title="Remove domain">
            <i data-feather="trash-2"></i> Remove
          </button>
        </li>
      `).join('')}
    </ul>`;

  // Re-render feather icons
  if (window.feather) feather.replace();

  // Bind delete buttons
  $$('.domain-delete', container).forEach(btn => {
    btn.addEventListener('click', () => deleteDomain(btn.dataset.domain));
  });
}

async function deleteDomain(domain) {
  try {
    await apiFetch(`/blocklist/${encodeURIComponent(domain)}`, { method: 'DELETE' });
    showToast(`Removed: ${domain}`, 'success');
    await loadBlocklist();
  } catch (err) {
    showToast('Delete failed: ' + err.message, 'error');
  }
}

// Search filter
$('#domain-search')?.addEventListener('input', e => {
  const q = e.target.value.trim().toLowerCase();
  const filtered = q ? allDomains.filter(d => d.includes(q)) : allDomains;
  renderBlocklist(filtered);
});

// Add domain form
$('#add-domain-form')?.addEventListener('submit', async e => {
  e.preventDefault();
  const input = $('#domain-input');
  const domain = input.value.trim();
  const msgEl = $('#blocklist-message');

  if (!domain) return;

  try {
    const res = await apiFetch('/blocklist', {
      method: 'POST',
      body: JSON.stringify({ domain })
    });

    msgEl.style.display = 'block';
    if (res.success) {
      msgEl.className = 'form-msg success';
      msgEl.textContent = res.message;
      input.value = '';
      await loadBlocklist();
    } else {
      msgEl.className = 'form-msg error';
      msgEl.textContent = res.message;
    }
  } catch (err) {
    msgEl.style.display = 'block';
    msgEl.className = 'form-msg error';
    msgEl.textContent = 'Error: ' + err.message;
  }

  setTimeout(() => { msgEl.style.display = 'none'; }, 4000);
});

/* ========================================================
   INIT
   ======================================================== */

document.addEventListener('DOMContentLoaded', () => {
  // Render feather icons
  if (window.feather) feather.replace();

  initNavigation();
  checkProxyStatus();
  loadMonitoring();
  startWebSocket();

  // Refresh status every 30s
  setInterval(checkProxyStatus, 30_000);
  // Refresh chart data periodically even if no live log event arrives.
  setInterval(() => {
    if ($('#tab-dashboard')?.classList.contains('active')) loadMonitoring();
  }, 30_000);
});
