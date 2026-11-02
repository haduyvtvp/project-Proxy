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
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
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
  if (tabName === 'dashboard') loadStats();
  if (tabName === 'logs') initLogs();
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

async function loadStats() {
  try {
    const stats = await apiFetch('/stats');
    $('#stat-total').textContent   = stats.total   ?? 0;
    $('#stat-allowed').textContent = stats.allowed ?? 0;
    $('#stat-blocked').textContent = stats.blocked ?? 0;
    $('#stat-error').textContent   = stats.error   ?? 0;
    renderTopBlocked(stats.topBlocked || []);
  } catch (err) {
    showToast('Failed to load stats: ' + err.message, 'error');
  }
}

function renderTopBlocked(entries) {
  const container = $('#top-blocked-container');
  if (!entries.length) {
    container.innerHTML = '<p class="empty-state">No blocked requests yet.</p>';
    return;
  }
  // API trả về { domain: string, count: number }
  const maxCount = entries[0]?.count ?? 1;

  container.innerHTML = `
    <ul class="top-blocked-list">
      ${entries.map((entry, i) => {
        const domain = escHtml(entry.domain || '');
        const count  = entry.count ?? 0;
        const pct    = Math.round((count / maxCount) * 100);
        return `
          <li class="top-blocked-item">
            <div class="top-blocked-rank">${i + 1}</div>
            <div class="top-blocked-domain">${domain}</div>
            <div class="top-blocked-bar-wrap">
              <div class="top-blocked-bar" style="width:${pct}%"></div>
            </div>
            <div class="top-blocked-count">${count}</div>
          </li>`;
      }).join('')}
    </ul>`;
}

$('#refresh-stats-btn')?.addEventListener('click', loadStats);

/* ========================================================
   ACCESS LOGS
   ======================================================== */

let sseSource = null;
let logsInitialized = false;

function initLogs() {
  if (logsInitialized) return;
  logsInitialized = true;
  fetchRecentLogs();
  startSSE();
}

async function fetchRecentLogs() {
  try {
    const logs = await apiFetch('/logs?limit=100');
    const tbody = $('#log-tbody');
    if (!logs.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No logs yet.</td></tr>';
      return;
    }
    tbody.innerHTML = '';
    logs.forEach(entry => appendLogRow(entry, false));
    scrollToBottom();
  } catch (err) {
    showToast('Failed to load logs: ' + err.message, 'error');
  }
}

function startSSE() {
  if (sseSource) { sseSource.close(); }

  const sseBadge = $('#sse-badge');
  sseSource = new EventSource(API_BASE + '/logs/stream');

  sseSource.addEventListener('log', e => {
    try {
      const entry = JSON.parse(e.data);
      appendLogRow(entry, true);
    } catch { /* ignore malformed */ }
  });

  sseSource.onopen = () => {
    sseBadge.textContent = '● Live';
    sseBadge.className = 'badge badge-sse';
  };

  sseSource.onerror = () => {
    sseBadge.textContent = '○ Disconnected';
    sseBadge.className = 'badge badge-sse disconnected';
    // Reconnect after 5s
    setTimeout(() => {
      if (logsInitialized) startSSE();
    }, 5000);
  };
}

const MAX_LOG_ROWS = 500;

function appendLogRow(entry, isNew) {
  const tbody = $('#log-tbody');

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

function scrollToBottom() {
  const wrapper = $('#log-table-wrapper');
  if (wrapper) wrapper.scrollTop = wrapper.scrollHeight;
}

$('#clear-logs-btn')?.addEventListener('click', () => {
  const tbody = $('#log-tbody');
  tbody.innerHTML = '<tr><td colspan="5" class="empty-state">Logs cleared (display only).</td></tr>';
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
  loadStats();

  // Refresh status every 30s
  setInterval(checkProxyStatus, 30_000);
  // Refresh stats every 15s when on dashboard
  setInterval(() => {
    if ($('#tab-dashboard')?.classList.contains('active')) loadStats();
  }, 15_000);
});
