/* ── ScamShield AI · Frontend Logic ─────────────────────────────────────────── */
"use strict";

// ── State ──────────────────────────────────────────────────────────────────────
let totalScans = 0;
let confusionChart = null;
let gaugeChart = null;
let statsLoaded = false;

// ── DOM refs ───────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const emailInput    = $('emailInput');
const analyzeBtn    = $('analyzeBtn');
const clearBtn      = $('clearBtn');
const charCount     = $('charCount');
const resultsArea   = $('resultsArea');
const scanLoader    = $('scanLoader');
const urlInput      = $('urlInput');
const checkUrlBtn   = $('checkUrlBtn');
const linkResults   = $('linkResults');
const totalScansEl  = $('totalScans');
const historyList   = $('historyList');
const historyCount  = $('historyCount');

// ── Tab switching ──────────────────────────────────────────────────────────────
document.querySelectorAll('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => {
    const tab = btn.dataset.tab;
    document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(`tab-${tab}`).classList.add('active');
    if (tab === 'stats' && !statsLoaded) loadStats();
  });
});

// ── Char counter ───────────────────────────────────────────────────────────────
emailInput.addEventListener('input', () => {
  const len = emailInput.value.length;
  charCount.textContent = `${len.toLocaleString()} / 10,000`;
  charCount.style.color = len > 9000 ? 'var(--red)' : len > 7000 ? 'var(--amber)' : '';
});

// ── Clear ──────────────────────────────────────────────────────────────────────
clearBtn.addEventListener('click', () => {
  emailInput.value = '';
  charCount.textContent = '0 / 10,000';
  resultsArea.classList.add('hidden');
  scanLoader.classList.add('hidden');
});

// ── ANALYZE EMAIL ──────────────────────────────────────────────────────────────
analyzeBtn.addEventListener('click', runEmailScan);
emailInput.addEventListener('keydown', e => {
  if (e.ctrlKey && e.key === 'Enter') runEmailScan();
});

async function runEmailScan() {
  const text = emailInput.value.trim();
  if (!text) { flashInput(emailInput); return; }

  analyzeBtn.disabled = true;
  resultsArea.classList.add('hidden');
  scanLoader.classList.remove('hidden');

  try {
    const res  = await fetch('/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email_text: text }),
    });
    const data = await res.json();

    if (data.error) { showError(data.error); return; }

    totalScans++;
    totalScansEl.textContent = totalScans;

    renderVerdict(data);
    renderRiskScore(data.domain_risk);
    renderLinks(data.suspicious_links);
    renderKeywords(data.keyword_hits);
    updateHistory(data, text);

    scanLoader.classList.add('hidden');
    resultsArea.classList.remove('hidden');

  } catch (err) {
    showError('Network error: ' + err.message);
  } finally {
    analyzeBtn.disabled = false;
    scanLoader.classList.add('hidden');
  }
}

// ── RENDER VERDICT ─────────────────────────────────────────────────────────────
function renderVerdict(data) {
  const card    = document.querySelector('.verdict-card');
  const icon    = $('verdictIcon');
  const text    = $('verdictText');
  const conf    = $('verdictConfidence');
  const meta    = $('verdictMeta');
  const dot     = $('verdictDot');

  const isSpam = data.prediction === 'Spam';

  card.className = 'glass-card verdict-card ' + (isSpam ? 'spam' : 'safe');
  dot.className  = 'dot ' + (isSpam ? 'red' : 'green');
  icon.textContent = isSpam ? '⚠' : '✔';
  text.textContent = data.prediction;

  conf.textContent = data.confidence
    ? `Confidence: ${data.confidence}%`
    : 'Rule-based classification';

  meta.innerHTML = [
    `Characters: ${data.char_count.toLocaleString()}`,
    `URLs found: ${data.total_urls}`,
    `Scanned at: ${data.timestamp}`,
  ].join('<br>');
}

// ── RENDER RISK GAUGE ─────────────────────────────────────────────────────────
function renderRiskScore(score) {
  const label    = $('riskScoreLabel');
  const fill     = $('riskBarFill');
  const barText  = $('riskBarText');
  const canvas   = $('riskGauge');

  label.textContent = score;
  fill.style.width  = score + '%';

  if (score >= 60)      { fill.classList.add('high');    barText.textContent = 'HIGH RISK'; }
  else if (score >= 30) { fill.classList.remove('high'); barText.textContent = 'Medium Risk'; }
  else                  { fill.classList.remove('high'); barText.textContent = 'Low Risk'; }

  // Destroy old gauge
  if (gaugeChart) { gaugeChart.destroy(); gaugeChart = null; }

  const color = score >= 60 ? '#ff3b5c' : score >= 30 ? '#ffb300' : '#00e676';

  gaugeChart = new Chart(canvas, {
    type: 'doughnut',
    data: {
      datasets: [{
        data: [score, 100 - score],
        backgroundColor: [color, 'rgba(255,255,255,0.04)'],
        borderWidth: 0,
        circumference: 180,
        rotation: 270,
      }]
    },
    options: {
      responsive: false,
      cutout: '72%',
      plugins: { legend: { display: false }, tooltip: { enabled: false } },
      animation: { duration: 900, easing: 'easeOutQuart' },
    }
  });
}

// ── RENDER LINKS ──────────────────────────────────────────────────────────────
function renderLinks(links) {
  const list = $('linksList');
  $('urlCount').textContent = links.length;
  list.innerHTML = '';

  if (!links.length) {
    list.innerHTML = '<div class="no-links">✓ No suspicious URLs detected</div>';
    return;
  }

  links.forEach(link => {
    const div = document.createElement('div');
    div.className = 'link-item';
    const flags = link.flags.map(f => `<span class="link-flag-tag">${esc(f)}</span>`).join('');
    div.innerHTML = `
      <div class="link-url">${esc(link.url)}</div>
      <div class="link-domain">${esc(link.domain)}</div>
      <div style="display:flex;justify-content:space-between;align-items:center;margin-top:4px">
        <div class="link-flags">${flags}</div>
        <span class="link-risk-score">Risk: ${link.risk}/100</span>
      </div>`;
    list.appendChild(div);
  });
}

// ── RENDER KEYWORDS ───────────────────────────────────────────────────────────
function renderKeywords(keywords) {
  const wrap = $('keywordsWrap');
  wrap.innerHTML = '';

  if (!keywords || !keywords.length) {
    wrap.innerHTML = '<span class="no-keywords">None detected</span>';
    return;
  }

  const clean = keywords.map(k => k.replace(/\\b/g, '').replace(/\\/g, ''));
  clean.forEach(kw => {
    const span = document.createElement('span');
    span.className = 'keyword-tag';
    span.textContent = kw;
    wrap.appendChild(span);
  });
}

// ── SCAN HISTORY ──────────────────────────────────────────────────────────────
function updateHistory(data, text) {
  const preview = text.replace(/\s+/g, ' ').trim().substring(0, 55) + (text.length > 55 ? '…' : '');
  const item = document.createElement('div');
  item.className = 'history-item';
  const cls = data.prediction === 'Spam' ? 'spam' : 'safe';
  item.innerHTML = `
    <div class="h-preview">${esc(preview)}</div>
    <div class="h-meta">
      <span class="h-verdict ${cls}">${data.prediction}</span>
      <span class="h-time">${data.timestamp}</span>
    </div>`;

  const empty = historyList.querySelector('.history-empty');
  if (empty) empty.remove();
  historyList.prepend(item);

  // Trim to 10
  while (historyList.children.length > 10) historyList.lastChild.remove();
  historyCount.textContent = historyList.children.length;
}

// ── LINK TESTER ───────────────────────────────────────────────────────────────
checkUrlBtn.addEventListener('click', runLinkCheck);
urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') runLinkCheck(); });

async function runLinkCheck() {
  const url = urlInput.value.trim();
  if (!url) { flashInput(urlInput); return; }

  checkUrlBtn.disabled = true;
  checkUrlBtn.textContent = 'Checking…';
  linkResults.classList.add('hidden');

  try {
    const res  = await fetch('/check-link', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    const data = await res.json();
    if (data.error) { showError(data.error); return; }
    renderLinkResult(data);
    linkResults.classList.remove('hidden');
  } catch (err) {
    showError('Network error: ' + err.message);
  } finally {
    checkUrlBtn.disabled = false;
    checkUrlBtn.innerHTML = '<span class="btn-icon">⚡</span> Check Link';
  }
}

function renderLinkResult(data) {
  const badge  = $('linkVerdictBadge');
  const domain = $('linkDomainText');
  const risk   = $('linkRiskVal');
  const flag   = $('linkFlagVal');
  const status = $('linkStatusVal');
  const fill   = $('linkRiskFill');
  const flagSec = $('flagsSection');
  const flagList = $('flagsList');

  const isDanger = data.domain_flag || !data.safe;

  badge.textContent = isDanger ? '⚠ HIGH RISK' : '✔ SAFE';
  badge.className   = 'link-verdict-badge ' + (isDanger ? 'danger' : 'safe');
  domain.textContent = data.domain;

  risk.textContent   = `${data.risk} / 100`;
  risk.style.color   = data.risk >= 60 ? 'var(--red)' : data.risk >= 30 ? 'var(--amber)' : 'var(--green)';
  flag.textContent   = data.domain_flag ? '⚑ Flagged' : '—';
  flag.style.color   = data.domain_flag ? 'var(--red)' : 'var(--green)';
  status.textContent = data.safe ? 'Likely Safe' : 'Suspicious';
  status.style.color = data.safe ? 'var(--green)' : 'var(--red)';

  fill.style.width = data.risk + '%';
  fill.className   = 'risk-bar-fill' + (data.risk >= 60 ? ' high' : '');

  if (data.flags && data.flags.length) {
    flagSec.style.display = 'block';
    flagList.innerHTML = data.flags.map(f => `<li>${esc(f)}</li>`).join('');
  } else {
    flagSec.style.display = 'none';
  }
}

// ── MODEL STATS ───────────────────────────────────────────────────────────────
async function loadStats() {
  try {
    const res  = await fetch('/stats');
    const data = await res.json();

    animateMetric('statAccuracy',  data.accuracy,  'barAccuracy');
    animateMetric('statPrecision', data.precision, 'barPrecision');
    animateMetric('statRecall',    data.recall,    'barRecall');
    animateMetric('statF1',        data.f1_score,  'barF1');

    $('modelType').textContent    = data.model_type;
    $('trainSamples').textContent = data.training_samples.toLocaleString();

    renderConfusionMatrix(data.confusion_matrix);
    statsLoaded = true;
  } catch (err) {
    console.error('Stats load failed:', err);
  }
}

function animateMetric(valId, pct, barId) {
  const el = $(valId);
  const bar = $(barId);
  if (!el) return;

  let current = 0;
  const target = pct;
  const step = () => {
    current = Math.min(current + 1.2, target);
    el.textContent = current.toFixed(1) + '%';
    bar.style.width = current + '%';
    if (current < target) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function renderConfusionMatrix(cm) {
  const canvas = $('confusionMatrix');
  if (!canvas) return;
  if (confusionChart) { confusionChart.destroy(); confusionChart = null; }

  const { tn, fp, fn, tp } = cm;

  confusionChart = new Chart(canvas, {
    type: 'bar',
    data: {
      labels: ['True Negative', 'False Positive', 'False Negative', 'True Positive'],
      datasets: [{
        label: 'Count',
        data: [tn, fp, fn, tp],
        backgroundColor: [
          'rgba(0,230,118,0.5)',
          'rgba(255,59,92,0.5)',
          'rgba(255,179,0,0.5)',
          'rgba(0,245,255,0.5)',
        ],
        borderColor: [
          'rgba(0,230,118,0.9)',
          'rgba(255,59,92,0.9)',
          'rgba(255,179,0,0.9)',
          'rgba(0,245,255,0.9)',
        ],
        borderWidth: 1,
        borderRadius: 6,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 1200, easing: 'easeOutQuart' },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: 'rgba(2,15,28,0.95)',
          borderColor: 'rgba(0,245,255,0.2)',
          borderWidth: 1,
          titleColor: '#00f5ff',
          bodyColor: '#c8d8e4',
          padding: 12,
        }
      },
      scales: {
        x: {
          grid: { color: 'rgba(0,245,255,0.04)' },
          ticks: { color: '#526577', font: { family: "'Share Tech Mono'", size: 11 } }
        },
        y: {
          grid: { color: 'rgba(0,245,255,0.04)' },
          ticks: { color: '#526577', font: { family: "'Share Tech Mono'", size: 11 } }
        }
      }
    }
  });
}

// ── Utilities ─────────────────────────────────────────────────────────────────
function esc(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function flashInput(el) {
  el.style.borderColor = 'var(--red)';
  el.style.boxShadow   = '0 0 0 3px rgba(255,59,92,0.15)';
  setTimeout(() => {
    el.style.borderColor = '';
    el.style.boxShadow   = '';
  }, 1000);
}

function showError(msg) {
  scanLoader.classList.add('hidden');
  // Simple toast
  const toast = document.createElement('div');
  toast.style.cssText = `
    position:fixed; bottom:28px; right:28px; z-index:999;
    background:rgba(255,59,92,0.12); border:1px solid rgba(255,59,92,0.35);
    color:var(--red); font-family:var(--font-mono); font-size:0.78rem;
    padding:12px 20px; border-radius:8px; animation:fadeSlide .3s ease;
    max-width:340px; line-height:1.5;`;
  toast.textContent = '⚠ ' + msg;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}

// ── Init ───────────────────────────────────────────────────────────────────────
// Pre-fill demo text for quick testing
const DEMO_TEXT = `Subject: URGENT: Your account will be suspended!

Dear Customer,

Congratulations! You have been selected as a winner of our $1,000,000 lottery!
Click here to claim your free prize immediately: http://bit.ly/win-now
Verify your bank account at: http://paypal-security.tk/verify

Act now — limited time offer! No credit card required.
Your social security details are needed to process the claim.

Best regards,
The Prize Team`;

emailInput.value = DEMO_TEXT;
charCount.textContent = `${DEMO_TEXT.length.toLocaleString()} / 10,000`;
