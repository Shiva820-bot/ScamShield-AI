"""
ScamShield AI - app.py
======================
COMPLETELY SELF-CONTAINED. No templates/ or static/ folders needed.
Just run:  python app.py
"""

import os, re, pickle, json
from datetime import datetime
from flask import Flask, request, jsonify, Response

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)

# ── ML Model ──────────────────────────────────────────────────────────────────
model, vectorizer = None, None
try:
    with open(os.path.join(BASE_DIR, "model.pkl"), "rb") as f:
        model = pickle.load(f)
    with open(os.path.join(BASE_DIR, "vectorizer.pkl"), "rb") as f:
        vectorizer = pickle.load(f)
    print("[OK] model.pkl + vectorizer.pkl loaded.")
except FileNotFoundError:
    print("[--] No model files found — using rule-based fallback. Run train_model.py to fix.")

scan_history = []

SPAM_KEYWORDS = [
    r"\bfree\b", r"\burgent\b", r"\bwinner\b", r"\bcongratulations\b",
    r"\bclaim\s+your\b", r"\bclick\s+here\b", r"\bact\s+now\b",
    r"\blimited\s+time\b", r"\bverify\s+your\s+account\b",
    r"\bpassword\b", r"\bbank\s+account\b", r"\bsocial\s+security\b",
    r"\blottery\b", r"\bmillion\s+dollar", r"\binheritance\b",
    r"\b100%\s+free\b", r"\bno\s+credit\s+card\b",
]
HIGH_RISK_DOMAINS = [
    "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","tiny.cc",
    "url4.eu","tr.im","su.pr","snipurl.com","short.to","ping.fm",
    "post.ly","bkite.com","snipr.com","doiop.com","kl.am","wp.me",
    "rubyurl.com","om.ly","to.ly","bit.do","lnkd.in",
]
SUSPICIOUS_TLDS = [".tk",".ml",".ga",".cf",".gq",".xyz",".top",".club"]
PHISHING_PATTERNS = [
    r"paypal[^\.]*\.(?!com\b)\w+", r"amazon[^\.]*\.(?!com\b|co\.uk\b|de\b|fr\b|jp\b)\w+",
    r"google[^\.]*\.(?!com\b|co\.\w+\b)\w+", r"apple[^\.]*\.(?!com\b)\w+",
    r"microsoft[^\.]*\.(?!com\b)\w+", r"netflix[^\.]*\.(?!com\b|net\b)\w+",
    r"bank[^\.]*\.(?!com\b|org\b|net\b)\w+",
]

def extract_urls(text):
    return re.findall(r'https?://[^\s<>"\'{}|\\^`\[\]]+', text, re.IGNORECASE)

def get_domain(url):
    m = re.search(r'https?://([^/\s?#]+)', url)
    return m.group(1).lower() if m else url.lower()

def check_domain_risk(domain):
    score, flags = 0, []
    if domain in HIGH_RISK_DOMAINS:
        score += 40; flags.append("URL shortener detected")
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 30; flags.append(f"Suspicious TLD: {tld}"); break
    for p in PHISHING_PATTERNS:
        if re.search(p, domain, re.IGNORECASE):
            score += 50; flags.append("Possible brand impersonation"); break
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        score += 35; flags.append("IP address used instead of domain")
    if domain.count('.') >= 3:
        score += 15; flags.append("Excessive subdomains")
    if len(domain) > 40:
        score += 10; flags.append("Unusually long domain")
    return min(score, 100), flags

def analyze_email_text(text):
    kw_hits = [kw for kw in SPAM_KEYWORDS if re.search(kw, text, re.IGNORECASE)]
    urls = extract_urls(text)
    suspicious, max_risk = [], 0
    for url in urls:
        domain = get_domain(url)
        risk, flags = check_domain_risk(domain)
        max_risk = max(max_risk, risk)
        if risk > 20 or flags:
            suspicious.append({"url": url, "domain": domain, "risk": risk, "flags": flags})
    combined = min(len(kw_hits) * 10 + max_risk, 100)
    return urls, suspicious, combined, kw_hits

def ml_predict(text):
    if model and vectorizer:
        try:
            vec = vectorizer.transform([text])
            pred = model.predict(vec)[0]
            proba = model.predict_proba(vec)[0] if hasattr(model, 'predict_proba') else None
            label = "Spam" if str(pred) in ["1","spam","Spam"] else "Not Spam"
            return label, (float(max(proba)) * 100 if proba is not None else None)
        except Exception as e:
            print(f"ML error: {e}")
    _, _, risk, kws = analyze_email_text(text)
    if risk >= 40 or len(kws) >= 3:
        return "Spam", min(50 + risk * 0.5, 99)
    return "Not Spam", min(50 + (100 - risk) * 0.3, 95)

# ── CSS served directly from Python ──────────────────────────────────────────
CSS = r"""
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#020c14;--sidebar-bg:rgba(2,15,28,0.95);--glass:rgba(0,245,255,0.04);
--glass-b:rgba(0,245,255,0.12);--cyan:#00f5ff;--cyan-dim:rgba(0,245,255,0.15);
--cyan-glow:rgba(0,245,255,0.35);--blue:#0072ff;--amber:#ffb300;--red:#ff3b5c;
--green:#00e676;--purple:#b44fff;--text:#c8d8e4;--text-dim:#526577;
--text-bright:#e8f4fc;--border:rgba(0,245,255,0.1);--radius:12px;
--sidebar-w:260px;--font-mono:'Share Tech Mono',monospace;
--font-main:'Exo 2',sans-serif}
html,body{height:100%;background:var(--bg);color:var(--text);font-family:var(--font-main);overflow:hidden}
.bg-grid{position:fixed;inset:0;z-index:0;
background-image:linear-gradient(rgba(0,245,255,0.03) 1px,transparent 1px),
linear-gradient(90deg,rgba(0,245,255,0.03) 1px,transparent 1px);
background-size:40px 40px;animation:gridDrift 30s linear infinite}
@keyframes gridDrift{0%{background-position:0 0}100%{background-position:40px 40px}}
.scan-line{position:fixed;left:0;right:0;height:2px;z-index:1;
background:linear-gradient(90deg,transparent,var(--cyan),transparent);
opacity:.3;animation:scanDown 8s ease-in-out infinite}
@keyframes scanDown{0%{top:-2px;opacity:0}10%{opacity:.3}90%{opacity:.3}100%{top:100vh;opacity:0}}
body{display:flex;height:100vh;overflow:hidden}
.sidebar{position:relative;z-index:10;width:var(--sidebar-w);min-width:var(--sidebar-w);
background:var(--sidebar-bg);border-right:1px solid var(--border);display:flex;
flex-direction:column;padding:24px 16px 16px;backdrop-filter:blur(20px);overflow-y:auto}
.main{position:relative;z-index:5;flex:1;overflow-y:auto;padding:28px 32px;
scrollbar-width:thin;scrollbar-color:var(--border) transparent}
.main::-webkit-scrollbar{width:4px}
.main::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}
.logo-block{display:flex;align-items:center;gap:12px;margin-bottom:20px}
.logo-icon{filter:drop-shadow(0 0 8px var(--cyan))}
.logo-text{font-family:var(--font-main);font-weight:900;font-size:1.15rem;
letter-spacing:.08em;color:var(--cyan);text-transform:uppercase;
text-shadow:0 0 15px var(--cyan-glow)}
.logo-sub{font-family:var(--font-mono);font-size:.65rem;color:var(--text-dim);
letter-spacing:.12em;margin-top:2px}
.status-badge{display:flex;align-items:center;gap:8px;background:rgba(0,230,118,.08);
border:1px solid rgba(0,230,118,.2);border-radius:20px;padding:5px 12px;
font-family:var(--font-mono);font-size:.68rem;color:var(--green);margin-bottom:24px;
letter-spacing:.05em}
.pulse-dot{width:7px;height:7px;border-radius:50%;background:var(--green);
box-shadow:0 0 0 0 rgba(0,230,118,.5);animation:pulse 2s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(0,230,118,.5)}
70%{box-shadow:0 0 0 7px rgba(0,230,118,0)}100%{box-shadow:0 0 0 0 rgba(0,230,118,0)}}
.nav{display:flex;flex-direction:column;gap:6px;margin-bottom:24px}
.nav-item{display:flex;align-items:center;gap:10px;background:transparent;
border:1px solid transparent;border-radius:8px;padding:10px 12px;color:var(--text-dim);
font-family:var(--font-main);font-size:.85rem;font-weight:600;letter-spacing:.03em;
cursor:pointer;transition:all .2s;text-align:left;width:100%}
.nav-item:hover{background:var(--glass);color:var(--text);border-color:var(--border)}
.nav-item.active{background:var(--cyan-dim);border-color:var(--glass-b);color:var(--cyan);
box-shadow:0 0 15px rgba(0,245,255,.08)}
.nav-icon{font-size:.75rem;opacity:.7}
.nav-arrow{margin-left:auto;opacity:.4;font-size:1rem;transition:transform .2s}
.nav-item.active .nav-arrow{opacity:1;transform:translateX(3px)}
.sidebar-footer{margin-top:auto;border-top:1px solid var(--border);padding-top:16px}
.history-label{display:flex;justify-content:space-between;align-items:center;
font-family:var(--font-mono);font-size:.65rem;color:var(--text-dim);
letter-spacing:.1em;margin-bottom:10px;text-transform:uppercase}
.history-count{background:var(--cyan-dim);color:var(--cyan);border-radius:10px;
padding:2px 7px;font-size:.65rem}
.history-list{display:flex;flex-direction:column;gap:4px;max-height:200px;overflow-y:auto}
.history-empty{font-family:var(--font-mono);font-size:.7rem;color:var(--text-dim);
text-align:center;padding:12px 0}
.history-item{background:var(--glass);border:1px solid var(--border);border-radius:6px;
padding:7px 10px;cursor:pointer;transition:background .15s;animation:fadeSlide .3s ease}
.history-item:hover{background:rgba(0,245,255,.08)}
@keyframes fadeSlide{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:translateY(0)}}
.h-preview{font-family:var(--font-mono);font-size:.65rem;color:var(--text);
white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:200px}
.h-meta{display:flex;justify-content:space-between;margin-top:3px}
.h-verdict{font-size:.6rem;font-weight:700;font-family:var(--font-mono)}
.h-verdict.spam{color:var(--red)}.h-verdict.safe{color:var(--green)}
.h-time{font-size:.6rem;color:var(--text-dim);font-family:var(--font-mono)}
.panel-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:24px}
.panel-title{font-size:1.6rem;font-weight:900;color:var(--text-bright);letter-spacing:-.01em}
.panel-sub{font-size:.82rem;color:var(--text-dim);margin-top:4px;max-width:520px;line-height:1.5}
.threat-counter{text-align:right;font-family:var(--font-mono)}
.threat-counter span:first-child{display:block;font-size:2rem;color:var(--cyan);
line-height:1;text-shadow:0 0 20px var(--cyan-glow)}
.threat-label{font-size:.65rem;color:var(--text-dim);text-transform:uppercase;letter-spacing:.1em}
.glass-card{background:var(--glass);border:1px solid var(--glass-b);border-radius:var(--radius);
padding:20px;backdrop-filter:blur(12px);position:relative;overflow:hidden;
transition:border-color .3s,box-shadow .3s}
.glass-card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;
background:linear-gradient(90deg,transparent,var(--cyan-dim),transparent)}
.glass-card:hover{border-color:rgba(0,245,255,.2);box-shadow:0 0 25px rgba(0,245,255,.06)}
.card-label{display:flex;align-items:center;gap:6px;font-family:var(--font-mono);
font-size:.65rem;letter-spacing:.1em;color:var(--text-dim);text-transform:uppercase;margin-bottom:14px}
.dot{width:6px;height:6px;border-radius:50%;display:inline-block;flex-shrink:0}
.dot.cyan{background:var(--cyan);box-shadow:0 0 6px var(--cyan)}
.dot.red{background:var(--red);box-shadow:0 0 6px var(--red)}
.dot.amber{background:var(--amber);box-shadow:0 0 6px var(--amber)}
.dot.purple{background:var(--purple);box-shadow:0 0 6px var(--purple)}
.dot.green{background:var(--green);box-shadow:0 0 6px var(--green)}
.input-card{margin-bottom:24px}
.email-textarea{width:100%;min-height:160px;max-height:300px;background:rgba(0,0,0,.3);
border:1px solid var(--border);border-radius:8px;padding:14px 16px;color:var(--text);
font-family:var(--font-mono);font-size:.8rem;line-height:1.7;resize:vertical;outline:none;
transition:border-color .2s,box-shadow .2s}
.email-textarea::placeholder{color:var(--text-dim);opacity:.6}
.email-textarea:focus{border-color:rgba(0,245,255,.4);box-shadow:0 0 0 3px rgba(0,245,255,.06)}
.input-actions{display:flex;align-items:center;gap:10px;margin-top:12px}
.char-count{font-family:var(--font-mono);font-size:.7rem;color:var(--text-dim);flex:1}
.btn-primary{display:flex;align-items:center;gap:7px;padding:10px 22px;
background:linear-gradient(135deg,#005f8a,#0093c4);border:1px solid var(--cyan-dim);
border-radius:8px;color:var(--cyan);font-family:var(--font-main);font-size:.85rem;
font-weight:700;letter-spacing:.05em;cursor:pointer;transition:all .2s;
white-space:nowrap;text-transform:uppercase}
.btn-primary:hover{background:linear-gradient(135deg,#006fa0,#00aad4);
box-shadow:0 0 20px rgba(0,245,255,.25);transform:translateY(-1px)}
.btn-primary:active{transform:translateY(0)}
.btn-primary:disabled{opacity:.5;cursor:not-allowed;transform:none}
.btn-icon{font-size:.7rem}
.btn-ghost{padding:8px 16px;background:transparent;border:1px solid var(--border);
border-radius:8px;color:var(--text-dim);font-family:var(--font-main);font-size:.82rem;
cursor:pointer;transition:all .2s}
.btn-ghost:hover{border-color:rgba(0,245,255,.3);color:var(--text)}
.results-grid{display:grid;grid-template-columns:1fr 1fr;grid-template-rows:auto auto;gap:16px}
.verdict-card{grid-column:1;grid-row:1}.risk-card{grid-column:2;grid-row:1}
.urls-card{grid-column:1;grid-row:2}.keywords-card{grid-column:2;grid-row:2}
.verdict-main{display:flex;align-items:center;gap:14px;margin-bottom:12px}
.verdict-icon{font-size:2.2rem;line-height:1;transition:color .4s}
.verdict-text{font-size:1.7rem;font-weight:900;font-family:var(--font-main);
letter-spacing:-.01em;transition:color .4s}
.verdict-confidence{font-family:var(--font-mono);font-size:.75rem;color:var(--text-dim);margin-bottom:6px}
.verdict-meta{font-family:var(--font-mono);font-size:.7rem;color:var(--text-dim);line-height:1.6}
.verdict-card.spam .verdict-icon,.verdict-card.spam .verdict-text{color:var(--red);
text-shadow:0 0 20px rgba(255,59,92,.5)}
.verdict-card.safe .verdict-icon,.verdict-card.safe .verdict-text{color:var(--green);
text-shadow:0 0 20px rgba(0,230,118,.4)}
.risk-gauge-wrap{position:relative;display:flex;justify-content:center;margin-bottom:12px}
.risk-score-label{position:absolute;bottom:-4px;left:50%;transform:translateX(-50%);
font-family:var(--font-mono);font-size:1.5rem;font-weight:700;color:var(--amber);
text-shadow:0 0 15px rgba(255,179,0,.5)}
.risk-bar-wrap{display:flex;align-items:center;gap:10px}
.risk-bar-track{flex:1;height:6px;background:rgba(255,255,255,.06);border-radius:3px;overflow:hidden}
.risk-bar-fill{height:100%;border-radius:3px;transition:width .8s cubic-bezier(.4,0,.2,1),background .5s;
background:linear-gradient(90deg,var(--green),var(--amber))}
.risk-bar-fill.high{background:linear-gradient(90deg,var(--amber),var(--red))}
.risk-bar-text{font-family:var(--font-mono);font-size:.68rem;color:var(--text-dim);
white-space:nowrap;min-width:60px;text-align:right}
.links-list{display:flex;flex-direction:column;gap:8px;max-height:180px;overflow-y:auto}
.no-links,.no-keywords{font-family:var(--font-mono);font-size:.72rem;color:var(--text-dim);padding:8px 0}
.link-item{background:rgba(255,59,92,.06);border:1px solid rgba(255,59,92,.15);
border-radius:7px;padding:10px 12px;animation:fadeSlide .3s ease}
.link-url{font-family:var(--font-mono);font-size:.7rem;color:var(--red);
word-break:break-all;margin-bottom:4px}
.link-domain{font-size:.68rem;color:var(--text-dim);margin-bottom:3px}
.link-flags{display:flex;flex-wrap:wrap;gap:4px;margin-top:4px}
.link-flag-tag{font-size:.6rem;font-family:var(--font-mono);background:rgba(255,59,92,.12);
border:1px solid rgba(255,59,92,.25);color:var(--red);padding:2px 7px;border-radius:4px}
.link-risk-score{font-family:var(--font-mono);font-size:.65rem;color:var(--amber);font-weight:700}
.keywords-wrap{display:flex;flex-wrap:wrap;gap:6px}
.keyword-tag{font-family:var(--font-mono);font-size:.68rem;background:rgba(180,79,255,.1);
border:1px solid rgba(180,79,255,.25);color:var(--purple);padding:4px 10px;
border-radius:4px;animation:fadeSlide .3s ease}
.scan-loader{display:flex;flex-direction:column;align-items:center;gap:16px;padding:40px}
.loader-ring{width:48px;height:48px;border:2px solid var(--border);
border-top-color:var(--cyan);border-radius:50%;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.loader-text{font-family:var(--font-mono);font-size:.8rem;color:var(--cyan);letter-spacing:.05em}
.dots::after{content:'';animation:dotCycle 1.5s infinite}
@keyframes dotCycle{0%{content:''}25%{content:'.'}50%{content:'..'}75%{content:'...'}}
.url-input-row{display:flex;gap:10px;align-items:center}
.url-input{flex:1;background:rgba(0,0,0,.3);border:1px solid var(--border);border-radius:8px;
padding:10px 14px;color:var(--text);font-family:var(--font-mono);font-size:.82rem;
outline:none;transition:border-color .2s}
.url-input:focus{border-color:rgba(0,245,255,.4)}
.link-results{margin-top:20px;max-width:680px}
.link-result-header{display:flex;align-items:center;gap:14px;margin-bottom:16px}
.link-verdict-badge{padding:5px 14px;border-radius:20px;font-family:var(--font-mono);
font-size:.75rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
.link-verdict-badge.danger{background:rgba(255,59,92,.12);border:1px solid rgba(255,59,92,.3);color:var(--red)}
.link-verdict-badge.safe{background:rgba(0,230,118,.1);border:1px solid rgba(0,230,118,.25);color:var(--green)}
.link-domain-text{font-family:var(--font-mono);font-size:.85rem;color:var(--text);word-break:break-all}
.link-detail-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:12px}
.link-detail-item{background:rgba(0,0,0,.2);border:1px solid var(--border);border-radius:7px;padding:10px}
.link-detail-label{display:block;font-family:var(--font-mono);font-size:.62rem;color:var(--text-dim);
text-transform:uppercase;letter-spacing:.08em;margin-bottom:5px}
.link-detail-val{display:block;font-family:var(--font-mono);font-size:.9rem;font-weight:700;color:var(--text-bright)}
.link-risk-bar-wrap{margin-top:14px}
.flags-list{list-style:none;display:flex;flex-direction:column;gap:5px;margin-top:8px}
.flags-list li{font-family:var(--font-mono);font-size:.72rem;color:var(--red);padding:5px 10px;
background:rgba(255,59,92,.06);border-left:2px solid var(--red);border-radius:0 5px 5px 0}
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:20px}
.metric-card{text-align:center;padding:24px 16px}
.metric-icon{font-size:1.4rem;color:var(--cyan);margin-bottom:10px;opacity:.8}
.metric-val{font-family:var(--font-mono);font-size:1.8rem;font-weight:700;color:var(--cyan);
text-shadow:0 0 15px var(--cyan-glow);margin-bottom:4px}
.metric-label{font-size:.72rem;color:var(--text-dim);text-transform:uppercase;
letter-spacing:.1em;font-family:var(--font-mono);margin-bottom:12px}
.metric-bar{height:3px;background:rgba(255,255,255,.06);border-radius:2px;overflow:hidden}
.metric-bar-fill{height:100%;background:linear-gradient(90deg,var(--blue),var(--cyan));
border-radius:2px;transition:width 1s cubic-bezier(.4,0,.2,1)}
.stats-bottom-grid{display:grid;grid-template-columns:1.5fr 1fr;gap:16px}
.cm-chart-wrap{height:260px;position:relative}
.model-info-list{display:flex;flex-direction:column;gap:0}
.info-row{display:flex;justify-content:space-between;align-items:center;
padding:10px 0;border-bottom:1px solid var(--border)}
.info-row:last-child{border-bottom:none}
.info-label{font-family:var(--font-mono);font-size:.7rem;color:var(--text-dim);
text-transform:uppercase;letter-spacing:.06em}
.info-val{font-family:var(--font-mono);font-size:.78rem;color:var(--text)}
.info-val.cyan{color:var(--cyan)}
.tab-panel{display:none;animation:panelIn .35s ease}
.tab-panel.active{display:block}
@keyframes panelIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.hidden{display:none!important}
.results-area{animation:panelIn .4s ease}
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}
"""

# ── JS served directly from Python ───────────────────────────────────────────
JS = r"""
"use strict";
let totalScans=0,confusionChart=null,gaugeChart=null,statsLoaded=false;
const $=id=>document.getElementById(id);
const emailInput=$('emailInput'),analyzeBtn=$('analyzeBtn'),clearBtn=$('clearBtn'),
  charCount=$('charCount'),resultsArea=$('resultsArea'),scanLoader=$('scanLoader'),
  urlInput=$('urlInput'),checkUrlBtn=$('checkUrlBtn'),linkResults=$('linkResults'),
  totalScansEl=$('totalScans'),historyList=$('historyList'),historyCount=$('historyCount');

document.querySelectorAll('.nav-item').forEach(btn=>{
  btn.addEventListener('click',()=>{
    const tab=btn.dataset.tab;
    document.querySelectorAll('.nav-item').forEach(b=>b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('tab-'+tab).classList.add('active');
    if(tab==='stats'&&!statsLoaded)loadStats();
  });
});

emailInput.addEventListener('input',()=>{
  const len=emailInput.value.length;
  charCount.textContent=len.toLocaleString()+' / 10,000';
  charCount.style.color=len>9000?'var(--red)':len>7000?'var(--amber)':'';
});

clearBtn.addEventListener('click',()=>{
  emailInput.value='';charCount.textContent='0 / 10,000';
  resultsArea.classList.add('hidden');scanLoader.classList.add('hidden');
});

analyzeBtn.addEventListener('click',runEmailScan);
emailInput.addEventListener('keydown',e=>{if(e.ctrlKey&&e.key==='Enter')runEmailScan();});

async function runEmailScan(){
  const text=emailInput.value.trim();
  if(!text){flashInput(emailInput);return;}
  analyzeBtn.disabled=true;
  resultsArea.classList.add('hidden');
  scanLoader.classList.remove('hidden');
  try{
    const res=await fetch('/predict',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({email_text:text})});
    const data=await res.json();
    if(data.error){showError(data.error);return;}
    totalScans++;totalScansEl.textContent=totalScans;
    renderVerdict(data);renderRiskScore(data.domain_risk);
    renderLinks(data.suspicious_links);renderKeywords(data.keyword_hits);
    updateHistory(data,text);
    scanLoader.classList.add('hidden');resultsArea.classList.remove('hidden');
  }catch(err){showError('Network error: '+err.message);}
  finally{analyzeBtn.disabled=false;scanLoader.classList.add('hidden');}
}

function renderVerdict(data){
  const card=document.querySelector('.verdict-card'),
    icon=$('verdictIcon'),text=$('verdictText'),
    conf=$('verdictConfidence'),meta=$('verdictMeta'),dot=$('verdictDot');
  const isSpam=data.prediction==='Spam';
  card.className='glass-card verdict-card '+(isSpam?'spam':'safe');
  dot.className='dot '+(isSpam?'red':'green');
  icon.textContent=isSpam?'⚠':'✔';
  text.textContent=data.prediction;
  conf.textContent=data.confidence?'Confidence: '+data.confidence+'%':'Rule-based classification';
  meta.innerHTML='Characters: '+data.char_count.toLocaleString()+'<br>URLs found: '+data.total_urls+'<br>Scanned at: '+data.timestamp;
}

function renderRiskScore(score){
  const label=$('riskScoreLabel'),fill=$('riskBarFill'),barText=$('riskBarText'),canvas=$('riskGauge');
  label.textContent=score;fill.style.width=score+'%';
  if(score>=60){fill.classList.add('high');barText.textContent='HIGH RISK';}
  else if(score>=30){fill.classList.remove('high');barText.textContent='Medium Risk';}
  else{fill.classList.remove('high');barText.textContent='Low Risk';}
  if(gaugeChart){gaugeChart.destroy();gaugeChart=null;}
  const color=score>=60?'#ff3b5c':score>=30?'#ffb300':'#00e676';
  gaugeChart=new Chart(canvas,{type:'doughnut',
    data:{datasets:[{data:[score,100-score],
      backgroundColor:[color,'rgba(255,255,255,0.04)'],
      borderWidth:0,circumference:180,rotation:270}]},
    options:{responsive:false,cutout:'72%',
      plugins:{legend:{display:false},tooltip:{enabled:false}},
      animation:{duration:900,easing:'easeOutQuart'}}});
}

function renderLinks(links){
  const list=$('linksList');$('urlCount').textContent=links.length;list.innerHTML='';
  if(!links.length){list.innerHTML='<div class="no-links">&#10003; No suspicious URLs detected</div>';return;}
  links.forEach(link=>{
    const div=document.createElement('div');div.className='link-item';
    const flags=link.flags.map(f=>'<span class="link-flag-tag">'+esc(f)+'</span>').join('');
    div.innerHTML='<div class="link-url">'+esc(link.url)+'</div>'
      +'<div class="link-domain">'+esc(link.domain)+'</div>'
      +'<div style="display:flex;justify-content:space-between;align-items:center;margin-top:4px">'
      +'<div class="link-flags">'+flags+'</div>'
      +'<span class="link-risk-score">Risk: '+link.risk+'/100</span></div>';
    list.appendChild(div);
  });
}

function renderKeywords(keywords){
  const wrap=$('keywordsWrap');wrap.innerHTML='';
  if(!keywords||!keywords.length){wrap.innerHTML='<span class="no-keywords">None detected</span>';return;}
  keywords.map(k=>k.replace(/\\b/g,'').replace(/\\/g,'')).forEach(kw=>{
    const span=document.createElement('span');span.className='keyword-tag';span.textContent=kw;wrap.appendChild(span);
  });
}

function updateHistory(data,text){
  const preview=text.replace(/\s+/g,' ').trim().substring(0,55)+(text.length>55?'\u2026':'');
  const item=document.createElement('div');item.className='history-item';
  const cls=data.prediction==='Spam'?'spam':'safe';
  item.innerHTML='<div class="h-preview">'+esc(preview)+'</div>'
    +'<div class="h-meta"><span class="h-verdict '+cls+'">'+data.prediction+'</span>'
    +'<span class="h-time">'+data.timestamp+'</span></div>';
  const empty=historyList.querySelector('.history-empty');if(empty)empty.remove();
  historyList.prepend(item);
  while(historyList.children.length>10)historyList.lastChild.remove();
  historyCount.textContent=historyList.children.length;
}

checkUrlBtn.addEventListener('click',runLinkCheck);
urlInput.addEventListener('keydown',e=>{if(e.key==='Enter')runLinkCheck();});

async function runLinkCheck(){
  const url=urlInput.value.trim();if(!url){flashInput(urlInput);return;}
  checkUrlBtn.disabled=true;checkUrlBtn.textContent='Checking\u2026';
  linkResults.classList.add('hidden');
  try{
    const res=await fetch('/check-link',{method:'POST',
      headers:{'Content-Type':'application/json'},body:JSON.stringify({url})});
    const data=await res.json();
    if(data.error){showError(data.error);return;}
    renderLinkResult(data);linkResults.classList.remove('hidden');
  }catch(err){showError('Network error: '+err.message);}
  finally{checkUrlBtn.disabled=false;checkUrlBtn.innerHTML='<span class="btn-icon">\u26a1</span> Check Link';}
}

function renderLinkResult(data){
  const badge=$('linkVerdictBadge'),domain=$('linkDomainText'),
    risk=$('linkRiskVal'),flag=$('linkFlagVal'),status=$('linkStatusVal'),
    fill=$('linkRiskFill'),flagSec=$('flagsSection'),flagList=$('flagsList');
  const isDanger=data.domain_flag||!data.safe;
  badge.textContent=isDanger?'\u26a0 HIGH RISK':'\u2714 SAFE';
  badge.className='link-verdict-badge '+(isDanger?'danger':'safe');
  domain.textContent=data.domain;
  risk.textContent=data.risk+' / 100';
  risk.style.color=data.risk>=60?'var(--red)':data.risk>=30?'var(--amber)':'var(--green)';
  flag.textContent=data.domain_flag?'\u2691 Flagged':'\u2014';
  flag.style.color=data.domain_flag?'var(--red)':'var(--green)';
  status.textContent=data.safe?'Likely Safe':'Suspicious';
  status.style.color=data.safe?'var(--green)':'var(--red)';
  fill.style.width=data.risk+'%';
  fill.className='risk-bar-fill'+(data.risk>=60?' high':'');
  if(data.flags&&data.flags.length){
    flagSec.style.display='block';
    flagList.innerHTML=data.flags.map(f=>'<li>'+esc(f)+'</li>').join('');
  }else{flagSec.style.display='none';}
}

async function loadStats(){
  try{
    const res=await fetch('/stats'),data=await res.json();
    animateMetric('statAccuracy',data.accuracy,'barAccuracy');
    animateMetric('statPrecision',data.precision,'barPrecision');
    animateMetric('statRecall',data.recall,'barRecall');
    animateMetric('statF1',data.f1_score,'barF1');
    $('modelType').textContent=data.model_type;
    $('trainSamples').textContent=data.training_samples.toLocaleString();
    renderConfusionMatrix(data.confusion_matrix);statsLoaded=true;
  }catch(err){console.error('Stats load failed:',err);}
}

function animateMetric(valId,pct,barId){
  const el=$(valId),bar=$(barId);if(!el)return;
  let current=0;
  const step=()=>{current=Math.min(current+1.2,pct);
    el.textContent=current.toFixed(1)+'%';bar.style.width=current+'%';
    if(current<pct)requestAnimationFrame(step);};
  requestAnimationFrame(step);
}

function renderConfusionMatrix(cm){
  const canvas=$('confusionMatrix');if(!canvas)return;
  if(confusionChart){confusionChart.destroy();confusionChart=null;}
  const{tn,fp,fn,tp}=cm;
  confusionChart=new Chart(canvas,{type:'bar',
    data:{labels:['True Negative','False Positive','False Negative','True Positive'],
      datasets:[{label:'Count',data:[tn,fp,fn,tp],
        backgroundColor:['rgba(0,230,118,0.5)','rgba(255,59,92,0.5)','rgba(255,179,0,0.5)','rgba(0,245,255,0.5)'],
        borderColor:['rgba(0,230,118,0.9)','rgba(255,59,92,0.9)','rgba(255,179,0,0.9)','rgba(0,245,255,0.9)'],
        borderWidth:1,borderRadius:6}]},
    options:{responsive:true,maintainAspectRatio:false,
      animation:{duration:1200,easing:'easeOutQuart'},
      plugins:{legend:{display:false},
        tooltip:{backgroundColor:'rgba(2,15,28,0.95)',borderColor:'rgba(0,245,255,0.2)',
          borderWidth:1,titleColor:'#00f5ff',bodyColor:'#c8d8e4',padding:12}},
      scales:{x:{grid:{color:'rgba(0,245,255,0.04)'},ticks:{color:'#526577',font:{family:"'Share Tech Mono'",size:11}}},
        y:{grid:{color:'rgba(0,245,255,0.04)'},ticks:{color:'#526577',font:{family:"'Share Tech Mono'",size:11}}}}}});
}

function esc(str){return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function flashInput(el){
  el.style.borderColor='var(--red)';el.style.boxShadow='0 0 0 3px rgba(255,59,92,0.15)';
  setTimeout(()=>{el.style.borderColor='';el.style.boxShadow='';},1000);
}

function showError(msg){
  scanLoader.classList.add('hidden');
  const toast=document.createElement('div');
  toast.style.cssText='position:fixed;bottom:28px;right:28px;z-index:999;'+
    'background:rgba(255,59,92,0.12);border:1px solid rgba(255,59,92,0.35);'+
    'color:var(--red);font-family:var(--font-mono);font-size:0.78rem;'+
    'padding:12px 20px;border-radius:8px;max-width:340px;line-height:1.5;';
  toast.textContent='\u26a0 '+msg;document.body.appendChild(toast);
  setTimeout(()=>toast.remove(),4000);
}

const DEMO=`Subject: URGENT: Your account will be suspended!\n\nDear Customer,\n\nCongratulations! You have been selected as a winner of our $1,000,000 lottery!\nClick here to claim your free prize immediately: http://bit.ly/win-now\nVerify your bank account at: http://paypal-security.tk/verify\n\nAct now - limited time offer! No credit card required.\nYour social security details are needed to process the claim.\n\nBest regards,\nThe Prize Team`;
emailInput.value=DEMO;
charCount.textContent=DEMO.length.toLocaleString()+' / 10,000';
"""

# ── HTML served directly from Python ─────────────────────────────────────────
HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>ScamShield AI</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;700;900&display=swap" rel="stylesheet"/>
<link rel="stylesheet" href="/app.css"/>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
</head>
<body>
<div class="bg-grid"></div>
<div class="scan-line"></div>
<aside class="sidebar">
  <div class="logo-block">
    <div class="logo-icon">
      <svg width="36" height="36" viewBox="0 0 36 36" fill="none">
        <polygon points="18,2 34,10 34,26 18,34 2,26 2,10" stroke="#00f5ff" stroke-width="1.5" fill="none"/>
        <polygon points="18,7 29,12.5 29,23.5 18,29 7,23.5 7,12.5" stroke="#00f5ff" stroke-width="1" fill="rgba(0,245,255,0.05)"/>
        <path d="M18 12 L18 18 L22 22" stroke="#00f5ff" stroke-width="2" stroke-linecap="round"/>
        <circle cx="18" cy="18" r="2" fill="#00f5ff"/>
      </svg>
    </div>
    <div>
      <div class="logo-text">ScamShield</div>
      <div class="logo-sub">AI &middot; v2.4.1</div>
    </div>
  </div>
  <div class="status-badge"><span class="pulse-dot"></span><span>System Online</span></div>
  <nav class="nav">
    <button class="nav-item active" data-tab="scanner">
      <span class="nav-icon">&#x2B21;</span><span>Email Scanner</span><span class="nav-arrow">&rsaquo;</span>
    </button>
    <button class="nav-item" data-tab="linktester">
      <span class="nav-icon">&#x2B21;</span><span>Link Tester</span><span class="nav-arrow">&rsaquo;</span>
    </button>
    <button class="nav-item" data-tab="stats">
      <span class="nav-icon">&#x2B21;</span><span>Model Stats</span><span class="nav-arrow">&rsaquo;</span>
    </button>
  </nav>
  <div class="sidebar-footer">
    <div class="history-label"><span>Scan History</span><span class="history-count" id="historyCount">0</span></div>
    <div class="history-list" id="historyList"><div class="history-empty">No scans yet</div></div>
  </div>
</aside>
<main class="main">
  <section class="tab-panel active" id="tab-scanner">
    <div class="panel-header">
      <div>
        <h1 class="panel-title">Email Threat Scanner</h1>
        <p class="panel-sub">Paste a suspicious email to analyze it for phishing, spam signals &amp; malicious links.</p>
      </div>
      <div class="threat-counter"><span id="totalScans">0</span><span class="threat-label">Total Scans</span></div>
    </div>
    <div class="glass-card input-card">
      <div class="card-label"><span class="dot cyan"></span>INPUT &middot; EMAIL CONTENT</div>
      <textarea id="emailInput" class="email-textarea" placeholder="Paste email content here..."></textarea>
      <div class="input-actions">
        <span class="char-count" id="charCount">0 / 10,000</span>
        <button class="btn-ghost" id="clearBtn">Clear</button>
        <button class="btn-primary" id="analyzeBtn"><span class="btn-icon">&#9654;</span>Analyze Threat</button>
      </div>
    </div>
    <div id="resultsArea" class="results-area hidden">
      <div class="results-grid">
        <div class="glass-card verdict-card" id="verdictCard">
          <div class="card-label"><span class="dot" id="verdictDot"></span>THREAT VERDICT</div>
          <div class="verdict-main">
            <div class="verdict-icon" id="verdictIcon">&#9689;</div>
            <div class="verdict-text" id="verdictText">&mdash;</div>
          </div>
          <div class="verdict-confidence" id="verdictConfidence"></div>
          <div class="verdict-meta" id="verdictMeta"></div>
        </div>
        <div class="glass-card risk-card">
          <div class="card-label"><span class="dot amber"></span>DOMAIN RISK SCORE</div>
          <div class="risk-gauge-wrap">
            <canvas id="riskGauge" width="160" height="90"></canvas>
            <div class="risk-score-label" id="riskScoreLabel">0</div>
          </div>
          <div class="risk-bar-wrap">
            <div class="risk-bar-track"><div class="risk-bar-fill" id="riskBarFill" style="width:0%"></div></div>
            <span class="risk-bar-text" id="riskBarText">Low Risk</span>
          </div>
        </div>
        <div class="glass-card urls-card">
          <div class="card-label"><span class="dot red"></span>SUSPICIOUS LINKS &middot; <span id="urlCount">0</span> found</div>
          <div class="links-list" id="linksList"><div class="no-links">No suspicious URLs detected</div></div>
        </div>
        <div class="glass-card keywords-card">
          <div class="card-label"><span class="dot purple"></span>SPAM KEYWORDS DETECTED</div>
          <div class="keywords-wrap" id="keywordsWrap"><span class="no-keywords">None detected</span></div>
        </div>
      </div>
    </div>
    <div id="scanLoader" class="scan-loader hidden">
      <div class="loader-ring"></div>
      <div class="loader-text">Scanning threat vectors<span class="dots"></span></div>
    </div>
  </section>

  <section class="tab-panel" id="tab-linktester">
    <div class="panel-header">
      <div>
        <h1 class="panel-title">Link Threat Tester</h1>
        <p class="panel-sub">Enter any URL to check its domain reputation, phishing signals &amp; risk score.</p>
      </div>
    </div>
    <div class="glass-card input-card" style="max-width:680px">
      <div class="card-label"><span class="dot cyan"></span>URL INPUT</div>
      <div class="url-input-row">
        <input type="text" id="urlInput" class="url-input" placeholder="https://suspicious-domain.tk/phish"/>
        <button class="btn-primary" id="checkUrlBtn"><span class="btn-icon">&#9889;</span>Check Link</button>
      </div>
    </div>
    <div id="linkResults" class="link-results hidden">
      <div class="glass-card link-result-card">
        <div class="link-result-header">
          <div class="link-verdict-badge" id="linkVerdictBadge">&mdash;</div>
          <div class="link-domain-text" id="linkDomainText">&mdash;</div>
        </div>
        <div class="link-detail-grid">
          <div class="link-detail-item"><span class="link-detail-label">Risk Score</span><span class="link-detail-val" id="linkRiskVal">&mdash;</span></div>
          <div class="link-detail-item"><span class="link-detail-label">Domain Flag</span><span class="link-detail-val" id="linkFlagVal">&mdash;</span></div>
          <div class="link-detail-item"><span class="link-detail-label">Status</span><span class="link-detail-val" id="linkStatusVal">&mdash;</span></div>
        </div>
        <div class="flags-section" id="flagsSection" style="display:none">
          <div class="card-label" style="margin-top:1rem"><span class="dot red"></span>THREAT FLAGS</div>
          <ul class="flags-list" id="flagsList"></ul>
        </div>
        <div class="link-risk-bar-wrap">
          <div class="risk-bar-track"><div class="risk-bar-fill" id="linkRiskFill" style="width:0%"></div></div>
        </div>
      </div>
    </div>
  </section>

  <section class="tab-panel" id="tab-stats">
    <div class="panel-header">
      <div>
        <h1 class="panel-title">Model Intelligence Report</h1>
        <p class="panel-sub">Performance metrics for the deployed ML classification model.</p>
      </div>
    </div>
    <div class="stats-grid">
      <div class="glass-card metric-card"><div class="metric-icon">&#9678;</div><div class="metric-val" id="statAccuracy">&mdash;</div><div class="metric-label">Accuracy</div><div class="metric-bar"><div class="metric-bar-fill" id="barAccuracy"></div></div></div>
      <div class="glass-card metric-card"><div class="metric-icon">&#9672;</div><div class="metric-val" id="statPrecision">&mdash;</div><div class="metric-label">Precision</div><div class="metric-bar"><div class="metric-bar-fill" id="barPrecision"></div></div></div>
      <div class="glass-card metric-card"><div class="metric-icon">&#9680;</div><div class="metric-val" id="statRecall">&mdash;</div><div class="metric-label">Recall</div><div class="metric-bar"><div class="metric-bar-fill" id="barRecall"></div></div></div>
      <div class="glass-card metric-card"><div class="metric-icon">&#9681;</div><div class="metric-val" id="statF1">&mdash;</div><div class="metric-label">F1 Score</div><div class="metric-bar"><div class="metric-bar-fill" id="barF1"></div></div></div>
    </div>
    <div class="stats-bottom-grid">
      <div class="glass-card cm-card">
        <div class="card-label"><span class="dot cyan"></span>CONFUSION MATRIX</div>
        <div class="cm-chart-wrap"><canvas id="confusionMatrix"></canvas></div>
      </div>
      <div class="glass-card model-info-card">
        <div class="card-label"><span class="dot purple"></span>MODEL DETAILS</div>
        <div class="model-info-list">
          <div class="info-row"><span class="info-label">Algorithm</span><span class="info-val" id="modelType">&mdash;</span></div>
          <div class="info-row"><span class="info-label">Training Samples</span><span class="info-val" id="trainSamples">&mdash;</span></div>
          <div class="info-row"><span class="info-label">Feature Extraction</span><span class="info-val">TF-IDF Vectorizer</span></div>
          <div class="info-row"><span class="info-label">Classes</span><span class="info-val">Spam / Not Spam</span></div>
          <div class="info-row"><span class="info-label">Deployment</span><span class="info-val cyan">Active &middot; Render</span></div>
        </div>
      </div>
    </div>
  </section>
</main>
<script src="/app.js"></script>
</body>
</html>"""

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return Response(HTML, mimetype="text/html")

@app.route("/app.css")
def serve_css():
    return Response(CSS, mimetype="text/css")

@app.route("/app.js")
def serve_js():
    return Response(JS, mimetype="application/javascript")

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json(force=True)
        email_text = data.get("email_text", "").strip()
        if not email_text:
            return jsonify({"error": "No email text provided."}), 400
        if len(email_text) > 10000:
            return jsonify({"error": "Input too long (max 10,000 chars)."}), 400
        prediction, confidence = ml_predict(email_text)
        urls, suspicious_links, domain_risk, keyword_hits = analyze_email_text(email_text)
        result = {
            "prediction": prediction,
            "confidence": round(confidence, 1) if confidence else None,
            "suspicious_links": suspicious_links,
            "domain_risk": domain_risk,
            "domain_flag": domain_risk >= 40,
            "keyword_hits": keyword_hits[:8],
            "total_urls": len(urls),
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "char_count": len(email_text),
        }
        scan_history.insert(0, {"prediction": prediction, "domain_risk": domain_risk,
            "timestamp": result["timestamp"],
            "preview": email_text[:60] + ("..." if len(email_text) > 60 else "")})
        if len(scan_history) > 10: scan_history.pop()
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500

@app.route("/check-link", methods=["POST"])
def check_link():
    try:
        data = request.get_json(force=True)
        url = data.get("url", "").strip()
        if not url: return jsonify({"error": "No URL provided."}), 400
        if not url.startswith(("http://", "https://")): url = "https://" + url
        domain = get_domain(url)
        risk, flags = check_domain_risk(domain)
        return jsonify({"url": url, "domain": domain, "risk": risk,
                        "domain_flag": risk >= 40, "flags": flags, "safe": risk < 20})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/history")
def history():
    return jsonify(scan_history)

@app.route("/stats")
def stats():
    stats_path = os.path.join(BASE_DIR, "stats.json")
    if os.path.exists(stats_path):
        with open(stats_path) as f:
            data = json.load(f)
        if model:
            data["model_type"] = type(model).__name__
        return jsonify(data)
    else:
        return jsonify({
            "accuracy": 0, "precision": 0, "recall": 0, "f1_score": 0,
            "model_type": "Not trained yet — run Train_Model.py",
            "training_samples": 0, "total_samples": 0,
            "note": "Run Train_Model.py to generate real statistics.",
            "confusion_matrix": {"tn": 0, "fp": 0, "fn": 0, "tp": 0}
        })

# ── Run ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n{'='*50}")
    print(f"  ScamShield AI starting on http://127.0.0.1:{port}")
    print(f"  Model loaded: {model is not None}")
    print(f"  No templates/ or static/ folders needed.")
    print(f"{'='*50}\n")
    app.run(host="0.0.0.0", port=port, debug=True)
