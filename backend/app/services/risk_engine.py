"""
Block Bord AI — Risk Engine (Modular)
Core heuristic rules and URL analysis logic.
Refactored from the monolith risk_engine.py.
"""
import re
import math
import ssl
import socket
import hashlib
import os
import contextlib
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse, unquote, parse_qs

logger = logging.getLogger("blockbord.risk_engine")

# ──────────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────────
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
    "rebrand.ly", "shorturl.at", "ow.ly", "buff.ly", "rb.gy", "s.id",
    "lnkd.in", "trib.al", "v.gd", "tiny.cc", "clck.ru", "qr.net"
}

SUSPICIOUS_TLDS = {
    '.top', '.xyz', '.club', '.best', '.monster', '.accountant',
    '.click', '.download', '.loan', '.win', '.gq', '.cf', '.ga', '.ml',
    '.tk', '.work', '.stream', '.trade', '.racing', '.review', '.bid'
}

SUSPICIOUS_FILE_EXTS = {
    '.exe', '.apk', '.scr', '.bat', '.cmd', '.vbs', '.js', '.jar',
    '.zip', '.rar', '.msi', '.pif', '.com', '.dmg', '.ps1'
}

KNOWN_BRANDS = {
    "google": "google.com",
    "facebook": "facebook.com",
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "netflix": "netflix.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "twitter": "twitter.com",
    "youtube": "youtube.com",
    "linkedin": "linkedin.com",
    "sbi": "sbi.co.in",
    "hdfc": "hdfcbank.com",
    "icici": "icicibank.com",
    "axis": "axisbank.com",
    "paytm": "paytm.com",
    "phonepe": "phonepe.com",
    "gpay": "pay.google.com",
    "upi": "npci.org.in",
    "github": "github.com",
    "render": "render.com",
}

MEGA_TRUSTED_DOMAINS = {
    "google.com", "google.co.in", "github.com", "microsoft.com",
    "apple.com", "netflix.com", "amazon.com", "amazon.in",
    "play.google.com", "apps.apple.com", "youtube.com", "linkedin.com"
}

URGENCY_MANIPULATION = {
    "urgent", "immediately", "today", "now", "asap", "expires", "final",
    "last chance", "act now", "limited time", "hurry", "deadline", "account suspended"
}
ACTION_WORDS = {
    "click", "open", "verify", "update", "login", "claim", "redeem",
    "submit", "confirm", "link", "download", "install"
}
SCAM_LURE_WORDS = {
    "reward", "cashback", "prize", "winner", "congratulations", "bonus", "offer",
    "free recharge", "loan", "credit", "pre-approved", "limit increased",
    "investment", "profit", "earn", "work from home", "lucky draw",
    "selected", "gift card", "voucher"
}
PHISHING_KEYWORDS = {
    "login", "verify", "secure", "bank", "free", "claim", "reward",
    "account", "update", "suspended", "password", "service", "support",
    "billing", "invoice", "mailbox", "unusual activity", "locked",
    "otp", "credentials", "ssn", "social security", "card number",
    "cvv", "ifsc", "aadhaar"
}
UPI_SCAM_WORDS = {"collect request", "request money", "qr", "refund", "upi", "upi://pay"}

URL_REGEX = r"(https?://\S+|www\.\S+|\b[a-z0-9.-]+\.[a-z]{2,}(?:/\S*)?)"

# ──────────────────────────────────────────────────────────────
# UTILS
# ──────────────────────────────────────────────────────────────
def _build_word_pattern(words):
    sorted_words = sorted(words, key=len, reverse=True)
    return re.compile(r'\b(?:' + '|'.join(map(re.escape, sorted_words)) + r')\b', re.IGNORECASE)

URGENT_RE = _build_word_pattern(URGENCY_MANIPULATION)
ACTION_RE = _build_word_pattern(ACTION_WORDS)
SCAM_LURE_RE = _build_word_pattern(SCAM_LURE_WORDS)
PHISHING_KEYWORDS_RE = _build_word_pattern(PHISHING_KEYWORDS)
UPI_SCAM_RE = _build_word_pattern(UPI_SCAM_WORDS - {"upi://pay"})

def _extract_domains(text: str):
    urls = re.findall(URL_REGEX, text.lower())
    domains = []
    for u in urls:
        uu = u
        if uu.startswith("www."): uu = "http://" + uu
        if "://" not in uu: uu = "http://" + uu
        try:
            d = urlparse(uu).netloc.lower().split(":")[0]
            if d: domains.append(d)
        except: continue
    return urls, domains

def _get_root_domain(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) >= 2: return ".".join(parts[-2:])
    return domain

def _url_entropy(url: str) -> float:
    if not url: return 0.0
    url = url.lower()
    freq = {}
    for c in url: freq[c] = freq.get(c, 0) + 1
    total = len(url)
    return round(-sum((count / total) * math.log2(count / total) for count in freq.values()), 2)

@contextlib.contextmanager
def suppress_output():
    with open(os.devnull, 'w') as devnull:
        with contextlib.redirect_stdout(devnull), contextlib.redirect_stderr(devnull):
            yield

# ──────────────────────────────────────────────────────────────
# ANALYSIS COMPONENTS
# ──────────────────────────────────────────────────────────────
def analyze_url_structure(url: str):
    score = 0
    checks = []
    if unquote(url) != url:
        score += 15
        checks.append("URL contains encoded/obfuscated characters.")
    entropy = _url_entropy(url)
    if entropy > 4.2:
        score += 15
        checks.append(f"High URL entropy ({entropy}) — suspicious randomness.")
    if any(url.lower().endswith(ext) for ext in SUSPICIOUS_FILE_EXTS):
        score += 25
        checks.append("URL points to a potentially dangerous file type.")
    return score, checks

def analyze_domain_structure(domain: str):
    score = 0
    checks = []
    parts = domain.split('.')
    is_ip = len(parts) == 4 and all(p.isdigit() for p in parts)
    if len(parts) > 3 and not is_ip:
        score += 15
        checks.append("Excessive subdomains detected.")
    if any(p.startswith('xn--') for p in parts):
        score += 30
        checks.append("Punycode/Homograph domain detected.")
    if domain.count('-') >= 2:
        score += 10
        checks.append("Multiple hyphens in domain.")
    if is_ip:
        score += 15
        checks.append("URL uses a raw IP address.")
    return score, checks

def check_ssl_certificate(domain: str):
    score = 0
    checks = []
    if domain in ('localhost', '127.0.0.1'): return 0, []
    try:
        with suppress_output():
            conn = socket.create_connection((domain, 443), timeout=2)
            conn.close()
    except:
        score += 15
        checks.append("Website does not support a secure HTTPS connection.")
    return score, checks

# ──────────────────────────────────────────────────────────────
# MASTER CALCULATOR (3-Layer Detection Engine)
# ──────────────────────────────────────────────────────────────
async def calculate_risk(text: str, url: str = None, **kwargs):
    """
    3-Layer Detection Engine:
    Layer 1: Google Safe Browsing (Instant flag)
    Layer 2: XGBoost ML (Probabilistic)
    Layer 3: Heuristic Rules (Structural/Lexical)
    """
    raw = (text or "").strip()
    low = raw.lower()
    url = url or ""
    
    # 0. Trusted Domain Check (Bypass)
    if url:
        try:
            d = urlparse(url if "://" in url else "http://" + url).netloc.lower().split(":")[0]
            if _get_root_domain(d) in MEGA_TRUSTED_DOMAINS:
                return {"risk_score": 0, "risk_level": "OK", "reasons": ["Trusted official domain."], "category": "Safe"}
        except: pass

    # Initialize components
    reasons = []
    
    # --- LAYER 1: GOOGLE SAFE BROWSING (30% weight or total override) ---
    # In a real setup, if Safe Browsing flags it, we often jump to high risk immediately.
    from backend.app.services.safe_browsing import safe_browsing
    is_sb_malicious = await safe_browsing.check_url(url) if url else False
    sb_score = 100 if is_sb_malicious else 0
    if is_sb_malicious:
        reasons.append("Flagged by Google Safe Browsing as potentially dangerous.")

    # --- LAYER 2: XGBOOST ML ENGINE (40% weight) ---
    from backend.app.services.ml_engine import ml_engine
    ml_prob = ml_engine.predict(url) if url else 0.0
    ml_score = ml_prob * 100
    if ml_prob > 0.7:
        reasons.append(f"AI Detection: Highly suspicious pattern detected (Confidence: {ml_prob:.2f}).")
    elif ml_prob > 0.4:
        reasons.append(f"AI Detection: Moderate suspicion score ({ml_prob:.2f}).")

    # --- LAYER 3: HEURISTIC ENGINE (30% weight) ---
    heuristic_score = 0
    # Money bait
    if re.search(r"rs\.?\s?\d+|₹\s?\d+", low):
        heuristic_score += 25
        reasons.append("Money bait detected.")
    
    # UPI Scam
    if "upi://pay" in low or UPI_SCAM_RE.search(low):
        heuristic_score += 45
        reasons.append("UPI scam pattern detected.")

    # Phishing Keywords
    phishing_hits = set(PHISHING_KEYWORDS_RE.findall(low))
    if phishing_hits:
        heuristic_score += min(30, 10 + 5 * len(phishing_hits))
        reasons.append(f"Phishing indicators: {', '.join(phishing_hits)}.")

    # Urgency
    if URGENT_RE.search(low) and ACTION_RE.search(low):
        heuristic_score += 20
        reasons.append("Urgency + Action combo (high risk).")

    # Structural Checks
    urls, domains = _extract_domains(low)
    if url: urls.insert(0, url)
    
    for u in urls[:2]:
        s, c = analyze_url_structure(u)
        heuristic_score += s
        reasons.extend(c)
        if any(sd in URL_SHORTENERS for sd in domains):
            heuristic_score += 25
            reasons.append("URL shortener used to hide destination.")

    for d in domains[:2]:
        s, c = analyze_domain_structure(d)
        heuristic_score += s
        reasons.extend(c)
        s, c = check_ssl_certificate(d)
        heuristic_score += s
        reasons.extend(c)

    if re.search(r'\bpassword\b|\botp\b|\bupi pin\b', low):
        heuristic_score += 30
        reasons.append("Page requests highly sensitive credentials.")

    heuristic_score = min(100, heuristic_score)

    # ──────────────────────────────────────────────────────────────
    # FINAL WEIGHTED BLEND
    # ──────────────────────────────────────────────────────────────
    # If Safe Browsing is positive, it's an automatic High Risk (min 85)
    # Otherwise: 0.5 * ML + 0.5 * Heuristics
    if is_sb_malicious:
        final_score = max(85, (0.4 * ml_score) + (0.3 * heuristic_score) + 30)
    else:
        final_score = (0.5 * ml_score) + (0.5 * heuristic_score)

    final_score = min(100, round(final_score, 1))
    
    if final_score >= 75: level = "High"
    elif final_score >= 40: level = "Suspicious"
    else: level = "OK"

    return {
        "risk_score": final_score,
        "risk_level": level,
        "reasons": list(dict.fromkeys(reasons)), # deduplicate preserving order
        "category": "ML + Heuristic Hybrid" if final_score > 10 else "General"
    }
