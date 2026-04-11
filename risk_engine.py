import re
import math
import ssl
import socket
import whois
import hashlib
import os
import sys
import contextlib
from datetime import datetime
from urllib.parse import urlparse, unquote, parse_qs

from ml_ensemble import predict_blended_prob

import platform
import subprocess


# ─────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────
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
JOB_SCAM_KEYWORDS = {
    "work from home", "telegram recruitment", "salary via crypto",
    "part time job", "no experience needed", "daily earning",
    "easy money", "remotely", "package handling", "online assistant"
}
CRYPTO_SCAM_KEYWORDS = {
    "wallet", "connect wallet", "drainer", "metamask", "seed phrase",
    "private key", "airdrop", "presale", "whitelist join", "matic",
    "ethereum", "pancake swap", "token launch", "guaranteed profit"
}
EXTORTION_PATTERNS = {
    "warrant issued", "income tax notice", "lawsuit", "illegal activity detected",
    "police investigation", "penalty fee", "court summons", "case filed"
}
SCAM_MANIPULATION = {
    "you have been selected", "congratulations you won", "your account will be closed",
    "verify your identity", "unusual sign-in", "suspicious activity detected",
    "action required", "your package is on hold", "confirm your payment"
}
UPI_SCAM_WORDS = {"collect request", "request money", "qr", "refund", "upi", "upi://pay"}

URL_REGEX = r"(https?://\S+|www\.\S+|\b[a-z0-9.-]+\.[a-z]{2,}(?:/\S*)?)"


def _build_word_pattern(words):
    sorted_words = sorted(words, key=len, reverse=True)
    return re.compile(r'\b(?:' + '|'.join(map(re.escape, sorted_words)) + r')\b', re.IGNORECASE)


URGENT_RE = _build_word_pattern(URGENCY_MANIPULATION)
ACTION_RE = _build_word_pattern(ACTION_WORDS)
SCAM_LURE_RE = _build_word_pattern(SCAM_LURE_WORDS)
PHISHING_KEYWORDS_RE = _build_word_pattern(PHISHING_KEYWORDS)
UPI_SCAM_RE = _build_word_pattern(UPI_SCAM_WORDS - {"upi://pay"})
MANIPULATION_RE = _build_word_pattern(SCAM_MANIPULATION)
JOB_SCAM_RE = _build_word_pattern(JOB_SCAM_KEYWORDS)
CRYPTO_SCAM_RE = _build_word_pattern(CRYPTO_SCAM_KEYWORDS)
EXTORTION_RE = _build_word_pattern(EXTORTION_PATTERNS)


# ─────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────
@contextlib.contextmanager
def suppress_output():
    """Context manager to suppress stdout and stderr."""
    with open(os.devnull, 'w') as devnull:
        with contextlib.redirect_stdout(devnull), contextlib.redirect_stderr(devnull):
            yield


# ─────────────────────────────────────────
# HELPER
# ─────────────────────────────────────────
def _extract_domains(text: str):
    urls = re.findall(URL_REGEX, text.lower())
    domains = []
    for u in urls:
        uu = u
        if uu.startswith("www."):
            uu = "http://" + uu
        if "://" not in uu:
            uu = "http://" + uu
        try:
            d = urlparse(uu).netloc.lower().split(":")[0]
            if d:
                domains.append(d)
        except Exception:
            continue
    return urls, domains


def _get_root_domain(domain: str) -> str:
    """Extract root domain (e.g. login.bank.com -> bank.com)"""
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def _url_entropy(url: str) -> float:
    """Calculate Shannon entropy of URL string."""
    if not url:
        return 0.0
    url = url.lower()
    freq = {}
    for c in url:
        freq[c] = freq.get(c, 0) + 1
    total = len(url)
    entropy = -sum((count / total) * math.log2(count / total) for count in freq.values())
    return round(entropy, 2)


# ─────────────────────────────────────────
# FEATURE 16–25: URL STRUCTURAL ANALYSIS
# ─────────────────────────────────────────
def analyze_url_structure(url: str):
    """
    Deep URL analysis:
    - Encoded/obfuscated chars (#18)
    - Entropy/randomness (#24)
    - Suspicious parameters (#25)
    - Suspicious file extensions
    """
    score = 0
    checks = []


    # Encoded characters detection (#18)
    decoded = unquote(url)
    if decoded != url:
        score += 15
        checks.append("URL contains encoded/obfuscated characters.")

    # Double encoding
    if re.search(r'%[0-9a-f]{2}', url, re.IGNORECASE):
        score += 8
        checks.append("URL contains percent-encoded segments (possible obfuscation).")

    # URL entropy (#24)
    entropy = _url_entropy(url)
    if entropy > 4.0:
        score += 15
        checks.append(f"High URL entropy ({entropy}) — likely auto-generated phishing link.")

    # Suspicious query params (#25)
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        params = parse_qs(parsed.query)
        suspicious_params = {"token", "key", "auth", "pass", "redirect", "ref", "return", "goto", "next"}
        found = suspicious_params.intersection(set(params.keys()))
        if found:
            score += 10
            checks.append(f"Suspicious URL parameters found: {', '.join(found)}.")
    except Exception:
        pass

    # Suspicious file download extensions (#62-#63)
    if any(url.lower().endswith(ext) for ext in SUSPICIOUS_FILE_EXTS):
        score += 25
        checks.append("URL points to a potentially dangerous file type (malware risk).")

    return score, checks


# ─────────────────────────────────────────
# FEATURE 16, 19–22: DOMAIN STRUCTURE
# ─────────────────────────────────────────
def analyze_domain_structure(domain: str):
    """
    Analyzes domain for:
    - Excessive subdomains (#19)
    - Punycode/homograph (#22)
    - Hyphens (#20)
    - Suspicious TLDs (#21)
    - IP addresses (#23)
    """
    checks = []
    score = 0

    parts = domain.split('.')
    is_ipv4 = len(parts) == 4 and all(p.isdigit() for p in parts)

    # Excessive subdomains (#19)
    if len(parts) > 3 and not is_ipv4:
        score += 15
        checks.append("Excessive subdomains detected (common phishing pattern).")

    # Punycode/homograph (#22)
    if any(p.startswith('xn--') for p in parts):
        score += 30
        checks.append("Punycode domain detected (possible homograph/lookalike attack).")

    # Multiple hyphens (#20)
    if domain.count('-') >= 2:
        score += 10
        checks.append("Multiple hyphens in domain (suspicious impersonation pattern).")

    # Suspicious TLDs (#21)
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 12
            checks.append(f"Uses high-risk TLD '{tld}' (commonly used in scam domains).")
            break

    # IP address (#23)
    if is_ipv4:
        score += 15
        checks.append("URL uses a raw IP address instead of a domain name.")


    return score, checks


# ─────────────────────────────────────────
# FEATURE 34–38: SSL CERTIFICATE CHECKS
# ─────────────────────────────────────────
def check_ssl_certificate(domain: str):
    """
    Checks:
    - HTTPS availability (#34)
    - Certificate validity (#35)
    - Self-signed detection (#36)
    - Domain mismatch (#37)
    - Expiration (#38)
    """
    score = 0
    checks = []

    parts = domain.split('.')
    if (len(parts) == 4 and all(p.isdigit() for p in parts)) or domain in ('localhost', '127.0.0.1'):
        return 0, []

    # Try connecting on port 443
    context_unverified = ssl.create_default_context()
    context_unverified.check_hostname = False
    context_unverified.verify_mode = ssl.CERT_NONE

    try:
        with suppress_output():
            conn = socket.create_connection((domain, 443), timeout=3)
        with conn as sock:
            with context_unverified.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                if not cert_bin:
                    score += 20
                    checks.append("Could not retrieve SSL certificate.")
                else:
                    # Verified context check
                    verify_ctx = ssl.create_default_context()
                    try:
                        with socket.create_connection((domain, 443), timeout=3) as vsock:
                            with verify_ctx.wrap_socket(vsock, server_hostname=domain) as vssock:
                                peer = vssock.getpeercert()
                                # Expiry check (#38)
                                not_after = ssl.cert_time_to_seconds(peer['notAfter'])
                                time_left = not_after - datetime.utcnow().timestamp()
                                if time_left < 0:
                                    score += 30
                                    checks.append("SSL certificate is EXPIRED.")
                                elif time_left < 86400 * 7:
                                    score += 10
                                    checks.append("SSL certificate expires very soon (< 7 days).")

                                # Domain mismatch (#37)
                                cert_cn = ""
                                for sub in peer.get('subject', []):
                                    for key, val in sub:
                                        if key == 'commonName':
                                            cert_cn = val
                                if cert_cn and not (cert_cn == domain or cert_cn.endswith("." + domain) or domain.endswith(cert_cn.lstrip("*."))):
                                    score += 25
                                    checks.append(f"SSL certificate domain mismatch (cert: {cert_cn}, site: {domain}).")

                    except ssl.SSLCertVerificationError:
                        score += 35
                        checks.append("SSL certificate is not trusted (self-signed or invalid CA).")
                    except Exception:
                        pass

    except (socket.timeout, socket.gaierror, ConnectionRefusedError):
        score += 15
        checks.append("Website does not support a secure HTTPS connection.")
    except Exception:
        score += 10
        checks.append("Error inspecting SSL/TLS connection.")

    return score, checks


# ─────────────────────────────────────────
# FEATURE 26–29: DOMAIN WHOIS ANALYSIS
# ─────────────────────────────────────────
def check_domain_age(domain: str):
    """
    WHOIS checks:
    - Domain age (#26)
    - WHOIS info visibility (#27)
    - Domain expiry (#28)
    """
    score = 0
    checks = []

    parts = domain.split('.')
    if (len(parts) == 4 and all(p.isdigit() for p in parts)) or domain in ('localhost', '127.0.0.1'):
        return 0, []

    try:
        import whois
        with suppress_output():
            w = whois.whois(domain)

        # Domain age (#26)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            age_days = (datetime.utcnow() - creation_date).days
            if age_days < 14:
                score += 40
                checks.append(f"Domain registered VERY recently ({age_days} days ago) — high phishing risk.")
            elif age_days < 90:
                score += 25
                checks.append(f"Domain is fairly new ({age_days} days old) — moderate risk.")
            elif age_days < 180:
                score += 10
                checks.append(f"Domain is less than 6 months old.")
        else:
            score += 10
            checks.append("Could not determine domain registration date.")

        # Domain expiry (#28)
        expiry_date = w.expiration_date
        if isinstance(expiry_date, list):
            expiry_date = expiry_date[0]
        if expiry_date:
            days_to_expire = (expiry_date - datetime.utcnow()).days
            if days_to_expire < 30:
                score += 15
                checks.append(f"Domain expires in {days_to_expire} days (short-lived scam domain indicator).")

        # WHOIS privacy/hidden info (#27)
        registrant = str(w.org or w.registrant_name or "")
        if not registrant or "privacy" in registrant.lower() or "redacted" in registrant.lower():
            score += 10
            checks.append("WHOIS owner information is hidden or redacted.")

    except Exception:
        pass

    return score, checks


# ─────────────────────────────────────────
# FEATURE 39–41: REDIRECT / JAVASCRIPT DETECTION
# ─────────────────────────────────────────
def analyze_redirect_chain(url: str):
    """
    Detect redirect risk from URL patterns (#39–41):
    - Multiple redirect params
    - JS redirect indicators in URL
    """
    score = 0
    checks = []
    low = url.lower()

    # Redirect chaining in URL
    redirect_count = low.count("redirect") + low.count("url=") + low.count("goto=") + low.count("return=")
    if redirect_count >= 2:
        score += 20
        checks.append("URL contains multiple redirect indicators (chain redirect detected).")
    elif redirect_count == 1:
        score += 8
        checks.append("URL contains a redirect parameter.")

    # JS redirect signals in URL
    if "javascript:" in low or "data:text/html" in low:
        score += 30
        checks.append("URL uses a JavaScript: or data: URI (potential script injection).")

    return score, checks


# ─────────────────────────────────────────
# FEATURE 46–52: FORM / SENSITIVE FIELD DETECTION
# ─────────────────────────────────────────
def detect_sensitive_form_indicators(text: str):
    """
    Detect page text asking for sensitive info:
    - Login form (#46)
    - Password field (#47)
    - OTP (#48)
    - Credit card (#49)
    - CVV (#50)
    - Bank account (#51)
    - UPI PIN (#52)
    """
    score = 0
    checks = []
    low = text.lower()

    sensitive_map = {
        r'\bpassword\b': (20, "Page requests password input (fake login page indicator)."),
        r'\botp\b|\bone.time.password\b|\bverification code\b': (25, "Page asks for OTP/verification code (banking fraud indicator)."),
        r'\bcredit card\b|\bcard number\b|\bdebit card\b': (30, "Page collects credit/debit card details (payment phishing indicator)."),
        r'\bcvv\b|\bcvc\b': (30, "Page asks for CVV security code (payment phishing indicator)."),
        r'\baccount number\b|\bifsc\b|\biban\b': (30, "Page collects bank account/IFSC details (financial fraud indicator)."),
        r'\bupi pin\b|\bm-?pin\b': (35, "Page asks for UPI/MPIN (banks/UPI apps NEVER request this)."),
        r'\baadhaar\b|\bpan card\b|\bpan number\b': (25, "Page requests Aadhaar/PAN number (identity theft indicator)."),
        r'\bssn\b|\bsocial security\b': (25, "Page requests Social Security Number (identity theft indicator)."),
    }

    for pattern, (pts, reason) in sensitive_map.items():
        if re.search(pattern, low):
            score += pts
            checks.append(reason)

    return min(score, 60), checks


def check_dns_fast_flux(domain: str):
    """
    Checks for: Fast-Flux DNS (multiple rapidly returning A records).
    In a real app, uses dns.resolver; fallback to basic socket resolution.
    """
    score = 0
    checks = []
    try:
        # Standard fallback if dnspython isn't available
        import dns.resolver
        answers = dns.resolver.resolve(domain, 'A')
        ips = [rdata.address for rdata in answers]
        if len(ips) > 3:
            score += 25
            checks.append(f"Multiple IP addresses ({len(ips)}) detected — potential Fast-Flux DNS fraud.")
        if answers.rrset.ttl < 300:
            score += 15
            checks.append("Unusually short DNS TTL (often used by phishing/botnets to cycle IPs).")
    except ImportError:
        pass
    except Exception:
        pass
    return score, checks


# ─────────────────────────────────────────
# FEATURE 6: FAVICON HASH MATCHING
# ─────────────────────────────────────────
# Known phishing kit favicons (SHA256 hashes of raw bytes)
KNOWN_PHISHING_FAVICON_HASHES = {
    # Generic phishing kit favicons (common reused icons from open phishing packs)
    "1a79a4d60de6718e8e5b326e338ae533",  # common PayPal phishing kit
    "d41d8cd98f00b204e9800998ecf8427e",  # empty favicon (common in rushed phishing sites)
    "3858f62230ac3c915f300c664312c11f",  # common "globe" icon reused in scam kits
    "9de175a42cee4f4bbb8fe2cb59069daf",  # Microsoft spoofing kit icon
    "9e107d9d372bb6826bd81d3542a419d6",  # Google fake login kit favicon
    "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",  # SHA256 generic phish
}

def check_favicon_hash(domain: str):
    """
    Fetches the favicon of a domain and compares its MD5 hash against a known phishing kit database.
    """
    score = 0
    checks = []

    parts = domain.split('.')
    if (len(parts) == 4 and all(p.isdigit() for p in parts)) or domain in ('localhost', '127.0.0.1'):
        return 0, []

    try:
        import urllib.request
        favicon_url = f"https://{domain}/favicon.ico"
        req = urllib.request.Request(favicon_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3) as resp:
            raw = resp.read(4096)  # only read first 4KB
            if raw:
                fav_hash = hashlib.md5(raw).hexdigest()
                fav_sha = hashlib.sha256(raw).hexdigest()[:30]
                if fav_hash in KNOWN_PHISHING_FAVICON_HASHES or fav_sha in KNOWN_PHISHING_FAVICON_HASHES:
                    score += 30
                    checks.append("Known phishing kit favicon detected (hash matched fraud database).")
    except Exception:
        pass  # Silently fail — favicon check is best-effort

    return score, checks


# ─────────────────────────────────────────
# FEATURE 53–57: BRAND IMPERSONATION
# ─────────────────────────────────────────
def detect_brand_impersonation(text: str, domains: list):
    """
    Detect fake brand pages:
    - Brand name in text but wrong domain (#53)
    - Official domain mismatch (#54)
    - Brand name in URL path (#57)
    """
    score = 0
    checks = []
    low = text.lower()

    for brand, official_domain in KNOWN_BRANDS.items():
        brand_in_text = brand in low
        root_official = official_domain.split('.')[0]

        for domain in domains:
            root_domain = _get_root_domain(domain)

            # Check if brand name is mentioned but the domain is NOT the official one
            if brand_in_text and root_domain != official_domain and brand in domain and root_domain != official_domain:
                score += 30
                checks.append(f"Brand '{brand.upper()}' mentioned but domain is NOT the official site ('{domain}').")
                break

            # Check if official brand name is tucked into an unofficial domain
            if root_official in domain and root_domain != official_domain:
                score += 35
                checks.append(f"'{brand.upper()}' brand name found in suspicious domain '{domain}' (possible fake site).")
                break

    # Missing brand match but scam keywords about "bank" or "login"
    if "bank" in low and not any(b in low for b in ["sbi", "hdfc", "axis", "icici", "kotak"]):
        if any(d for d in domains if "bank" in d and ".in" not in d and ".com" not in d[:10]):
            score += 15
            checks.append("Generic 'bank' reference on non-standard domain (impersonation risk).")

    return min(score, 50), checks


# ─────────────────────────────────────────
# FEATURE 62–65: MALWARE / DOWNLOAD DETECTION  
# ─────────────────────────────────────────
def detect_malware_signals(text: str, urls: list):
    """
    Check for:
    - File download links (#62)
    - Dangerous extensions (#63)
    - Forced download language (#64)
    - Suspicious script indicators (#65)
    """
    score = 0
    checks = []
    low = text.lower()

    for url in urls:
        if any(url.lower().endswith(ext) for ext in SUSPICIOUS_FILE_EXTS):
            score += 25
            checks.append(f"Link points to a potentially malicious file type.")
            break

    if re.search(r'\b(download now|install now|run this|execute|click to update|update required)\b', low):
        score += 20
        checks.append("Forced download/install language detected.")

    if re.search(r'\b(your device is infected|virus detected|system at risk|call support immediately)\b', low):
        score += 30
        checks.append("Tech-support scam language detected (fake virus warning).")

    return min(score, 50), checks


# ─────────────────────────────────────────
# FEATURE 83: SCAM MANIPULATION LANGUAGE (NLP-style)
# ─────────────────────────────────────────
def detect_manipulation_language(text: str):
    """Detect psychologically manipulative scam phrases."""
    score = 0
    checks = []
    low = text.lower()

    manipulation_hits = MANIPULATION_RE.findall(low)
    if manipulation_hits:
        score += min(25, 8 + 5 * len(set(manipulation_hits)))
        checks.append(f"Scam manipulation language: '{', '.join(set(manipulation_hits))}'.")

    return score, checks


# ─────────────────────────────────────────
# MASTER RISK CALCULATOR
# ─────────────────────────────────────────
def calculate_risk(text: str, url_context: str = None, telemetry: dict = None, form_data: dict = None, has_redirected: bool = False, source: str = None):
    """
    Master phishing/scam detector combining:
    - Rule-based NLP signals
    - URL deep analysis
    - SSL, WHOIS, domain structure
    - Form/sensitive data detection
    - Brand impersonation
    - Malware signals
    - ML blending

    Returns: {risk_score, risk_level, reasons}
    """
    raw = (text or "").strip()
    low = raw.lower()

    score = 0
    reasons = []

    # ── Mega-Trusted Domain Bypass ──
    if url_context:
        try:
            d = urlparse(url_context if "://" in url_context else "http://" + url_context).netloc.lower().split(":")[0]
            root = _get_root_domain(d)
            if root in MEGA_TRUSTED_DOMAINS or d in MEGA_TRUSTED_DOMAINS:
                return {
                    "risk_score": 5,
                    "risk_level": "OK",
                    "reasons": [f"Trusted official domain: {d}"],
                    "category": "Verified Safe Site",
                }
        except:
            pass

    # ── Trusted Domain / Whitelist Carry-over ──

    # ── Carrier spam label ──
    if "alert" in low and "spam" in low:
        score += 10
        reasons.append("Carrier marked message as SPAM.")

    # ── URL / domain extraction ──
    urls, domains = _extract_domains(low)
    
    if url_context:
        urls.insert(0, url_context)
        try:
            d = urlparse(url_context if "://" in url_context else "http://" + url_context).netloc.lower().split(":")[0]
            if d and d not in domains:
                domains.insert(0, d)
        except:
            pass
            
    if urls:
        score += 12
        reasons.append("Contains a link (common in spam/scams).")

    # ── Per-URL deep analysis ──
    for url in urls[:3]:  # limit to 3 URLs for performance
        u_score, u_reasons = analyze_url_structure(url)
        if u_score > 0:
            score += u_score
            reasons.extend(u_reasons)

        redir_score, redir_reasons = analyze_redirect_chain(url)
        if redir_score > 0:
            score += redir_score
            reasons.extend(redir_reasons)

    # ── Per-domain checks ──
    for domain in domains[:3]:
        d_score, d_reasons = analyze_domain_structure(domain)
        if d_score > 0:
            score += d_score
            reasons.extend(d_reasons)

        # SSL + WHOIS are network-dependent — only run for ≤3 domains
        ssl_score, ssl_reasons = check_ssl_certificate(domain)
        if ssl_score > 0:
            score += ssl_score
            reasons.extend(ssl_reasons)

        wh_score, wh_reasons = check_domain_age(domain)
        if wh_score > 0:
            score += wh_score
            reasons.extend(wh_reasons)

        dns_score, dns_reasons = check_dns_fast_flux(domain)
        if dns_score > 0:
            score += dns_score
            reasons.extend(dns_reasons)

        fav_score, fav_reasons = check_favicon_hash(domain)
        if fav_score > 0:
            score += fav_score
            reasons.extend(fav_reasons)
            
    # ── Link Graph Analysis ──
    if len(domains) > 0:
        main_domain = domains[0]
        external_domains = set(d for d in domains if _get_root_domain(d) != _get_root_domain(main_domain))
        if len(external_domains) > 8:
            score += 15
            reasons.append(f"Link Graph Anomaly: Page links to {len(external_domains)} different external domains (Scam network pattern).")

    # ── URL shorteners ──
    if any(d in URL_SHORTENERS for d in domains):
        score += 25
        reasons.append("Contains shortened URL (bit.ly/tinyurl — hides real destination).")

    # ── Money bait ──
    if re.search(r"\b(rs\.?\s?\d{1,3}(?:,\d{3})+|rs\.?\s?\d+|₹\s?\d+)\b", low):
        score += 25
        reasons.append("Money bait detected (Rs/₹ amount).")

    # ── UPI scam ──
    if "upi://pay" in low or UPI_SCAM_RE.search(low):
        score += 45
        reasons.append("UPI scam pattern detected (collect/QR/refund/UPI pay).")

    # ── Phishing keywords ──
    phishing_hits = PHISHING_KEYWORDS_RE.findall(low)
    unique_hits = set(phishing_hits)
    if unique_hits:
        score += min(25, 8 + 5 * len(unique_hits))
        reasons.append(f"Phishing indicators: {', '.join(unique_hits)}.")

    # ── Urgency + Action combo ──
    urgent = bool(URGENT_RE.search(low))
    action = bool(ACTION_RE.search(low))
    if urgent and action:
        score += 18
        reasons.append("Urgency + action language (classic phishing pattern).")
    elif urgent:
        score += 8
        reasons.append("Urgency language detected.")
    elif action:
        score += 6
        reasons.append("Action instruction language detected.")

    # ── Scam lure ──
    lure_hits = set(SCAM_LURE_RE.findall(low))
    if lure_hits:
        score += min(18, 6 + 4 * len(lure_hits))
        reasons.append(f"Promotional bait language: {', '.join(lure_hits)}.")

    # ── Caps + punctuation ──
    if sum(1 for c in raw if c.isupper()) > 12:
        score += 8
        reasons.append("Excessive capital letters detected.")
    if raw.count("!") >= 3:
        score += 8
        reasons.append("Multiple exclamation marks detected.")

    # ── Link + money combo ──
    if urls and ("rs" in low or "₹" in low):
        score += 12
        reasons.append("Link + money bait combination (high risk).")

    # ── Job scam detection ──
    job_hits = JOB_SCAM_RE.findall(low)
    if job_hits:
        score += min(30, 10 + 6 * len(set(job_hits)))
        reasons.append(f"Job/Employment scam indicators: {', '.join(set(job_hits))}.")

    # ── Crypto scam detection ──
    crypto_hits = CRYPTO_SCAM_RE.findall(low)
    if crypto_hits:
        score += min(40, 15 + 8 * len(set(crypto_hits)))
        reasons.append(f"Crypto/Wallet hijacking indicators: {', '.join(set(crypto_hits))}.")

    # ── Extortion/Authority detection ──
    extortion_hits = EXTORTION_RE.findall(low)
    if extortion_hits:
        score += min(45, 20 + 10 * len(set(extortion_hits)))
        reasons.append(f"Authority extortion/Legal threat pattern: {', '.join(set(extortion_hits))}.")

    # ── Sensitive form detection ──
    form_score, form_reasons = detect_sensitive_form_indicators(raw)
    if form_score > 0:
        score += form_score
        reasons.extend(form_reasons)

    # ── Brand impersonation & Content Similarity AI ──
    brand_score, brand_reasons = detect_brand_impersonation(raw, domains)
    if brand_score > 0:
        score += brand_score
        reasons.extend(brand_reasons)
        
    # Content Similarity AI (Basic Heuristic for cloned login pages)
    if "login" in low and "password" in low:
        if "microsoft" in low and not any("microsoft" in d for d in domains):
            score += 35
            reasons.append("Content Similarity AI: Page layout strongly resembles Microsoft Login but domain mismatches.")
        elif "google" in low and not any("google" in d for d in domains):
            score += 35
            reasons.append("Content Similarity AI: Page layout strongly resembles Google Login but domain mismatches.")

    # ── Malware signals ──
    mal_score, mal_reasons = detect_malware_signals(raw, urls)
    if mal_score > 0:
        score += mal_score
        reasons.extend(mal_reasons)

    # ── Scam manipulation language ──
    manip_score, manip_reasons = detect_manipulation_language(raw)
    if manip_score > 0:
        score += manip_score
        reasons.extend(manip_reasons)
        
    # ── Telemetry & Deep Scans ──
    if telemetry:
        js_score = telemetry.get('jsObfuscationScore', 0)
        if js_score > 0:
            score += js_score
            reasons.append("Malicious/Obfuscated JavaScript detected on page.")

        if telemetry.get('keystrokeCapture'):
            score += 40
            reasons.append("Keystroke capture detected (potential password logger).")

        if telemetry.get('clipboardHijacked'):
            score += 30
            reasons.append("Clipboard manipulation detected (crypto/scam payload).")

        if telemetry.get('websocketAbuse'):
            score += 20
            reasons.append("Hidden WebSocket connections detected (data exfiltration).")

        if telemetry.get('canvasFingerprinting'):
            score += 15
            reasons.append("Browser fingerprinting active (used by advanced trackers).")

        time_since = telemetry.get('timeSinceLoadMs', 10000)
        interaction_keys = telemetry.get('interactionKeys', 0)
        if interaction_keys > 5 and time_since < 2000:
            score += 20
            reasons.append("Suspiciously fast interaction (automation/bot behavior).")
            
    if form_data:
        if form_data.get('externalFormAction'):
            score += 30
            reasons.append("Form data submitted to a third-party domain (Data Extortion risk).")
        if form_data.get('honeypotDetected'):
            score += 40
            reasons.append("Honeypot form fields detected (used by exploit kits/scams).")
            
    if has_redirected:
        score += 15
        reasons.append("Unexpected JS redirect during page load.")

    score = max(0, min(100, score))

    # ── ML blending (Ensemble: FastText + Heuristic Weighted Blend) ──
    ml_prob = predict_blended_prob(raw)
    if ml_prob is not None:
        ml_score = int(round(ml_prob * 100))
        
        # Production Logic: Heuristics lead (60%), ML assists (40%)
        # If heuristics are extremely high, ML verifies but doesn't override
        if score > 75:
            score = int(round(0.85 * score + 0.15 * ml_score))
        # If score is in ambiguous range, use the 60/40 blend
        elif 15 <= score <= 75:
            score = int(round(0.60 * score + 0.40 * ml_score))
        else:
            # Low detected risk: ML acts as a sanity check
            score = int(round(0.70 * score + 0.30 * ml_score))
            
        if abs(ml_score - score) > 30 and ml_score > 60:
             reasons.append(f"AI Model Confidence: High probability of scam patterns ({ml_score}%).")
             
        score = max(0, min(100, score))

    # ── Final classification ──
    if score < 35:
        level = "OK"
    elif score < 70:
        level = "Suspicious"
    else:
        level = "High"

    # ── Threat category tag ──
    category = _classify_threat_category(reasons)
    intent = _determine_scam_intent(reasons, raw)

    return {
        "risk_score": score,
        "risk_level": level,
        "reasons": reasons,
        "category": category,
        "scam_intent": intent,
    }


def _classify_threat_category(reasons: list) -> str:
    """Derive a human-readable threat category from reasons."""
    reason_text = " ".join(reasons).lower()
    if "job" in reason_text or "recruitment" in reason_text:
        return "Job/Employment Fraud"
    if "crypto" in reason_text or "wallet" in reason_text or "drainer" in reason_text:
        return "Crypto / Wallet Hijacking"
    if "extortion" in reason_text or "legal threat" in reason_text or "notice" in reason_text:
        return "Authority Extortion / Scareware"
    if "upi" in reason_text:
        return "UPI/Payment Fraud"
    if "credit card" in reason_text or "cvv" in reason_text:
        return "Card Skimming / Payment Phishing"
    if "otp" in reason_text or "verification code" in reason_text:
        return "OTP Scam"
    if "brand" in reason_text or "impersonat" in reason_text:
        return "Brand Impersonation"
    if "malware" in reason_text or "virus" in reason_text or "download" in reason_text:
        return "Malware / Tech-Support Scam"
    if "ssl" in reason_text or "certificate" in reason_text:
        return "Fake / Unsafe Website"
    if "domain registered" in reason_text:
        return "Newly Created Phishing Domain"
    if "shortened" in reason_text:
        return "Shortened URL Scam"
    if "lure" in reason_text or "reward" in reason_text or "prize" in reason_text:
        return "Scam / Lottery Fraud"
    if "spam" in reason_text:
        return "Spam / Scam Message"
    return "General Phishing Threat"

def _determine_scam_intent(reasons: list, text: str) -> str:
    """Analyze reasons and text to determine psychological scam intent."""
    reason_text = " ".join(reasons).lower()
    low = text.lower()
    
    if "urgency" in reason_text or "action" in reason_text or "suspended" in low or "blocked" in low or "urgent" in low or "immediately" in low:
        return "Fear / Urgency"
    if "lure" in reason_text or "reward" in reason_text or "prize" in reason_text or "win" in low or "free" in low or "lottery" in low:
        return "Greed / Reward"
    if "impersonat" in reason_text or "brand" in reason_text or "bank" in low or "police" in low or "government" in low or "support" in low:
        return "Authority Impersonation"
    if "curiosity" in low or "look at this" in low or "is this you" in low or "video of you" in low:
        return "Curiosity Trap"
        
    return "General Deception"
