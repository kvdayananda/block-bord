"""
Block Bord AI — ML Feature Engineering
Extracts features from a URL to match the PhiUSIIL dataset column names exactly.
The model was trained on these 50 numeric features — every name must match.
"""
import re
import math
import tldextract
from urllib.parse import urlparse, parse_qs
from collections import Counter

# ── Trusted & Suspicious TLDs ─────────────────────────────────────────────────
_TRUSTED_TLDS   = {'com', 'net', 'org', 'edu', 'gov', 'in', 'io', 'ai', 'co', 'uk'}
_SUSPICIOUS_TLDS = {'top', 'xyz', 'club', 'best', 'monster', 'gq', 'cf', 'tk', 'ml',
                    'work', 'click', 'link', 'pw', 'ga', 'zip', 'mobi', 'info'}

# ── Brands for impersonation detection ───────────────────────────────────────
_BRANDS = [
    "google", "facebook", "paypal", "amazon", "apple", "microsoft",
    "netflix", "instagram", "whatsapp", "twitter", "linkedin", "sbi",
    "paytm", "hdfc", "axis", "icici", "binance", "coinbase", "chase",
    "wellsfargo", "hsbc", "ebay", "dropbox", "gmail", "yahoo", "outlook",
]

# ── Phishing keyword signals ──────────────────────────────────────────────────
_PHISHING_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update", "banking",
    "password", "confirm", "free", "winner", "click", "claim", "suspend",
    "urgent", "alert", "limited", "offer", "prize", "gift",
]


def _calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    probs = [n / len(text) for n in Counter(text).values()]
    return -sum(p * math.log2(p) for p in probs)


def _calculate_char_continuation(url: str) -> float:
    """Ratio of max run of repeated chars to URL length."""
    if len(url) < 2:
        return 0.0
    max_run = cur = 1
    for i in range(1, len(url)):
        cur = cur + 1 if url[i] == url[i - 1] else 1
        max_run = max(max_run, cur)
    return max_run / len(url)


def _tld_legit_score(suffix: str) -> float:
    suffix = (suffix or "").lower()
    if suffix in _TRUSTED_TLDS:
        return 1.0
    if suffix in _SUSPICIOUS_TLDS:
        return 0.1
    return 0.5


def _url_char_prob(url: str) -> float:
    """Ratio of alphanumeric chars — high ratio = more legitimate."""
    if not url:
        return 0.0
    alnum = sum(c.isalnum() for c in url)
    return alnum / len(url)


def _calculate_similarity(url: str, domain: str, ext) -> float:
    """
    Measures how similar the URL is to a KNOWN LEGITIMATE site.
    HIGH score (close to 1.0) = looks like a real site.
    LOW score (close to 0.0) = suspicious/phishing.

    This is the #1 most important feature (59% importance).
    """
    score = 0.0

    # Uses HTTPS → more legitimate
    if url.startswith("https://"):
        score += 0.25

    # Trusted TLD
    tld = (ext.suffix or "").lower()
    if tld in _TRUSTED_TLDS:
        score += 0.25
    elif tld in _SUSPICIOUS_TLDS:
        score -= 0.30

    # Short, clean domain (no hyphens, no digits) → more legitimate
    d = ext.domain or ""
    if len(d) <= 15 and "-" not in d and not any(c.isdigit() for c in d):
        score += 0.20

    # No subdomain or just www → more legitimate
    sub = ext.subdomain or ""
    if sub in ("", "www"):
        score += 0.15
    elif sub.count(".") >= 2:  # deep subdomains → suspicious
        score -= 0.20

    # Phishing keywords in URL → suspicious
    low = url.lower()
    hits = sum(1 for kw in _PHISHING_KEYWORDS if kw in low)
    score -= hits * 0.08

    # Brand name NOT in its own domain (impersonation) → suspicious
    brand_in_url    = any(b in low for b in _BRANDS)
    brand_in_domain = any(b in (ext.domain or "").lower() for b in _BRANDS)
    if brand_in_url and not brand_in_domain:
        score -= 0.25

    # IP address as domain → very suspicious
    if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ext.domain or ""):
        score -= 0.40

    # Clamp to [0, 1]
    return max(0.0, min(1.0, score + 0.5))  # centre at 0.5


def extract_url_features(url: str, page_content: str = "") -> dict:
    """
    Extracts a feature vector matching all PhiUSIIL dataset columns.
    Returns a dict suitable for pd.DataFrame([features]).
    """
    try:
        ext    = tldextract.extract(url)
        parsed = urlparse(url)
    except Exception:
        return _zero_features()

    low_url = url.lower()
    domain  = f"{ext.subdomain}.{ext.domain}.{ext.suffix}".strip(".")
    path    = parsed.path or ""
    content_low = (page_content or "").lower()

    f = {}

    # ── Lexical ──────────────────────────────────────────────────────────────
    f["URLLength"]                 = len(url)
    f["DomainLength"]              = len(domain)
    f["IsDomainIP"]                = 1 if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ext.domain or "") else 0
    f["URLSimilarityIndex"]        = _calculate_similarity(url, domain, ext)
    f["CharContinuationRate"]      = _calculate_char_continuation(url)
    f["TLDLegitimateProb"]         = _tld_legit_score(ext.suffix)
    f["URLCharProb"]               = _url_char_prob(url)
    f["TLDLength"]                 = len(ext.suffix or "")
    f["NoOfSubDomain"]             = max(0, ext.subdomain.count(".") + 1) if ext.subdomain else 0
    f["NoOfDotsInURL"]             = url.count(".")
    f["EntropyOfURL"]              = _calculate_entropy(url)
    f["IsBrandInDomain"]           = 1 if any(b in (ext.domain or "").lower() for b in _BRANDS) else 0
    f["HasObfuscation"]            = 1 if "%" in url or "0x" in url.lower() else 0
    f["NoOfObfuscatedChar"]        = url.count("%")
    f["ObfuscationRatio"]          = url.count("%") / len(url) if url else 0
    f["NoOfLettersInURL"]          = sum(c.isalpha() for c in url)
    f["LetterRatioInURL"]          = f["NoOfLettersInURL"] / len(url) if url else 0
    f["NoOfDegitsInURL"]           = sum(c.isdigit() for c in url)   # Note: PhiUSIIL typo "Degits"
    f["DegitRatioInURL"]           = f["NoOfDegitsInURL"] / len(url) if url else 0
    f["NoOfEqualsInURL"]           = url.count("=")
    f["NoOfQMarkInURL"]            = url.count("?")
    f["NoOfAmpersandInURL"]        = url.count("&")
    f["NoOfOtherSpecialCharsInURL"]= sum(not c.isalnum() and c not in "/:.-_?=&" for c in url)
    f["SpacialCharRatioInURL"]     = f["NoOfOtherSpecialCharsInURL"] / len(url) if url else 0
    f["IsHTTPS"]                   = 1 if url.startswith("https") else 0

    # ── Page/Content features (estimated from URL when no content) ───────────
    f["LineOfCode"]                = max(1, content_low.count("\n")) if content_low else 50
    f["LargestLineLength"]         = max((len(l) for l in content_low.split("\n")), default=0) if content_low else 80
    f["HasTitle"]                  = 1 if "<title" in content_low else 0
    f["DomainTitleMatchScore"]     = 1.0 if ext.domain.lower() in content_low else 0.0
    f["URLTitleMatchScore"]        = 0.5  # neutral default
    f["HasFavicon"]                = 1 if "favicon" in content_low else 0
    f["Robots"]                    = 1 if "robots" in content_low else 0
    f["IsResponsive"]              = 1 if "viewport" in content_low else 0
    f["NoOfURLRedirect"]           = low_url.count("redirect") + low_url.count("url=")
    f["NoOfSelfRedirect"]          = max(0, url.count("//") - 1)
    f["HasDescription"]            = 1 if "description" in content_low else 0
    f["NoOfPopup"]                 = content_low.count("window.open") + content_low.count("popup")
    f["NoOfiFrame"]                = content_low.count("<iframe") + content_low.count("<frame")
    f["HasExternalFormSubmit"]     = 1 if re.search(r'action=["\']https?://', content_low) else 0
    f["HasSocialNet"]              = 1 if any(s in content_low for s in ["facebook.com", "twitter.com", "instagram.com"]) else 0
    f["HasSubmitButton"]           = 1 if "type=\"submit\"" in content_low or "type='submit'" in content_low else 0
    f["HasHiddenFields"]           = 1 if "type=\"hidden\"" in content_low or "type='hidden'" in content_low else 0
    f["HasPasswordField"]          = 1 if "type=\"password\"" in content_low or "password" in low_url else 0

    # ── Keyword signals ───────────────────────────────────────────────────────
    f["Bank"]                      = 1 if any(w in low_url for w in ["bank", "sbi", "hdfc", "icici", "axis"]) else 0
    f["Pay"]                       = 1 if any(w in low_url for w in ["pay", "payment", "paypal", "paytm"]) else 0
    f["Crypto"]                    = 1 if any(w in low_url for w in ["crypto", "bitcoin", "wallet", "binance", "coin"]) else 0
    f["HasCopyrightInfo"]          = 1 if "copyright" in content_low or "©" in content_low else 0

    # ── External references ───────────────────────────────────────────────────
    f["NoOfImage"]                 = content_low.count("<img")
    f["NoOfCSS"]                   = content_low.count("<link") + content_low.count(".css")
    f["NoOfJS"]                    = content_low.count("<script") + content_low.count(".js")
    f["NoOfSelfRef"]               = content_low.count(ext.domain) if ext.domain else 0
    f["NoOfEmptyRef"]              = content_low.count('href="#"') + content_low.count("href=''")
    f["NoOfExternalRef"]           = content_low.count("http") - f["NoOfSelfRef"]

    return f


def _zero_features() -> dict:
    """Returns a zero-filled feature dict for error cases."""
    keys = [
        "URLLength", "DomainLength", "IsDomainIP", "URLSimilarityIndex",
        "CharContinuationRate", "TLDLegitimateProb", "URLCharProb", "TLDLength",
        "NoOfSubDomain", "HasObfuscation", "NoOfObfuscatedChar", "ObfuscationRatio",
        "NoOfLettersInURL", "LetterRatioInURL", "NoOfDegitsInURL", "DegitRatioInURL",
        "NoOfEqualsInURL", "NoOfQMarkInURL", "NoOfAmpersandInURL",
        "NoOfOtherSpecialCharsInURL", "SpacialCharRatioInURL", "IsHTTPS",
        "NoOfDotsInURL", "EntropyOfURL", "IsBrandInDomain",
        "LineOfCode", "LargestLineLength", "HasTitle", "DomainTitleMatchScore",
        "URLTitleMatchScore", "HasFavicon", "Robots", "IsResponsive",
        "NoOfURLRedirect", "NoOfSelfRedirect", "HasDescription", "NoOfPopup",
        "NoOfiFrame", "HasExternalFormSubmit", "HasSocialNet", "HasSubmitButton",
        "HasHiddenFields", "HasPasswordField", "Bank", "Pay", "Crypto",
        "HasCopyrightInfo", "NoOfImage", "NoOfCSS", "NoOfJS", "NoOfSelfRef",
        "NoOfEmptyRef", "NoOfExternalRef",
    ]
    return {k: 0 for k in keys}
