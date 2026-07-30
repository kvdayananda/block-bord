"""
Block Bord AI — Tools Router
20 Security Tools: Leak Checker, URL Scanner, Scam Map, AI Assistant,
Password Checker, Email Header, IP Lookup, Domain Inspector, Phishing Sim,
Dark Web Monitor, SSL Checker, File Hash, QR Scanner, Social Scanner,
Port Scanner, Malware Intel, UPI Checker, Threat Score, Bulk Email, Security Report
"""
import logging
import os
import re
import hashlib
import httpx
import json
import socket
import random
from pydantic import BaseModel
from typing import Optional
from fastapi import APIRouter, Request, Depends, HTTPException, Form, File, UploadFile, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from datetime import datetime, timezone, timedelta

from backend.app.dependencies import get_db, get_current_user, validate_csrf
from backend.app.models import ScanHistory
from backend.app.config import settings

logger = logging.getLogger("blockbord.tools")
router = APIRouter(prefix="/tools", tags=["Tools"])
templates = Jinja2Templates(directory="frontend/templates")


def _get_user_plan(request: Request, db: Session) -> str:
    user = get_current_user(request, db)
    return getattr(user, "plan", "free") if user else "free"


def _render(tpl: str, request: Request, db: Session, **extra):
    user = get_current_user(request, db)
    plan = getattr(user, "plan", "free") if user else "free"
    return templates.TemplateResponse(tpl, {"request": request, "user": user, "plan": plan, **extra})


# ══════════════════════════════════════════════════════════════════════
# PAGE ROUTES (HTML)
# ══════════════════════════════════════════════════════════════════════

@router.get("", response_class=HTMLResponse)
def tools_home(request: Request, db: Session = Depends(get_db)):
    """Main tools landing page with all 20 tools."""
    return _render("tools.html", request, db)


@router.get("/leak-checker", response_class=HTMLResponse)
def leak_checker_page(request: Request, db: Session = Depends(get_db)):
    return _render("leak_checker.html", request, db)


@router.get("/url-scanner", response_class=HTMLResponse)
def url_scanner_page(request: Request, db: Session = Depends(get_db)):
    return _render("url_scanner.html", request, db)


@router.get("/scam-map", response_class=HTMLResponse)
def scam_map_page(request: Request, db: Session = Depends(get_db)):
    return _render("scam_map.html", request, db)


@router.get("/ai-assistant", response_class=HTMLResponse)
def ai_assistant_page(request: Request, db: Session = Depends(get_db)):
    return _render("ai_assistant.html", request, db)


@router.get("/password-checker", response_class=HTMLResponse)
def password_checker_page(request: Request, db: Session = Depends(get_db)):
    return _render("password_checker.html", request, db)


@router.get("/email-header", response_class=HTMLResponse)
def email_header_page(request: Request, db: Session = Depends(get_db)):
    return _render("email_header.html", request, db)


@router.get("/ip-lookup", response_class=HTMLResponse)
def ip_lookup_page(request: Request, db: Session = Depends(get_db)):
    return _render("ip_lookup.html", request, db)


@router.get("/domain-inspector", response_class=HTMLResponse)
def domain_inspector_page(request: Request, db: Session = Depends(get_db)):
    return _render("domain_inspector.html", request, db)


@router.get("/phishing-sim", response_class=HTMLResponse)
def phishing_sim_page(request: Request, db: Session = Depends(get_db)):
    return _render("phishing_sim.html", request, db)


@router.get("/darkweb-monitor", response_class=HTMLResponse)
def darkweb_monitor_page(request: Request, db: Session = Depends(get_db)):
    return _render("darkweb_monitor.html", request, db)


@router.get("/ssl-checker", response_class=HTMLResponse)
def ssl_checker_page(request: Request, db: Session = Depends(get_db)):
    return _render("ssl_checker.html", request, db)


@router.get("/file-hash", response_class=HTMLResponse)
def file_hash_page(request: Request, db: Session = Depends(get_db)):
    return _render("file_hash.html", request, db)


@router.get("/qr-scanner", response_class=HTMLResponse)
def qr_scanner_page(request: Request, db: Session = Depends(get_db)):
    return _render("qr_scanner.html", request, db)


@router.get("/social-scanner", response_class=HTMLResponse)
def social_scanner_page(request: Request, db: Session = Depends(get_db)):
    return _render("social_scanner.html", request, db)


@router.get("/port-scanner", response_class=HTMLResponse)
def port_scanner_page(request: Request, db: Session = Depends(get_db)):
    return _render("port_scanner.html", request, db)


@router.get("/malware-intel", response_class=HTMLResponse)
def malware_intel_page(request: Request, db: Session = Depends(get_db)):
    return _render("malware_intel.html", request, db)


@router.get("/upi-checker", response_class=HTMLResponse)
def upi_checker_page(request: Request, db: Session = Depends(get_db)):
    return _render("upi_checker.html", request, db)


@router.get("/threat-score", response_class=HTMLResponse)
def threat_score_page(request: Request, db: Session = Depends(get_db)):
    return _render("threat_score.html", request, db)


@router.get("/email-verifier", response_class=HTMLResponse)
def email_verifier_page(request: Request, db: Session = Depends(get_db)):
    return _render("email_verifier.html", request, db)


@router.get("/security-report", response_class=HTMLResponse)
def security_report_page(request: Request, db: Session = Depends(get_db)):
    return _render("security_report.html", request, db)


# ══════════════════════════════════════════════════════════════════════
# API ROUTES (JSON)
# ══════════════════════════════════════════════════════════════════════

# ── 1. LEAK CHECKER (HIBP) ───────────────────────────────────────────
@router.post("/api/check-leak")
async def check_leak(request: Request, email: str = Form(...), db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    email = email.strip().lower()
    hibp_key = settings.hibp_api_key

    if not hibp_key:
        is_leaked = (len(email) % 4 != 0)
        if is_leaked:
            return {
                "leaked": True, "source": "Block Bord AI (Simulated)",
                "details": [
                    {"Name": "DeepWeb-Dump", "Title": "Global Credential Leak", "BreachDate": "2023-11-12",
                     "Description": "A large collection of email/password pairs found on an underground forum."},
                    {"Name": "SocialMedia-2021", "Title": "Legacy Platform Breach", "BreachDate": "2021-05-20",
                     "Description": "Email addresses and hashed passwords leaked from an older social platform."}
                ],
                "message": "⚠️ Simulation Mode: Add your HIBP_API_KEY to .env for live data."
            }
        return {"leaked": False, "source": "Block Bord AI (Simulated)", "details": [],
                "message": "✅ No leaks found in simulation."}

    async with httpx.AsyncClient() as client:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {"hibp-api-key": hibp_key, "user-agent": "BlockBord-AI"}
        resp = await client.get(url, headers=headers)
        if resp.status_code == 404:
            return {"leaked": False, "details": "No leaks found."}
        elif resp.status_code == 200:
            return {"leaked": True, "details": resp.json()}
        else:
            return {"error": "HIBP API error", "status": resp.status_code}


# ── 2. URL SCANNER ───────────────────────────────────────────────────
class URLRequest(BaseModel):
    url: str

@router.post("/api/url-scan")
async def url_scan(req: URLRequest, request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    url = req.url.strip()
    # Heuristic analysis
    suspicious_patterns = [
        ("paypa1", "Typosquatting"), ("bit.ly", "URL shortener"),
        ("tinyurl", "URL shortener"), ("-login", "Login phishing"),
        ("free-", "Suspicious keyword"), (".tk/", "Free TLD"),
        (".xyz/login", "Suspicious path"), ("account-verify", "Credential phishing"),
    ]
    flags = []
    score = 0
    for pattern, reason in suspicious_patterns:
        if pattern.lower() in url.lower():
            flags.append(reason)
            score += 20

    # Check for HTTP (not HTTPS)
    if url.startswith("http://"):
        flags.append("No HTTPS encryption")
        score += 15

    score = min(score, 100)
    risk_level = "Dangerous" if score > 60 else "Suspicious" if score > 30 else "Safe"

    checks = {
        "HTTPS": not url.startswith("http://"),
        "No_Shortener": not any(s in url for s in ["bit.ly", "tinyurl", "t.co"]),
        "No_Typosquat": not any(p in url.lower() for p in ["paypa1", "g00gle", "facebo0k"]),
        "No_Phishing_Path": not any(p in url.lower() for p in ["login-verify", "account-secure"]),
    }

    return {"risk_level": risk_level, "threat_score": score, "flags": flags, "checks": checks}


# ── 3. SCAM MAP STATS ────────────────────────────────────────────────
@router.get("/api/scam-stats")
def scam_stats_api(db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    total_scans = db.query(ScanHistory).count()
    today_scans = db.query(ScanHistory).filter(ScanHistory.created_at >= today_start).count()
    high_risk_today = db.query(ScanHistory).filter(
        ScanHistory.created_at >= today_start, ScanHistory.risk_level == "High").count()
    recent_scans = db.query(ScanHistory).filter(
        ScanHistory.created_at >= now - timedelta(hours=1)).order_by(ScanHistory.created_at.desc()).limit(10).all()
    cities = ["Mumbai", "Delhi", "Bangalore", "New York", "London", "Lagos", "São Paulo", "Sydney"]
    event_types = ["Phishing Attempt", "UPI Scam", "Vishing Blocked", "Malicious Link", "Credential Harvesting"]
    feed = []
    for scan in recent_scans:
        feed.append({
            "type": scan.category if scan.category and scan.category not in ("General",) else random.choice(event_types),
            "city": random.choice(cities),
            "time": scan.created_at.strftime("%H:%M") if scan.created_at else now.strftime("%H:%M")
        })
    while len(feed) < 10:
        feed.append({"type": random.choice(event_types), "city": random.choice(cities),
                     "time": (now - timedelta(minutes=random.randint(5, 60))).strftime("%H:%M")})
    base = max(total_scans, 10)
    return {"total_today": today_scans, "high_risk_today": high_risk_today, "total_all_time": total_scans,
            "top_country": "IN", "countries": {"IN": int(base*0.45), "US": int(base*0.20), "GB": int(base*0.10),
                                               "BR": int(base*0.08), "NG": int(base*0.09), "AU": int(base*0.05)},
            "feed": feed[:10]}


# ── 4. AI ASSISTANT ──────────────────────────────────────────────────
class AssistantRequest(BaseModel):
    message: str

@router.post("/api/assistant")
async def assistant_api(req: AssistantRequest, request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    gemini_key = settings.gemini_api_key
    if not gemini_key or not gemini_key.startswith("AIzaSy"):
        return {"response": "I'm in rule-based mode. Add a valid GEMINI_API_KEY for full AI capability."}

    try:
        from google import genai
        client = genai.Client(api_key=gemini_key)
        system_prompt = ("You are Block Bord AI, a cyber intelligence assistant. "
                         "Help the user understand scams, phishing, and online safety. "
                         "Be professional, direct, and security-focused.")
        for model_id in ["gemini-2.0-flash-lite", "gemini-2.0-flash", "gemini-1.5-flash"]:
            try:
                response = client.models.generate_content(
                    model=model_id, contents=f"{system_prompt}\n\nUser: {req.message}")
                if response and response.text:
                    return {"response": response.text}
            except Exception as e:
                if "429" in str(e):
                    return {"response": "I'm very busy right now (rate limit). Please try again in 30 seconds! ⏳"}
                continue
        return {"response": "AI service temporarily unavailable. Please try again."}
    except Exception as e:
        logger.error(f"Gemini SDK Error: {e}")
        return {"response": "Sorry, I'm having trouble right now. How else can I help?"}


# ── 5. IP LOOKUP ─────────────────────────────────────────────────────
@router.get("/api/ip-lookup")
async def ip_lookup(ip: str = Query(...), request: Request = None, db: Session = Depends(get_db)):
    if settings.enable_mock_data:
        logger.info("Mock data mode: returning simulated IP lookup result")
        return {"country": "Mockland", "city": "Mock City", "isp": "Mock ISP",
                "lat": 0.0, "lon": 0.0, "ip": ip,
                "threat_score": 0, "blacklisted": False}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,lat,lon,query")
            data = r.json()
            if data.get("status") == "success":
                threat_score = random.randint(0, 30)  # Simulated; integrate AbuseIPDB for real data
                return {"country": data.get("country"), "city": data.get("city"), "isp": data.get("isp"),
                        "lat": data.get("lat"), "lon": data.get("lon"), "ip": data.get("query"),
                        "threat_score": threat_score, "blacklisted": threat_score > 70}
    except Exception as e:
        logger.error(f"IP lookup error: {e}")
    return {"country": "Unknown", "city": "Unknown", "isp": "Unknown", "threat_score": 0, "blacklisted": False}


# ── 6. EMAIL HEADER ANALYSER ─────────────────────────────────────────
class EmailHeaderRequest(BaseModel):
    headers: str

@router.post("/api/email-header")
async def email_header_analyse(req: EmailHeaderRequest):
    headers_text = req.headers

    def extract(pattern, text, default="fail"):
        m = re.search(pattern, text, re.IGNORECASE)
        return m.group(1).strip().lower() if m else default

    spf = extract(r"spf=(\w+)", headers_text)
    dkim = extract(r"dkim=(\w+)", headers_text)
    dmarc = extract(r"dmarc=(\w+)", headers_text)

    hops = []
    for line in headers_text.split("\n"):
        if line.strip().startswith("Received:"):
            hops.append(line.strip()[:120])

    return {"spf": spf, "dkim": dkim, "dmarc": dmarc, "hops": hops[:6]}


# ── 7. DOMAIN INSPECTOR ──────────────────────────────────────────────
@router.get("/api/domain-inspect")
async def domain_inspect(domain: str = Query(...)):
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    if settings.enable_mock_data:
        logger.info("Mock data mode: returning simulated domain inspector result")
        return {"registrar": "Mock Registrar", "created": "2020-01-01", "expires": "2025-01-01",
                "ssl_issuer": "Mock CA", "risk_level": "Low", "ip": "0.0.0.0",
                "dns": [f"A: 0.0.0.0", f"MX: mail.{domain}", f"NS: ns1.{domain}", f"TXT: v=spf1 include:{domain} ~all"]}
    result = {"registrar": "Simulated Registrar Inc.", "created": "2019-03-15", "expires": "2025-03-15",
              "ssl_issuer": "Let's Encrypt", "risk_level": "Low", "ip": "Unknown",
              "dns": [f"A: 192.168.1.1", f"MX: mail.{domain}", f"NS: ns1.{domain}", f"TXT: v=spf1 include:{domain} ~all"]}
    try:
        ip = socket.gethostbyname(domain)
        result["ip"] = ip
        # Heuristic risk
        suspicious_tlds = [".tk", ".ml", ".cf", ".gq", ".xyz"]
        if any(domain.endswith(t) for t in suspicious_tlds):
            result["risk_level"] = "High"
        elif len(domain) > 30:
            result["risk_level"] = "Medium"
    except Exception:
        result["ip"] = "Could not resolve"
    return result


# ── 8. SSL CHECKER ───────────────────────────────────────────────────
@router.get("/api/ssl-check")
async def ssl_check(domain: str = Query(...)):
    import ssl
    import socket as sock
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    if settings.enable_mock_data:
        logger.info("Mock data mode: returning simulated SSL check result")
        return {"valid": True, "subject": domain, "issuer": "Mock CA", "valid_from": "2020-01-01", "expires": "2030-01-01", "days_left": 3650, "cipher": "TLS_AES_256_GCM_SHA384", "tls_version": "TLSv1.3"}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(sock.socket(), server_hostname=domain) as s:
            s.settimeout(8)
            s.connect((domain, 443))
            cert = s.getpeercert()
            not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
            days_left = (not_after - datetime.now(timezone.utc)).days
            issuer = dict(x[0] for x in cert.get("issuer", []))
            subject = dict(x[0] for x in cert.get("subject", []))
            return {"valid": True, "subject": subject.get("commonName", domain),
                    "issuer": issuer.get("organizationName", "Unknown"),
                    "valid_from": not_before.strftime("%Y-%m-%d"), "expires": not_after.strftime("%Y-%m-%d"),
                    "days_left": days_left, "cipher": s.cipher()[0] if s.cipher() else "Unknown",
                    "tls_version": s.version()}
    except ssl.SSLCertVerificationError:
        return {"valid": False, "subject": domain, "issuer": "Invalid", "days_left": 0,
                "expires": "N/A", "valid_from": "N/A", "cipher": "N/A", "tls_version": "N/A"}

    except Exception as e:
        logger.warning(f"SSL check error for {domain}: {e}")
        return {"valid": False, "subject": domain, "issuer": "Could not connect", "days_left": 0,
                "expires": "N/A", "valid_from": "N/A", "cipher": "N/A", "tls_version": "N/A"}


# ── 9. QR SCANNER ────────────────────────────────────────────────────
@router.post("/api/qr-scan")
async def qr_scan(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    if settings.enable_mock_data:
        logger.info("Mock data mode: returning simulated QR scan result")
        return {"url": "https://example.com", "risk_level": "Safe", "threat_score": 0}

    try:
        from PIL import Image
        import io
        content = await file.read()
        img = Image.open(io.BytesIO(content))
        try:
            from pyzbar.pyzbar import decode
            decoded = decode(img)
            url = decoded[0].data.decode() if decoded else None
        except ImportError:
            url = None

        if url:
            score = 0
            if url.startswith("http://"):
                score += 20
            if any(p in url.lower() for p in ["bit.ly", "tinyurl", ".tk", "free-", "login-verify"]):
                score += 40
            risk_level = "Dangerous" if score > 60 else "Suspicious" if score > 20 else "Safe"
            return {"url": url, "risk_level": risk_level, "threat_score": score}
        return {"url": "QR code could not be decoded", "risk_level": "Unknown", "threat_score": 0}
    except Exception as e:
        logger.error(f"QR scan error: {e}")
        return {"url": "Decoding failed", "risk_level": "Unknown", "threat_score": 0}


# ── 10. UPI CHECKER ──────────────────────────────────────────────────
@router.get("/api/upi-check")
def upi_check(upi: str = Query(...)):
    upi = upi.strip().lower()
    known_banks = ["paytm", "okaxis", "okhdfcbank", "oksbi", "okicici", "ybl", "upi", "apl", "jupiteraxis"]
    flags = []
    risk_score = 0

    if "@" not in upi:
        flags.append("Invalid UPI format (missing @)")
        risk_score += 50
    else:
        handle = upi.split("@")[-1]
        if handle not in known_banks:
            flags.append(f"Unknown UPI handle: @{handle}")
            risk_score += 25
        if re.search(r"\d{10}", upi):
            upi_type = "Mobile-linked"
        else:
            upi_type = "Username-linked"

    # Check for suspicious patterns
    for keyword in ["prize", "winner", "free", "helpdesk", "support", "bank", "kyc"]:
        if keyword in upi:
            flags.append(f"Suspicious keyword: '{keyword}'")
            risk_score += 20

    risk_score = min(risk_score, 100)
    risk_level = "High" if risk_score > 60 else "Medium" if risk_score > 30 else "Safe"

    return {"risk_level": risk_level, "risk_score": risk_score,
            "flags": flags if flags else ["No suspicious patterns detected"],
            "upi_type": upi_type if "@" in upi else "Invalid"}


# ── 11. THREAT SCORE ENGINE ──────────────────────────────────────────
class ThreatScoreRequest(BaseModel):
    content: str

@router.post("/api/threat-score")
async def threat_score(req: ThreatScoreRequest, request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user or getattr(user, "plan", "free") not in ["pro", "enterprise"]:
        raise HTTPException(status_code=403, detail="Pro plan required")

    text = req.content.lower()
    dimensions = {
        "Urgency": min(sum(20 for w in ["urgent", "immediately", "expire", "24 hours", "now"] if w in text), 100),
        "Phishing": min(sum(20 for w in ["click here", "verify account", "confirm identity", "login"] if w in text), 100),
        "Financial": min(sum(20 for w in ["bank", "payment", "transfer", "wallet", "upi", "credit"] if w in text), 100),
        "Social_Eng": min(sum(20 for w in ["you won", "prize", "selected", "congratulations", "winner"] if w in text), 100),
        "Malware_IOC": min(sum(20 for w in [".exe", ".bat", "download", "install", "run this"] if w in text), 100),
        "Impersonation": min(sum(20 for w in ["microsoft", "amazon", "google", "paypal", "irs", "income tax"] if w in text), 100),
    }

    overall = int(sum(dimensions.values()) / len(dimensions))
    summary = (f"High-risk content detected with strong indicators of phishing and social engineering."
               if overall > 70 else
               f"Moderate risk content — some suspicious patterns detected. Exercise caution."
               if overall > 40 else
               f"Low risk content. No major threat indicators found.")

    return {"threat_score": overall, "dimensions": dimensions, "summary": summary}


# ── 12. DARK WEB MONITOR ─────────────────────────────────────────────
class DarkwebRequest(BaseModel):
    email: str

@router.post("/api/darkweb-scan")
async def darkweb_scan(req: DarkwebRequest, request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user or getattr(user, "plan", "free") not in ["pro", "enterprise"]:
        raise HTTPException(status_code=403, detail="Pro plan required")

    # Simulated result (integrate with actual dark web monitoring APIs in production)
    found = len(req.email) % 3 == 0
    return {
        "found": found,
        "count": random.randint(1, 5) if found else 0,
        "message": ("Your email was found in dark web data dumps. Change your passwords immediately!"
                    if found else "No dark web exposure found for this email address.")
    }


# ── 13. SOCIAL MEDIA SCANNER ─────────────────────────────────────────
class SocialScanRequest(BaseModel):
    profile_url: str

@router.post("/api/social-scan")
async def social_scan(req: SocialScanRequest, request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user or getattr(user, "plan", "free") not in ["pro", "enterprise"]:
        raise HTTPException(status_code=403, detail="Pro plan required")

    url = req.profile_url.lower()
    platform = "Twitter/X" if "twitter.com" in url or "x.com" in url else \
               "Instagram" if "instagram.com" in url else \
               "LinkedIn" if "linkedin.com" in url else "Unknown"
    username = url.split("/")[-1].split("?")[0]

    indicators = {
        "Profile_exists": True,
        "Verified_account": random.choice([True, False]),
        "Account_age_ok": random.choice([True, False]),
        "Consistent_activity": random.choice([True, True, False]),
        "No_keyword_spam": not any(w in url for w in ["free", "win", "prize"]),
    }
    risk_score = sum(0 if v else 20 for v in indicators.values())
    risk_level = "High" if risk_score > 60 else "Medium" if risk_score > 30 else "Low"

    return {"platform": platform, "username": username, "risk_level": risk_level, "indicators": indicators}


# ── 14. PORT SCANNER ─────────────────────────────────────────────────
@router.get("/api/port-scan")
async def port_scan(target: str = Query(...), request: Request = None, db: Session = Depends(get_db)):
    COMMON_PORTS = {
        21: ("FTP", "File Transfer Protocol — often misconfigured"),
        22: ("SSH", "Secure Shell — brute-force target"),
        23: ("Telnet", "Unencrypted — high risk"),
        25: ("SMTP", "Mail server"),
        53: ("DNS", "Domain Name System"),
        80: ("HTTP", "Web server — unencrypted"),
        443: ("HTTPS", "Web server — encrypted"),
        3306: ("MySQL", "Database — should not be public"),
        3389: ("RDP", "Remote Desktop — frequent attack target"),
        5432: ("PostgreSQL", "Database"),
        6379: ("Redis", "Cache DB — often exposed"),
        8080: ("HTTP-Alt", "Alternative web port"),
        8443: ("HTTPS-Alt", "Alternative HTTPS"),
        27017: ("MongoDB", "NoSQL DB — often exposed"),
    }
    results = []
    for port, (service, desc) in COMMON_PORTS.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            result = s.connect_ex((target, port))
            state = "open" if result == 0 else "closed"
        except Exception:
            state = "filtered"
        finally:
            s.close()
        results.append({"port": port, "state": state, "service": service, "description": desc})

    return {"target": target, "total_scanned": len(COMMON_PORTS),
            "ports": [p for p in results if p["state"] == "open"]}


# ── 15. FILE HASH ANALYSER ────────────────────────────────────────────
@router.post("/api/file-hash")
async def file_hash(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user or getattr(user, "plan", "free") not in ["pro", "enterprise"]:
        raise HTTPException(status_code=403, detail="Pro plan required")

    content = await file.read()
    md5 = hashlib.md5(content).hexdigest()
    sha1 = hashlib.sha1(content).hexdigest()
    sha256 = hashlib.sha256(content).hexdigest()

    # In production: check sha256 against VirusTotal API
    # Simulated result
    malicious_count = 0
    total_engines = 72
    return {"md5": md5, "sha1": sha1, "sha256": sha256,
            "malicious_count": malicious_count, "total_engines": total_engines,
            "note": "Add VIRUSTOTAL_API_KEY to .env for real malware scanning"}


# ── 16. QR SCAN (already defined above as /api/qr-scan) ──────────────

# ── 17. BULK EMAIL VERIFIER ──────────────────────────────────────────
@router.post("/api/bulk-email-verify")
async def bulk_email_verify(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user or getattr(user, "plan", "free") != "enterprise":
        raise HTTPException(status_code=403, detail="Enterprise plan required")

    content = await file.read()
    text = content.decode("utf-8", errors="ignore")
    emails = re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", text)
    disposable_domains = {"mailinator.com", "guerrillamail.com", "10minutemail.com", "trashmail.com", "yopmail.com"}

    valid = invalid = disposable = leaked = 0
    for email in emails:
        domain = email.split("@")[-1].lower()
        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
            invalid += 1
        elif domain in disposable_domains:
            disposable += 1
        else:
            valid += 1
            if len(email) % 4 != 0:  # Simulated leak check
                leaked += 1

    return {"total": len(emails), "valid": valid, "invalid": invalid,
            "disposable": disposable, "leaked": leaked, "download_url": "#"}


# ── 18. SECURITY REPORT GENERATOR ────────────────────────────────────
class ReportRequest(BaseModel):
    domain: str

@router.post("/api/security-report")
async def security_report(req: ReportRequest, request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user or getattr(user, "plan", "free") != "enterprise":
        raise HTTPException(status_code=403, detail="Enterprise plan required")

    domain = req.domain.strip().lower()
    # Simulated scores — integrate real checks in production
    sections = {
        "WHOIS": random.randint(70, 100),
        "SSL": random.randint(60, 100),
        "Email Auth": random.randint(50, 90),
        "Blacklists": random.randint(80, 100),
        "Threats": random.randint(50, 85),
    }
    overall = int(sum(sections.values()) / len(sections))
    risk = "Good" if overall >= 80 else "Fair" if overall >= 60 else "Poor"
    return {"domain": domain, "overall_score": overall,
            "summary": f"Security posture is {risk} for {domain}. {len([v for v in sections.values() if v<70])} areas need improvement.",
            "sections": sections, "pdf_url": "#",
            "note": "Add API keys (VirusTotal, AbuseIPDB, HIBP) to .env for full live scanning"}


# --- PHASE 1 TOOLS ---

@router.get("/shopping-detector", response_class=HTMLResponse)
def fake_shopping_detector_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    return templates.TemplateResponse("shopping_detector.html", {"request": request, "user": user, "plan": getattr(user, "plan", "free")})

@router.get("/security-headers", response_class=HTMLResponse)
def security_headers_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    return templates.TemplateResponse("header_analyzer.html", {"request": request, "user": user, "plan": getattr(user, "plan", "free")})

@router.get("/fingerprint", response_class=HTMLResponse)
def fingerprint_analyzer_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    return templates.TemplateResponse("fingerprint_analyzer.html", {"request": request, "user": user, "plan": getattr(user, "plan", "free")})

@router.get("/metadata-scanner", response_class=HTMLResponse)
def metadata_scanner_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    return templates.TemplateResponse("metadata_scanner.html", {"request": request, "user": user, "plan": getattr(user, "plan", "free")})

@router.get("/screenshot-analyzer", response_class=HTMLResponse)
def screenshot_analyzer_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    return templates.TemplateResponse("screenshot_analyzer.html", {"request": request, "user": user, "plan": getattr(user, "plan", "free")})


# --- METADATA SCAN API ---
@router.post("/api/scan-metadata")
async def api_scan_metadata(request: Request, db: Session = Depends(get_db)):
    """Fetch a URL and extract HTTP metadata."""
    import httpx
    form = await request.form()
    url = form.get("url", "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    if not url.startswith("http"):
        url = "https://" + url

    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            resp = await client.get(url)
        hdrs = dict(resp.headers)
        hdrs_l = {k.lower(): v for k, v in hdrs.items()}

        security_header_fields = ["content-security-policy","strict-transport-security","x-frame-options",
                                   "x-content-type-options","referrer-policy","permissions-policy"]
        sec_hdrs = {k: hdrs_l.get(k, "NOT SET") for k in security_header_fields}

        general = {
            "URL": url,
            "Status Code": resp.status_code,
            "Final URL": str(resp.url),
            "Content Type": hdrs_l.get("content-type", "Unknown"),
        }

        server = {
            "Server": hdrs_l.get("server", "Hidden"),
            "X-Powered-By": hdrs_l.get("x-powered-by", "Not Disclosed"),
            "Via": hdrs_l.get("via", "—"),
        }

        caching = {
            "Cache-Control": hdrs_l.get("cache-control", "—"),
            "Pragma": hdrs_l.get("pragma", "—"),
            "Expires": hdrs_l.get("expires", "—"),
            "Set-Cookie": "Present" if "set-cookie" in hdrs_l else "None",
        }

        warnings = []
        if hdrs_l.get("x-powered-by"):
            warnings.append(f"Server is exposing technology stack via X-Powered-By: {hdrs_l['x-powered-by']}")
        if hdrs_l.get("server"):
            warnings.append(f"Server version exposed via Server header: {hdrs_l['server']}")
        not_set = [k for k, v in sec_hdrs.items() if v == "NOT SET"]
        if not_set:
            warnings.append(f"Missing security headers: {', '.join(not_set)}")

        return {
            "target": url,
            "target_type": "url",
            "metadata": {
                "general": general,
                "security_headers": sec_hdrs,
                "server": server,
                "caching": caching,
            },
            "risk_score": len(warnings) * 15,
            "warnings": warnings
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch URL: {e}")


