"""
Block Bord AI — Public API & Test Pages
"""
from fastapi import APIRouter, Depends
from fastapi.requests import Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from backend.app.dependencies import get_db, get_current_user

router = APIRouter(tags=["Public"])
templates = Jinja2Templates(directory="frontend/templates")


# ── Landing Page ──
@router.get("/", response_class=HTMLResponse)
def landing_page(request: Request):
    return templates.TemplateResponse("landing.html", {"request": request})


# ── About ──
@router.get("/about", response_class=HTMLResponse)
def about_page(request: Request):
    return templates.TemplateResponse("about.html", {"request": request})


# ── Contact ──
@router.get("/contact", response_class=HTMLResponse)
def contact_page(request: Request):
    return templates.TemplateResponse("contact.html", {"request": request})


# ── Privacy, Terms, Cookie Policy ──
@router.get("/privacy", response_class=HTMLResponse)
def privacy_page(request: Request):
    return templates.TemplateResponse("privacy.html", {"request": request})

@router.get("/terms", response_class=HTMLResponse)
def terms_page(request: Request):
    return templates.TemplateResponse("terms.html", {"request": request})

@router.get("/cookie", response_class=HTMLResponse)
def cookie_page(request: Request):
    return templates.TemplateResponse("cookie.html", {"request": request})


# ── Leak Checker (sidebar shortcut, canonical at /tools/leak-checker) ──
@router.get("/leak-checker", response_class=HTMLResponse)
def leak_checker_shortcut(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    plan = getattr(user, "plan", "free") if user else "free"
    return templates.TemplateResponse("leak_checker.html", {"request": request, "user": user, "plan": plan})


# ── Scam Map (sidebar shortcut, canonical at /tools/scam-map) ──
@router.get("/scam-map", response_class=HTMLResponse)
def scam_map_shortcut(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    plan = getattr(user, "plan", "free") if user else "free"
    return templates.TemplateResponse("scam_map.html", {"request": request, "user": user, "plan": plan})



# ── Test pages for extension validation ──
@router.get("/test-phishing", response_class=HTMLResponse)
def test_phishing(request: Request):
    return HTMLResponse("""
    <html>
      <head><title>Test Phishing Page</title></head>
      <body style="padding:50px;font-family:sans-serif;">
        <h1>Block Bord Test Page</h1>
        <p>Contains high-risk keywords to test the extension.</p>
        <div style="background:#fff5f5;border:1px solid #feb2b2;padding:20px;border-radius:8px;">
          <h3>Urgent: Your bank account is suspended!</h3>
          <p>Verify your identity immediately: http://secure-verify.bank-login.xyz/update</p>
          <p>Claim your reward of Rs. 5000 now!</p>
        </div>
        <p style="color:#666;margin-top:20px;">If working, a <b>RED OVERLAY</b> should appear.</p>
      </body>
    </html>
    """)


@router.get("/test-upi", response_class=HTMLResponse)
def test_upi_scam(request: Request):
    return HTMLResponse("""
    <html><body style="padding:50px;font-family:sans-serif;">
      <h1>UPI Scam Simulation</h1>
      <div style="background:#fff5f5;border:1px solid #feb2b2;padding:20px;border-radius:8px;">
        <h3>Verify Refund Request</h3>
        <p>To receive your Rs. 2500 refund, click the UPI link below and enter your PIN.</p>
        <code style="display:block;padding:10px;background:#eee;">upi://pay?pa=scammer@pay&pn=Refund&am=2500</code>
      </div>
    </body></html>
    """)


@router.get("/test-reward", response_class=HTMLResponse)
def test_reward_scam(request: Request):
    return HTMLResponse("""
    <html><body style="padding:50px;font-family:sans-serif;">
      <h1>Reward Scam Simulation</h1>
      <div style="background:#e6fffa;border:1px solid #38b2ac;padding:20px;border-radius:8px;">
        <h3>Congratulations! You Won!</h3>
        <p>You have been selected to win a free iPhone. Claim your prize immediately!</p>
        <p>Click here: http://iphones-for-everyone-winner.top/claim-now</p>
      </div>
    </body></html>
    """)


# ──────────────────────────────────────────────────────────────
# SEO: sitemap.xml + robots.txt
# ──────────────────────────────────────────────────────────────
from fastapi.responses import PlainTextResponse, Response

@router.get("/sitemap.xml", include_in_schema=False)
def sitemap(request: Request):
    base = str(request.base_url).rstrip("/")
    urls = [
        "/", "/about", "/pricing", "/contact", "/status",
        "/privacy", "/terms", "/cookie",
        "/tools", "/tools/url-scanner", "/tools/domain-inspector",
        "/tools/ip-lookup", "/tools/email-verifier", "/tools/email-header",
        "/tools/qr-scanner", "/tools/password-checker", "/tools/ssl-checker",
        "/tools/upi-checker", "/tools/social-scanner", "/tools/darkweb-monitor",
        "/tools/file-hash", "/tools/malware-intel", "/tools/port-scanner",
        "/tools/phishing-sim", "/tools/threat-score", "/tools/security-report",
        "/tools/shopping-detector", "/tools/security-headers",
        "/tools/fingerprint", "/tools/metadata-scanner", "/tools/screenshot-analyzer",
        "/login", "/register",
    ]
    entries = "\n".join([
        f"  <url><loc>{base}{u}</loc><changefreq>weekly</changefreq><priority>0.8</priority></url>"
        for u in urls
    ])
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
{entries}
</urlset>"""
    return Response(content=xml, media_type="application/xml")


@router.get("/robots.txt", include_in_schema=False)
def robots():
    content = """User-agent: *
Allow: /
Disallow: /app/
Disallow: /admin/
Disallow: /api/
Disallow: /settings
Disallow: /checkout/
Disallow: /payment/
Sitemap: https://blockbord.ai/sitemap.xml
"""
    return PlainTextResponse(content=content)

