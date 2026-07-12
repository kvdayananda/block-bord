"""
Block Bord AI — Public Pages Router
Routes: /, /about, /status, /contact, /privacy, /terms, /cookie, /test-*
No authentication required for these pages.
"""
from fastapi import APIRouter
from fastapi.requests import Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from backend.app.utils.seo import seo_context

router = APIRouter(tags=["Public"])
templates = Jinja2Templates(directory="frontend/templates")


@router.get("/", response_class=HTMLResponse)
def landing(request: Request):
    return templates.TemplateResponse("landing.html", {"request": request})


@router.get("/about", response_class=HTMLResponse)
def about_page(request: Request):
    return templates.TemplateResponse("about.html", {"request": request})


@router.get("/status", response_class=HTMLResponse)
def status_page(request: Request):
    return templates.TemplateResponse("status.html", {"request": request})


@router.get("/contact", response_class=HTMLResponse)
def contact_page(request: Request):
    return templates.TemplateResponse("contact.html", {"request": request})


@router.get("/privacy", response_class=HTMLResponse)
def privacy_page(request: Request):
    return templates.TemplateResponse("privacy.html", {"request": request})


@router.get("/terms", response_class=HTMLResponse)
def terms_page(request: Request):
    return templates.TemplateResponse("terms.html", {"request": request})


@router.get("/cookie", response_class=HTMLResponse)
def cookie_page(request: Request):
    return templates.TemplateResponse("cookie.html", {"request": request})


@router.get("/health")
def health_check():
    """Health check for Render, Docker, and load balancers."""
    return {"status": "ok", "version": "2.0.0", "service": "blockbord-ai"}


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
