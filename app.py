from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from passlib.context import CryptContext
from pydantic import BaseModel

from database import SessionLocal, ScanHistory, User
from risk_engine import calculate_risk

# -----------------------------
# CREATE APP FIRST
# -----------------------------
app = FastAPI(title="Block Bord AI")

app.add_middleware(SessionMiddleware, secret_key="super-secret-key")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Static & Templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# -----------------------------
# HOME ROUTE
# -----------------------------
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# -----------------------------
# SCAN ROUTE
# -----------------------------
class ScanRequest(BaseModel):
    content: str

@app.post("/scan")
def scan_content(request: ScanRequest):
    result = calculate_risk(request.content)

    db = SessionLocal()
    new_scan = ScanHistory(
        content=request.content,
        risk_score=result["risk_score"],
        risk_level=result["risk_level"]
    )
    db.add(new_scan)
    db.commit()
    db.close()

    return result

# -----------------------------
# REGISTER
# -----------------------------
@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
def register(username: str = Form(...), email: str = Form(...), password: str = Form(...)):
    db = SessionLocal()
    hashed_password = pwd_context.hash(password)

    user = User(username=username, email=email, password=hashed_password)
    db.add(user)
    db.commit()
    db.close()

    return RedirectResponse("/login", status_code=302)

# -----------------------------
# LOGIN
# -----------------------------
@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    db = SessionLocal()
    user = db.query(User).filter(User.username == username).first()
    db.close()

    if user and pwd_context.verify(password, user.password):
        request.session["user"] = user.username
        return RedirectResponse("/", status_code=302)

    return HTMLResponse("Invalid credentials", status_code=400)

# -----------------------------
# ADMIN (Protected)
# -----------------------------
@app.get("/admin", response_class=HTMLResponse)
def admin_panel(request: Request):
    if "user" not in request.session:
        return RedirectResponse("/login")

    db = SessionLocal()
    scans = db.query(ScanHistory).order_by(ScanHistory.created_at.desc()).all()
    db.close()

    return templates.TemplateResponse("admin.html", {
        "request": request,
        "scans": scans
    })