from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from risk_engine import calculate_risk
from database import SessionLocal, ScanHistory
from fastapi import Form
from fastapi.responses import RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from passlib.context import CryptContext
from database import User

app = FastAPI(title="Block Bord AI")

app.add_middleware(SessionMiddleware, secret_key="super-secret-key")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates
templates = Jinja2Templates(directory="templates")

class ScanRequest(BaseModel):
    content: str

# HOME PAGE
@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@app.post("/register")
def register(request: Request, username: str = Form(...), email: str = Form(...), password: str = Form(...)):
    db = SessionLocal()

    hashed_password = pwd_context.hash(password)

    user = User(username=username, email=email, password=hashed_password)
    db.add(user)
    db.commit()
    db.close()

    return RedirectResponse("/login", status_code=302)

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

@app.get("/admin", response_class=HTMLResponse)
def admin_panel(request: Request):
    if "user" not in request.session:
        return RedirectResponse("/login")

    db = SessionLocal()
    scans = db.query(ScanHistory).order_by(ScanHistory.created_at.desc()).all()
    db.close()

    return templates.TemplateResponse("admin.html", {"request": request, "scans": scans})