from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from risk_engine import calculate_risk
from database import SessionLocal, ScanHistory

app = FastAPI(title="Block Bord AI")

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates
templates = Jinja2Templates(directory="templates")

class ScanRequest(BaseModel):
    content: str

# HOME PAGE
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# SCAN API
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

# ADMIN PAGE
@app.get("/admin", response_class=HTMLResponse)
def admin_panel():
    db = SessionLocal()
    scans = db.query(ScanHistory).order_by(ScanHistory.created_at.desc()).all()
    db.close()

    html_content = "<h1>Block Bord - Scan History</h1><ul>"

    for scan in scans:
        html_content += f"<li><strong>{scan.risk_level}</strong> | Score: {scan.risk_score}% | {scan.created_at}<br>{scan.content}</li><br>"

    html_content += "</ul>"

    return HTMLResponse(content=html_content)