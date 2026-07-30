import re
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api", tags=["PasswordChecker"])

class PasswordRequest(BaseModel):
    password: str

def evaluate(pw: str):
    checks = {
        "len": len(pw) >= 8,
        "upper": bool(re.search(r"[A-Z]", pw)),
        "lower": bool(re.search(r"[a-z]", pw)),
        "num": bool(re.search(r"[0-9]", pw)),
        "sym": bool(re.search(r"[^A-Za-z0-9]", pw)),
        "long": len(pw) >= 12,
    }
    score = sum(checks.values())
    labels = ["Too Weak", "Weak", "Fair", "Good", "Strong", "Very Strong"]
    tips_map = {
        "len": "Use at least 8 characters",
        "upper": "Add uppercase letters (A‑Z)",
        "lower": "Add lowercase letters (a‑z)",
        "num": "Include numbers (0‑9)",
        "sym": "Add special characters (!@#$…)",
        "long": "Aim for 12+ characters for best security",
    }
    tips = [msg for key, msg in tips_map.items() if not checks[key]]
    return {
        "score": score,
        "label": labels[score],
        "checks": checks,
        "tips": tips,
    }

@router.post("/check-password")
async def check_password(req: PasswordRequest):
    if req.password is None:
        raise HTTPException(status_code=400, detail="Password missing")
    return evaluate(req.password)
