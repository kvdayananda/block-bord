from datetime import datetime, timezone
from sqlalchemy.orm import Session
from backend.app.models import ScanHistory

def norm_risk_level(level: str) -> str:
    """Normalize risk level string to canonical form (High, Suspicious, OK)."""
    l = (level or "").strip().lower()
    if "high" in l:
        return "High"
    if "susp" in l:
        return "Suspicious"
    return "OK"

def get_today_scan_count(db: Session, user_id: int) -> int:
    """Get the number of scans performed by a user today (UTC)."""
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    return (
        db.query(ScanHistory)
        .filter(ScanHistory.user_id == user_id, ScanHistory.created_at >= today_start)
        .count()
    )
