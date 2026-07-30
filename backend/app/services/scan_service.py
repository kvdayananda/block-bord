"""
Block Bord AI — Scan Service Helper
Allows scanning a single URL or content string with whitelist/blacklist and risk engine integration.
"""
import hashlib
import json
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from backend.app.models import ScanHistory, WhitelistDomain, BlacklistDomain
from backend.app.services.risk_engine import calculate_risk, _extract_domains

def normalize_url(url: str) -> str:
    if not url:
        return ""
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    try:
        parsed = urlparse(url)
        tracking_params = {'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'fbclid', 'gclid', 'sourceid', 'gs_lcrp'}
        qs = parse_qs(parsed.query)
        filtered_qs = {k: v for k, v in qs.items() if k.lower() not in tracking_params}
        new_query = urlencode(filtered_qs, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)).lower()
    except Exception:
        return url.lower()

async def run_scan(content: str, user_id: int, db: Session, url: str = None) -> dict:
    """Core scan logic callable from bulk scanning or regular scan routes."""
    target_url = url if url else content
    norm_url = normalize_url(target_url)
    content_hash_input = (norm_url + (content or "")).encode('utf-8')
    content_hash = hashlib.sha256(content_hash_input).hexdigest()

    urls, domains = _extract_domains(content)

    # 1. Whitelist Check
    for d in domains:
        if db.query(WhitelistDomain).filter(WhitelistDomain.domain == d).first():
            return {
                "risk_score": 0,
                "risk_level": "OK",
                "reasons": [f"Domain '{d}' is on the trusted whitelist."],
                "category": "Whitelisted",
                "scam_intent": "None Detected"
            }

    # 2. Blacklist Check
    for d in domains:
        hit = db.query(BlacklistDomain).filter(BlacklistDomain.domain == d).first()
        if hit:
            return {
                "risk_score": 100,
                "risk_level": "High",
                "reasons": [
                    f"Domain '{d}' is strictly blacklisted by administrators.",
                    hit.reason or "Known dangerous domain."
                ],
                "category": "Blacklisted Domain",
                "scam_intent": "Phishing"
            }

    # 3. Full Risk Analysis
    result = await calculate_risk(
        text=content,
        url=target_url
    )

    # 4. Save to ScanHistory
    score_val = float(result.get("risk_score", 0))
    scan = ScanHistory(
        content=content,
        url_hash=content_hash,
        risk_score=score_val,
        risk_level=str(result.get("risk_level", "Medium")),
        reasons=json.dumps(result.get("reasons", [])),
        category=result.get("category", "General Threat"),
        scam_intent=result.get("scam_intent", "None Detected"),
        user_id=user_id,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Real-time websocket threat feed broadcast
    try:
        from backend.app.utils.broadcaster import broadcaster
        import asyncio
        asyncio.create_task(broadcaster.broadcast({
            "url": target_url,
            "risk_score": scan.risk_score,
            "risk_level": scan.risk_level,
            "category": scan.category,
            "time": datetime.now(timezone.utc).strftime('%H:%M:%S')
        }))
    except Exception:
        pass

    return {
        "risk_score": scan.risk_score,
        "risk_level": scan.risk_level,
        "reasons": result.get("reasons", []),
        "category": scan.category,
        "scam_intent": scan.scam_intent,
        "scan_id": scan.id
    }

