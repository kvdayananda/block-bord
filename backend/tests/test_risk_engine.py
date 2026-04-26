import pytest
from backend.app.services.risk_engine import calculate_risk

@pytest.mark.asyncio
async def test_risk_safe_domain():
    result = await calculate_risk(text="Checkout my website", url="google.com")
    assert result["risk_level"] == "OK"
    assert "Trusted official domain" in result["reasons"][0]

@pytest.mark.asyncio
async def test_risk_suspicious_url():
    # URL with encoded chars and high entropy-like stuff
    result = await calculate_risk(text="Click this link: http://bit.ly/random-scam-12345")
    # bit.ly is a shortener -> suspicious
    assert result["risk_level"] in ["Suspicious", "High"]
    assert any("shortener" in r.lower() for r in result["reasons"])

@pytest.mark.asyncio
async def test_risk_upi_scam():
    result = await calculate_risk(text="Send money to upi://pay?pa=scammer@upi&am=1000")
    assert result["risk_level"] == "High"
    assert any("UPI scam" in r for r in result["reasons"])
