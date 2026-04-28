import pytest
from backend.app.services.risk_engine import calculate_risk

@pytest.mark.asyncio
async def test_risk_engine_safe_url():
    """Test a known safe URL (Google)."""
    result = await calculate_risk(text="Visit google.com", url="https://google.com")
    assert result["risk_score"] == 0
    assert result["risk_level"] == "OK"
    assert "Safe" in result["category"]

@pytest.mark.asyncio
async def test_risk_engine_upi_scam():
    """Test UPI scam detection and intent."""
    text = "Click to pay and get refund: upi://pay?pa=scam@upi&am=1000"
    result = await calculate_risk(text=text, url=None)
    
    # Heuristics should pick up UPI patterns
    assert result["risk_score"] >= 70
    assert result["risk_level"] == "High"
    assert "UPI" in result["scam_intent"]
    assert "UPI" in result["category"]

@pytest.mark.asyncio
async def test_risk_engine_credential_harvesting():
    """Test phishing keywords like password/otp."""
    text = "Your account is locked. Please enter your password and OTP here to unlock."
    result = await calculate_risk(text=text, url="http://verify-account-security.xyz")
    
    assert result["risk_score"] >= 50
    assert "Credential Harvesting" in result["scam_intent"]

@pytest.mark.asyncio
async def test_risk_engine_lottery_scam():
    """Test lottery/prize scam intent."""
    text = "Congratulations! You won a lottery of $1,000,000. Claim your prize now."
    result = await calculate_risk(text=text, url="http://claim-my-prize.top")
    
    assert result["risk_score"] >= 40
    assert "Lottery / Prize Scam" in result["scam_intent"]

@pytest.mark.asyncio
async def test_risk_engine_suspicious_tld():
    """Test suspicious TLD (.top, .xyz)."""
    result = await calculate_risk(text="Just a link", url="http://normal-site.top")
    # Heuristic should give some score for .top, but ML might override category
    assert result["risk_score"] > 10
    assert any(word in result["category"] for word in ["Heuristic", "AI-Detected", "ML"])

@pytest.mark.asyncio
async def test_risk_engine_social_engineering():
    """Test urgent action social engineering."""
    # Needs BOTH an urgency word (URGENT) and an action word (Verify)
    text = "URGENT: Your account is blocked. Verify now to prevent this: http://bank-security.cf"
    result = await calculate_risk(text=text, url=None)
    
    assert result["risk_score"] >= 50
    assert "Social Engineering" in result["scam_intent"]

@pytest.mark.asyncio
async def test_risk_engine_deduplication():
    """Ensure reasons are deduplicated."""
    # This might trigger 'password' and 'otp' which both add 'Credential harvesting'
    text = "password password password otp otp otp"
    result = await calculate_risk(text=text, url=None)
    
    # The reasons list should have unique entries
    assert len(result["reasons"]) == len(set(result["reasons"]))
