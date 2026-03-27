import pytest

from risk_engine import calculate_risk


def test_calculate_risk_high_upi_scam():
    text = "Urgent! Claim your reward now with UPI://pay?pa=scammer@upi&am=5000"
    result = calculate_risk(text)

    assert isinstance(result, dict)
    assert "risk_score" in result
    assert result["risk_score"] >= 70
    assert result["risk_level"] == "High"
    assert "UPI scam" in result["category"] or "UPI/Payment Fraud" in result["category"]


def test_calculate_risk_ok_text():
    text = "Hello, this is a friendly reminder: your daily meeting starts at 10 AM. Have a great day!"
    result = calculate_risk(text)

    assert isinstance(result, dict)
    assert "risk_score" in result
    assert result["risk_score"] < 35
    assert result["risk_level"] == "OK"
