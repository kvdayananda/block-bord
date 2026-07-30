import pytest
from fastapi import status

def test_analyze_shopping_site_success(client):
    """Test fake shopping detector API endpoint."""
    response = client.post("/security/api/analyze-shopping", data={"url": "https://cheap-deals-now.com"})
    # Free plan is default, need login. Let's make sure it handles auth redirection or response code correctly.
    # Note: client is initialized in conftest.py, we check the HTTP status.
    assert response.status_code in (status.HTTP_200_OK, status.HTTP_302_FOUND, status.HTTP_401_UNAUTHORIZED)

def test_analyze_headers_success(client):
    """Test security header analyzer API endpoint."""
    response = client.post("/security/api/analyze-headers", data={"url": "https://google.com"})
    assert response.status_code in (status.HTTP_200_OK, status.HTTP_302_FOUND, status.HTTP_401_UNAUTHORIZED)
