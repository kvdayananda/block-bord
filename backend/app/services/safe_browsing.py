"""
Block Bord AI — Google Safe Browsing Integration
Checks URLs against Google's database of malicious sites.
Currently implements a placeholder flow as requested by the user.
"""
import httpx
import logging
from backend.app.config import settings

logger = logging.getLogger("blockbord.safe_browsing")

class SafeBrowsingService:
    def __init__(self):
        self.api_key = settings.google_safe_browsing_key
        self.api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}"

    async def check_url(self, url: str) -> bool:
        """
        Checks if a URL is flagged by Google Safe Browsing.
        Returns True if malicious, False otherwise.
        """
        # Google Safe Browsing only supports http/https
        if not url or not (url.startswith("http://") or url.startswith("https://")):
            return False

        if not self.api_key or self.api_key == "YOUR_GOOGLE_SAFE_BROWSING_KEY":
            # Mock behavior for placeholder
            # Flagging known test phishing domains if in dev/mock mode
            if "phishing-test-site.com" in url or "malware.testing.google.test" in url:
                logger.info(f"[MOCK] Safe Browsing flagged: {url}")
                return True
            return False

        payload = {
            "client": {
                "clientId": "block-bord-ai",
                "clientVersion": "2.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(self.api_url, json=payload, timeout=5.0)
                if response.status_code == 200:
                    data = response.json()
                    # If 'matches' exists in response, it's malicious
                    return "matches" in data
                else:
                    logger.error(f"Safe Browsing API Error: {response.status_code} - {response.text}")
                    return False
        except Exception as e:
            logger.error(f"Safe Browsing Connection Error: {e}")
            return False

# Singleton instance
safe_browsing = SafeBrowsingService()
