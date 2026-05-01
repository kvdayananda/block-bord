"""
Block Bord AI — Google Safe Browsing Integration
Checks URLs against Google's database of malicious sites in real-time.
"""
import httpx
import logging
import asyncio
import time
from backend.app.config import settings

logger = logging.getLogger("blockbord.safe_browsing")

_sb_cache = {}
_sb_cache_ttl = 3600
_sb_semaphore = asyncio.Semaphore(10)

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

        now = time.time()
        # Clean up cache occasionally (very naive cleanup)
        if len(_sb_cache) > 5000:
            keys_to_del = [k for k, (ts, _) in _sb_cache.items() if now - ts > _sb_cache_ttl]
            for k in keys_to_del:
                del _sb_cache[k]

        if url in _sb_cache:
            ts, result = _sb_cache[url]
            if now - ts < _sb_cache_ttl:
                return result

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

        async with _sb_semaphore:
            try:
                async with httpx.AsyncClient(timeout=3.0) as client:
                    for attempt in range(2):
                        try:
                            response = await client.post(self.api_url, json=payload)
                            if response.status_code == 200:
                                data = response.json()
                                result = "matches" in data
                                _sb_cache[url] = (now, result)
                                return result
                            else:
                                logger.warning(f"Safe Browsing API Error: {response.status_code} - {response.text}")
                                return False
                        except httpx.TimeoutException:
                            if attempt == 1:
                                logger.warning(f"Safe Browsing timeout for {url} after 2 attempts.")
                                return False
            except Exception as e:
                logger.error(f"Safe Browsing Connection Error: {e}")
                return False

# Singleton instance
safe_browsing = SafeBrowsingService()
