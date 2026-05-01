import asyncio
import os
from dotenv import load_dotenv

# Load env before importing settings
load_dotenv()

from backend.app.services.safe_browsing import safe_browsing

async def main():
    print(f"API Key: {safe_browsing.api_key[:10]}...")
    
    # Test a known safe URL
    is_safe_malicious = await safe_browsing.check_url("https://www.google.com")
    print(f"Is google.com malicious? {is_safe_malicious}")
    
    # Test a known bad URL (Google's test malware site)
    is_bad_malicious = await safe_browsing.check_url("http://malware.testing.google.test/testing/malware/")
    print(f"Is malware.testing malicious? {is_bad_malicious}")

if __name__ == "__main__":
    asyncio.run(main())
