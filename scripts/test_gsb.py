import asyncio
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.app.services.safe_browsing import safe_browsing

async def test_gsb():
    # A known malware testing URL provided by Google
    test_url = "http://malware.testing.google.test/testing/malware/"
    print(f"Checking URL: {test_url}")
    
    is_malicious = await safe_browsing.check_url(test_url)
    
    if is_malicious:
        print("\nSUCCESS: Google Safe Browsing API is WORKING!")
        print("The test URL was correctly flagged as malicious.")
    else:
        print("\nFAILED: Google Safe Browsing API is NOT flagging the URL.")
        print("Check your terminal logs for any 'Safe Browsing API Error' messages.")
        print("Possible reasons:")
        print("1. API is still disabled in Google Cloud Console.")
        print("2. API Key is incorrect or has restrictions.")
        print("3. Quota exceeded.")

if __name__ == "__main__":
    asyncio.run(test_gsb())
