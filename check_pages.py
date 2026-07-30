import httpx
import asyncio

async def check_pages():
    routes = [
        "/",
        "/pricing",
        "/about",
        "/contact",
        "/privacy",
        "/terms",
        "/cookie",
        "/login",
        "/register",
        "/forgot-password",
        "/dashboard",
        "/security",
        "/admin"
    ]
    
    async with httpx.AsyncClient() as client:
        for route in routes:
            url = f"http://127.0.0.1:8000{route}"
            try:
                response = await client.get(url, follow_redirects=False)
                print(f"{route}: {response.status_code}")
            except Exception as e:
                print(f"{route}: Error ({e})")

if __name__ == "__main__":
    asyncio.run(check_pages())
