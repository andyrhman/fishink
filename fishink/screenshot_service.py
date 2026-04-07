import io
from urllib.parse import urlparse
import cloudinary.uploader
from playwright.sync_api import sync_playwright, Error as PlaywrightError
from .insight_service import normalize_url

def is_valid_http_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False

def capture_website_screenshot(raw_url: str) -> dict:
    url = normalize_url(raw_url)
    if not is_valid_http_url(url):
        return {"success": False, "error": "Invalid URL"}

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"]
            )
            page = browser.new_page(viewport={"width": 1440, "height": 900})
            page.goto(url, wait_until="networkidle", timeout=30000)
            screenshot_bytes = page.screenshot(full_page=False)
            browser.close()
    except Exception as e:
        return {"success": False, "error": f"Screenshot failed: {str(e)}"}

    upload_result = cloudinary.uploader.upload(
        io.BytesIO(screenshot_bytes),
        folder="phishing_screenshots",
        resource_type="image",
    )

    return {
        "success": True,
        "url": raw_url,
        "normalized_url": url,
        "screenshot_url": upload_result.get("secure_url"),
        "public_id": upload_result.get("public_id"),
    }