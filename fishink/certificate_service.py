import requests
from urllib.parse import urlparse


def get_hostname(raw_url: str) -> str:
    parsed = urlparse(raw_url if raw_url.startswith(("http://", "https://")) else "https://" + raw_url)
    return parsed.hostname or ""


def get_certificate_history(domain: str, limit: int = 10) -> list[dict]:
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()

        data = resp.json()
        results = []
        seen = set()

        for item in data:
            key = (
                item.get("id"),
                item.get("issuer_name"),
                item.get("name_value"),
                item.get("entry_timestamp"),
            )
            if key in seen:
                continue
            seen.add(key)

            results.append({
                "crtsh_id": item.get("id"),
                "issuer_name": item.get("issuer_name"),
                "common_name": item.get("common_name"),
                "name_value": item.get("name_value"),
                "entry_timestamp": item.get("entry_timestamp"),
                "not_before": item.get("not_before"),
                "not_after": item.get("not_after"),
            })

            if len(results) >= limit:
                break

        return results
    except Exception:
        return []


def build_certificate_history(raw_url: str) -> dict:
    domain = get_hostname(raw_url)
    return {
        "url": raw_url,
        "domain": domain,
        "certificate_history": get_certificate_history(domain) if domain else [],
    }