import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import tldextract


def normalize_url(raw_url: str) -> str:
    raw_url = str(raw_url).strip()
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url
    return raw_url


def get_hostname(target_url: str) -> str:
    parsed = urlparse(target_url)
    return parsed.hostname or ""


def get_ip_address(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def get_tld(hostname: str) -> str | None:
    try:
        extracted = tldextract.extract(hostname)
        if extracted.suffix:
            return extracted.suffix
        return None
    except Exception:
        return None


def get_location_from_ip(ip_address: str) -> str | None:
    """
    Uses ip-api.com. You can swap this later with another geo-IP provider if needed.
    """
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
        data = resp.json()
        if data.get("status") == "success":
            country = data.get("country", "")
            region = data.get("regionName", "")
            city = data.get("city", "")

            parts = [p for p in [city, region, country] if p]
            return ", ".join(parts) if parts else None
        return None
    except Exception:
        return None


def get_certificate_details(hostname: str, port: int = 443) -> dict | None:
    """
    Fetch TLS certificate details from the server.
    Works only if the site supports HTTPS.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        if not cert:
            return None

        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))

        return {
            "issuer_common_name": issuer.get("commonName"),
            "subject_common_name": subject.get("commonName"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "serial_number": cert.get("serialNumber"),
        }
    except Exception:
        return None

def get_hosting_provider_from_ip(ip_address: str) -> str | None:
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
        data = resp.json()
        if data.get("status") == "success":
            # prefer org, then isp, then as
            return data.get("org") or data.get("isp") or data.get("as")
        return None
    except Exception:
        return None   
    
def build_website_insight(raw_url: str) -> dict:
    url = normalize_url(raw_url)
    hostname = get_hostname(url)

    ip_address = get_ip_address(hostname) if hostname else None
    tld = get_tld(hostname) if hostname else None
    location = get_location_from_ip(ip_address) if ip_address else None
    hosting_provider = get_hosting_provider_from_ip(ip_address) if ip_address else None
    cert_details = get_certificate_details(hostname) if hostname else None

    return {
        "url": raw_url,
        "normalized_url": url,
        "ip_address": ip_address,
        "top_level_domain": tld,
        "location": location,
        "hosting_provider": hosting_provider,
        "detection_date": datetime.now(timezone.utc).isoformat(),
        "certificate_details": cert_details,
    }   