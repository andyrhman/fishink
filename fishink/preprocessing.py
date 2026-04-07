import re
import math
import urllib.parse
from collections import Counter

import numpy as np

def clean_url(url):
    url = str(url).lower()
    url = re.sub(r"^https?://", "", url)
    url = re.sub(r"^www\.", "", url)
    return url

def sanitize_url(url: str) -> str:
    if url is None:
        return ""

    url = str(url).strip().lower()

    # Remove scheme and www
    url = re.sub(r"^https?://", "", url)
    url = re.sub(r"^www\.", "", url)

    # Mask emails
    url = re.sub(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", "<EMAIL>", url)

    # Mask IPv4
    url = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<IP>", url)

    # Mask long numeric sequences
    url = re.sub(r"\b\d{4,}\b", "<NUMERIC_ID>", url)

    # Mask tokens / hashes / base64-like strings
    url = re.sub(r"\b[a-z0-9+/=]{20,}\b", "<ENCODED>", url)

    # Normalize repeated slashes
    url = re.sub(r"/{2,}", "/", url)

    return url

def calculate_entropy(text):
    if not text:
        return 0.0
    entropy = 0.0
    for x in Counter(text).values():
        p_x = x / len(text)
        entropy += -p_x * math.log2(p_x)
    return entropy

def extract_structural_features(raw_url, masked_url=""):
    def _fallback(raw_url_len):
        v = np.zeros(32, dtype=np.float32)
        v[-1] = raw_url_len
        return v

    try:
        cleaned_raw = re.sub(r"[\x00-\x1f\x7f]", "", str(raw_url))
        parsed_url = cleaned_raw if re.match(r"^https?://", cleaned_raw) else "http://" + cleaned_raw
        parsed = urllib.parse.urlparse(parsed_url)
    except Exception:
        return _fallback(len(str(raw_url)))

    domain_with_port = parsed.netloc.lower()
    domain = domain_with_port.split(":")[0]
    path = parsed.path.lower()
    query = parsed.query.lower()

    features = []
    is_ip = 1.0 if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", domain) else 0.0

    domain_parts = domain.split(".")
    subdomain_depth = 0.0 if is_ip else max(0, len(domain_parts) - 2)
    risky_tlds = [".click", ".xyz", ".top", ".club", ".online", ".site", ".ru", ".tk", ".cf"]
    is_risky_tld = 1.0 if any(domain.endswith(tld) for tld in risky_tlds) else 0.0
    digit_ratio = sum(c.isdigit() for c in domain) / max(1, len(domain))
    hyphen_count = domain.count("-")
    domain_len = len(domain)
    vowel_ratio = sum(c in "aeiou" for c in domain) / max(1, len(domain))
    features.extend([subdomain_depth, is_risky_tld, digit_ratio, hyphen_count, domain_len, vowel_ratio])

    path_depth = path.count("/")
    path_len = len(path)
    exec_exts = [".exe", ".bat", ".sh", ".php", ".dll", ".jar", ".vbs"]
    has_exec = 1.0 if any(path.endswith(ext) for ext in exec_exts) else 0.0
    has_double_ext = 1.0 if path.count(".") >= 2 else 0.0
    path_special_chars = sum(c in "-_@~" for c in path) / max(1, path_len)
    features.extend([path_depth, path_len, has_exec, has_double_ext, path_special_chars])

    params = urllib.parse.parse_qs(query)
    sensitive_words = ["token", "email", "redirect", "url", "next", "file", "auth", "key", "session"]
    param_count = len(params)
    sensitive_count = sum(1 for p in params.keys() if any(s in p.lower() for s in sensitive_words))
    max_val_len = max([len(v[0]) for v in params.values()]) if params else 0
    encoded_chars = cleaned_raw.count("%")
    query_len = len(query)
    has_email_in_query = 1.0 if "@" in urllib.parse.unquote(query) else 0.0
    query_digit_ratio = sum(c.isdigit() for c in query) / max(1, query_len)
    features.extend([param_count, sensitive_count, max_val_len, encoded_chars, query_len, has_email_in_query, query_digit_ratio])

    is_private_ip = 1.0 if is_ip and (
        domain.startswith("192.168.") or domain.startswith("10.") or re.match(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", domain)
    ) else 0.0
    obf_dec_hex_oct = 1.0 if re.fullmatch(r"0[xX][0-9a-fA-F]+|\d{8,10}|(?:0[0-7]+\.){3}0[0-7]+", domain) else 0.0
    has_port = 1.0 if ":" in domain_with_port else 0.0
    features.extend([is_ip, is_private_ip, obf_dec_hex_oct, has_port])

    # These six flags depend on your exact sanitize_url output.
    # Keep the same tags you used during training.
    has_jwt = 1.0 if "<JWT_FORMAT" in masked_url else 0.0
    has_ext_redirect = 1.0 if "<REF_EXTERNAL" in masked_url else 0.0
    has_email_mismatch = 1.0 if "<EMAIL_MISMATCH" in masked_url else 0.0
    has_exec_file = 1.0 if "<FILE_EXEC" in masked_url else 0.0
    has_base64 = 1.0 if "<BASE64" in masked_url else 0.0
    has_obf_redirect = 1.0 if "<REF_ENCODED" in masked_url else 0.0
    features.extend([has_jwt, has_ext_redirect, has_email_mismatch, has_exec_file, has_base64, has_obf_redirect])

    def _entropy(text):
        if not text:
            return 0.0
        e = 0.0
        for count in Counter(text).values():
            p = count / len(text)
            e -= p * math.log2(p)
        return e

    features.extend([_entropy(domain), _entropy(path), _entropy(query), len(cleaned_raw)])
    return np.array(features, dtype=np.float32)