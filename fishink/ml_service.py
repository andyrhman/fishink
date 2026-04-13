import json
import os
import pickle
from functools import lru_cache
from urllib.parse import urlparse

import numpy as np
import tensorflow as tf
from django.conf import settings

from .preprocessing import clean_url, extract_structural_features, sanitize_url

def normalize_hostname(hostname: str) -> str:
    return (hostname or "").strip().lower().rstrip(".")

def extract_hostname(raw_url: str) -> str:
    raw_url = str(raw_url).strip()
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)
    hostname = parsed.hostname or ""
    hostname = normalize_hostname(hostname)

    if hostname.startswith("www."):
        hostname = hostname[4:]

    return hostname

@lru_cache(maxsize=1)
def load_trusted_domains():
    model_dir = settings.PHISHING_MODEL_DIR
    trusted_path = os.path.join(model_dir, "trusted_website_high_confidence.json")

    if not os.path.exists(trusted_path):
        return set()

    with open(trusted_path, "r", encoding="utf-8") as f:
        domains = json.load(f)

    cleaned = set()
    for domain in domains:
        domain = normalize_hostname(str(domain))
        if domain.startswith("www."):
            domain = domain[4:]
        if domain:
            cleaned.add(domain)

    return cleaned

def is_whitelisted_domain(hostname: str) -> tuple[bool, str | None]:
    hostname = normalize_hostname(hostname)
    if not hostname:
        return False, None

    trusted_domains = load_trusted_domains()

    for trusted in trusted_domains:
        if hostname == trusted or hostname.endswith("." + trusted):
            return True, trusted

    return False, None


@lru_cache(maxsize=1)
def load_artifacts():
    model_dir = settings.PHISHING_MODEL_DIR

    model_path = os.path.join(model_dir, "wide_deep_fusion_20260403_075005.keras")
    tokenizer_path = os.path.join(model_dir, "tokenizer_20260403_075005.pkl")
    scaler_path = os.path.join(model_dir, "scaler_20260403_075005.pkl")
    config_path = os.path.join(model_dir, "config_20260403_075005.json")

    model = tf.keras.models.load_model(model_path, compile=False)

    with open(tokenizer_path, "rb") as f:
        tokenizer = pickle.load(f)

    with open(scaler_path, "rb") as f:
        scaler = pickle.load(f)

    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)

    print("Model ML, Tokenizer, dan Scaler berhasil dimuat!")
    return model, tokenizer, scaler, config


def predict_phishing(url: str):
    model, tokenizer, scaler, config = load_artifacts()

    raw_url = str(url).strip()
    cleaned_url = clean_url(raw_url)
    masked_url = sanitize_url(cleaned_url)

    hostname = extract_hostname(raw_url)
    whitelist_hit, matched_domain = is_whitelisted_domain(hostname)

    threshold = float(config.get("OPTIMAL_THRESHOLD", 0.5))

    # Whitelist override: trusted domains are forced to TERPERCAYA
    if whitelist_hit:
        return {
            "url": raw_url,
            "masked_url": masked_url,
            "probability": 0.0,
            "estimated_phishing_score": 0.0,
            "model_probability": None,
            "threshold": threshold,
            "prediction": "TERPERCAYA",
            "whitelist_override": True,
            "matched_trusted_domain": matched_domain,
        }

    seq = tokenizer.texts_to_sequences([masked_url])
    seq = tf.keras.preprocessing.sequence.pad_sequences(
        seq,
        maxlen=config["MAX_LEN"],
        padding="post",
        truncating="post",
    )

    struct_features = extract_structural_features(raw_url, masked_url)
    struct_scaled = scaler.transform(np.array([struct_features], dtype=np.float32))

    proba = float(
        model.predict(
            {"seq_input": seq, "structural_input": struct_scaled},
            verbose=0
        )[0][0]
    )

    probability_percent = round(proba * 100, 2)
    label = "PHISHING" if proba >= threshold else "TERPERCAYA"

    return {
        "url": raw_url,
        "masked_url": masked_url,
        "probability": proba,
        "estimated_phishing_score": probability_percent,
        "model_probability": proba,
        "threshold": threshold,
        "prediction": label,
        "whitelist_override": False,
        "matched_trusted_domain": None,
    }