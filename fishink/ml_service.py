import json
import os
import pickle
from functools import lru_cache

import numpy as np
import tensorflow as tf
from django.conf import settings

from .preprocessing import clean_url, extract_structural_features, sanitize_url

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

    seq = tokenizer.texts_to_sequences([masked_url])
    seq = tf.keras.preprocessing.sequence.pad_sequences(seq, maxlen=config["MAX_LEN"], padding="post", truncating="post")

    struct_features = extract_structural_features(raw_url, masked_url)
    struct_scaled = scaler.transform(np.array([struct_features], dtype=np.float32))

    proba = float(
        model.predict(
            {"seq_input": seq, "structural_input": struct_scaled},
            verbose=0
        )[0][0]
    )
    
    probability_percent = round(proba * 100, 2)

    threshold = float(config.get("OPTIMAL_THRESHOLD", 0.5))
    label = "PHISHING" if proba >= threshold else "TERPERCAYA"

    return {
        "url": raw_url,
        "masked_url": masked_url,
        "probability": proba,
        "estimated_phishing_score": probability_percent,        
        "threshold": threshold,
        "prediction": label,
    }