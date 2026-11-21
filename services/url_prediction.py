"""URL prediction service kept separate from Flask route handling."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import pandas as pd

from url_features import FEATURE_NAMES, extract_url_features, normalize_url


ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "models" / "url_phishing_pipeline.joblib"
METRICS_PATH = ROOT / "models" / "url_model_metrics.json"

INDICATOR_LABELS = {
    "UsingIP": "The hostname is an IP address instead of a domain name.",
    "LongURL": "The URL is unusually long.",
    "ShortURL": "The link uses a known URL-shortening service.",
    "Symbol@": "The URL contains an @ symbol that can obscure its destination.",
    "Redirecting//": "The URL contains an additional // redirect-like pattern.",
    "PrefixSuffix-": "The hostname contains a hyphen.",
    "SubDomains": "The hostname contains an unusually deep subdomain structure.",
    "HTTPS": "The submitted URL does not use HTTPS.",
    "NonStdPort": "The URL uses a non-standard network port.",
    "HTTPSDomainURL": "The word 'https' appears inside the hostname.",
}

# High-confidence brand lookalike safeguard. This is intentionally separate
# from the statistical model so its result is explainable and testable.
TRUSTED_BRAND_DOMAINS = {
    "google": {"google.com", "google.in", "google.co.in"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "live.com"},
    "apple": {"apple.com", "icloud.com"},
    "paypal": {"paypal.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
}


def _edit_distance(left: str, right: str) -> int:
    """Return the Levenshtein edit distance for two short domain labels."""
    previous = list(range(len(right) + 1))
    for left_index, left_character in enumerate(left, start=1):
        current = [left_index]
        for right_index, right_character in enumerate(right, start=1):
            current.append(min(
                current[-1] + 1,
                previous[right_index] + 1,
                previous[right_index - 1] + (left_character != right_character),
            ))
        previous = current
    return previous[-1]


def _is_official_hostname(hostname: str, official_domains: set[str]) -> bool:
    return any(hostname == domain or hostname.endswith(f".{domain}") for domain in official_domains)


def detect_brand_lookalike(url: str) -> str | None:
    """Return an impersonated brand when the hostname closely resembles it."""
    hostname = (urlsplit(url).hostname or "").lower().rstrip(".")
    labels = [label for label in hostname.split(".") if label and label != "www"]
    for brand, official_domains in TRUSTED_BRAND_DOMAINS.items():
        if _is_official_hostname(hostname, official_domains):
            continue
        for label in labels:
            normalized_label = label.translate(str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s"}))
            if normalized_label == brand or (
                len(normalized_label) >= 4 and _edit_distance(normalized_label, brand) == 1
            ):
                return brand
    return None


class URLPredictionService:
    def __init__(self) -> None:
        self.model = joblib.load(MODEL_PATH)
        self.metrics = json.loads(METRICS_PATH.read_text(encoding="utf-8"))

    @property
    def model_name(self) -> str:
        return str(self.metrics["selected_model"])

    def predict(self, value: str) -> dict[str, object]:
        normalized = normalize_url(value)
        features = extract_url_features(normalized)
        frame = pd.DataFrame([[features[name] for name in FEATURE_NAMES]], columns=FEATURE_NAMES)
        predicted_class = int(self.model.predict(frame)[0])

        classes = list(self.model.classes_)
        phishing_index = classes.index(-1)
        phishing_probability = float(self.model.predict_proba(frame)[0][phishing_index])

        # Some security signals are rare or contradictory in the legacy dataset.
        # Report them as an explicit deterministic safeguard, not as fabricated
        # model confidence or a blended probability.
        critical_rule = features["UsingIP"] == -1 and (
            features["HTTPS"] == -1 or features["NonStdPort"] == -1
        )
        impersonated_brand = detect_brand_lookalike(normalized)
        security_rule = critical_rule or impersonated_brand is not None

        if security_rule:
            risk_level = "High"
        elif phishing_probability >= 0.65:
            risk_level = "High"
        elif phishing_probability >= 0.40:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        indicators = [
            {"feature": name, "message": INDICATOR_LABELS[name]}
            for name in FEATURE_NAMES
            if features[name] == -1
        ]
        if impersonated_brand:
            indicators.insert(0, {
                "feature": "BrandLookalike",
                "message": (
                    f"The hostname resembles {impersonated_brand.title()} but is not one of its "
                    "recognized official domains. This may be a typosquatting attempt."
                ),
            })

        model_prediction = "Potential Phishing" if predicted_class == -1 else "Likely Legitimate"
        final_prediction = "Potential Phishing" if security_rule else model_prediction

        return {
            "input_type": "url",
            "url": normalized,
            "prediction": final_prediction,
            "risk_level": risk_level,
            "model_prediction": model_prediction,
            "model_phishing_probability": round(phishing_probability * 100, 2),
            "analysis_source": "security-rule" if security_rule else "machine-learning-model",
            "model_name": self.model_name,
            "indicators": indicators,
            "features": features,
            "disclaimer": (
                "PhishGuard AI provides machine-learning-based risk analysis for informational "
                "purposes. Predictions may contain false positives and false negatives."
            ),
        }

