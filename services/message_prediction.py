"""SMS/message spam classification and transparent theme indicators."""

from __future__ import annotations

import json
import math
import re
import unicodedata
from pathlib import Path

import joblib


ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "models" / "message_spam_pipeline.joblib"
METRICS_PATH = ROOT / "models" / "message_model_metrics.json"
URL_PATTERN = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>]+")

THEME_PATTERNS = {
    "Banking / KYC": r"\b(?:bank|banking|kyc|debit card|credit card|account blocked|account suspended)\b",
    "UPI / Payment": r"\b(?:upi|paytm|phonepe|gpay|google pay|payment|transaction|wallet)\b|₹|\brs\.?\s?\d",
    "Refund / Cashback": r"\b(?:refund|cashback|cash back|reimbursement)\b",
    "Job / Recruitment": r"\b(?:job offer|recruitment|work from home|registration fee|hiring|salary)\b",
    "Courier / Delivery": r"\b(?:courier|parcel|delivery|shipment|customs fee)\b",
    "Lottery / Prize": r"\b(?:lottery|winner|won|prize|reward|jackpot|claim)\b",
    "OTP / Account verification": r"\b(?:otp|one time password|verification code|verify your account|confirm your account)\b",
    "Shopping / Customer support": r"\b(?:order|shopping|customer support|customer care|helpline)\b",
}

INDICATOR_PATTERNS = {
    "Urgency language": r"\b(?:urgent|immediately|act now|final warning|within \d+ (?:hours?|minutes?))\b",
    "Prize or reward language": r"\b(?:winner|won|prize|reward|free gift|lottery|claim now)\b",
    "Financial request": r"\b(?:pay|payment|fee|transfer|send money|bank details|card details)\b|₹",
    "Credential or OTP request": r"\b(?:password|pin|otp|verification code|cvv)\b",
    "Action request": r"\b(?:click|tap|reply|call|download|install|verify|confirm|claim)\b",
}


class InvalidMessage(ValueError):
    """Raised when pasted message text cannot be analyzed."""


def normalize_message(value: str) -> str:
    if not isinstance(value, str):
        raise InvalidMessage("Message must be text.")
    value = unicodedata.normalize("NFKC", value)
    value = re.sub(r"\s+", " ", value).strip()
    if not value:
        raise InvalidMessage("Message text is required.")
    if len(value) > 10_000:
        raise InvalidMessage("Message must be 10,000 characters or fewer.")
    return value


def extract_urls(text: str) -> list[str]:
    urls = []
    for match in URL_PATTERN.findall(text):
        cleaned = match.rstrip(".,;:!?)]}\"")
        normalized = cleaned if cleaned.lower().startswith(("http://", "https://")) else f"http://{cleaned}"
        if normalized not in urls:
            urls.append(normalized)
    return urls[:5]


class MessagePredictionService:
    def __init__(self) -> None:
        self.model = joblib.load(MODEL_PATH)
        self.metrics = json.loads(METRICS_PATH.read_text(encoding="utf-8"))

    @property
    def model_name(self) -> str:
        return str(self.metrics["selected_model"])

    def _spam_probability(self, text: str) -> float | None:
        if hasattr(self.model, "predict_proba"):
            index = list(self.model.classes_).index("spam")
            return float(self.model.predict_proba([text])[0][index])
        if hasattr(self.model, "decision_function"):
            score = float(self.model.decision_function([text])[0])
            return 1 / (1 + math.exp(-score))
        return None

    def predict(self, value: str, url_service=None) -> dict[str, object]:
        text = normalize_message(value)
        predicted_label = str(self.model.predict([text])[0])
        probability = self._spam_probability(text)
        prediction = "Likely Spam" if predicted_label == "spam" else "Likely Legitimate"
        if probability is None:
            risk_level = "Elevated" if predicted_label == "spam" else "Low"
        elif probability >= 0.75:
            risk_level = "High"
        elif probability >= 0.40:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        themes = [
            {"name": name, "evidence": "Pattern found in message text"}
            for name, pattern in THEME_PATTERNS.items()
            if re.search(pattern, text, re.IGNORECASE)
        ]
        indicators = [
            {"name": name, "evidence": match.group(0)}
            for name, pattern in INDICATOR_PATTERNS.items()
            if (match := re.search(pattern, text, re.IGNORECASE))
        ]
        urls = extract_urls(text)
        url_results = []
        if url_service:
            for url in urls:
                try:
                    result = url_service.predict(url)
                    url_results.append(
                        {
                            "url": result["url"],
                            "prediction": result["prediction"],
                            "risk_level": result["risk_level"],
                            "indicators": result["indicators"],
                        }
                    )
                except Exception:
                    url_results.append({"url": url, "prediction": "Unable to analyze", "risk_level": "Unknown"})

        return {
            "input_type": "message",
            "prediction": prediction,
            "risk_level": risk_level,
            "model_name": self.model_name,
            "model_spam_probability": round(probability * 100, 2) if probability is not None else None,
            "scam_themes": themes,
            "indicators": indicators,
            "extracted_urls": urls,
            "url_results": url_results,
            "limitations": self.metrics["limitations"],
            "disclaimer": (
                "This model distinguishes ordinary SMS spam from legitimate messages. It does not "
                "prove that a message is phishing or financial fraud."
            ),
        }
