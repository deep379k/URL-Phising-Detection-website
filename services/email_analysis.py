"""Lightweight email risk analysis built from existing validated services."""

from __future__ import annotations

import html
import re
import unicodedata
from email import policy
from email.parser import Parser
from urllib.parse import urlsplit

from services.message_prediction import extract_urls


class InvalidEmail(ValueError):
    """Raised when pasted email content is invalid."""


def normalize_email(value: str) -> str:
    if not isinstance(value, str):
        raise InvalidEmail("Email content must be text.")
    value = unicodedata.normalize("NFKC", value).strip()
    if not value:
        raise InvalidEmail("Email content is required.")
    if len(value) > 50_000:
        raise InvalidEmail("Email content must be 50,000 characters or fewer.")
    value = re.sub(r"(?is)<(?:script|style).*?>.*?</(?:script|style)>", " ", value)
    value = html.unescape(re.sub(r"<[^>]+>", " ", value))
    return re.sub(r"\s+", " ", value).strip()


def _domain(address: str) -> str:
    match = re.search(r"@([a-z0-9.-]+)", address, re.IGNORECASE)
    return match.group(1).lower().rstrip(".") if match else ""


def analyze_email(value: str, message_service, url_service) -> dict[str, object]:
    raw_value = value
    text = normalize_email(value)
    parsed = Parser(policy=policy.default).parsestr(raw_value)
    subject = str(parsed.get("subject", "")).strip()
    sender = str(parsed.get("from", "")).strip()
    reply_to = str(parsed.get("reply-to", "")).strip()

    model_input = f"Subject: {subject} {text}"[:10_000]
    text_result = message_service.predict(model_input)
    urls = extract_urls(text)
    url_results = []
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

    indicators = list(text_result["indicators"])
    sender_domain = _domain(sender)
    reply_domain = _domain(reply_to)
    if sender_domain and reply_domain and sender_domain != reply_domain:
        indicators.append(
            {
                "name": "Reply-to domain mismatch",
                "evidence": f"Sender uses {sender_domain}; replies go to {reply_domain}",
            }
        )
    if re.search(r"\b(?:dear customer|dear user|valued customer)\b", text, re.IGNORECASE):
        indicators.append({"name": "Generic greeting", "evidence": "Non-personalized greeting found"})

    phishing_url = any(result["prediction"] == "Potential Phishing" for result in url_results)
    if phishing_url:
        prediction = "Potential Phishing"
        risk_level = "High"
        analysis_source = "embedded-url-analysis"
    elif text_result["prediction"] == "Likely Spam":
        prediction = "Suspicious Email"
        risk_level = text_result["risk_level"]
        analysis_source = "shared-spam-language-model"
    else:
        prediction = "Likely Legitimate"
        risk_level = "Low"
        analysis_source = "shared-spam-language-model"

    return {
        "input_type": "email",
        "prediction": prediction,
        "risk_level": risk_level,
        "analysis_source": analysis_source,
        "model_name": f"{message_service.model_name} (shared spam-language model)",
        "text_classification": text_result["prediction"],
        "model_spam_probability": text_result["model_spam_probability"],
        "subject": subject[:300] if subject else None,
        "sender_domain": sender_domain or None,
        "reply_to_domain": reply_domain or None,
        "indicators": indicators,
        "scam_themes": text_result["scam_themes"],
        "extracted_urls": urls,
        "url_results": url_results,
        "input_truncated_for_model": len(model_input) >= 10_000,
        "disclaimer": (
            "This lightweight email analyzer reuses the SMS spam-language model and separate URL "
            "model. It is not a dedicated email-phishing classifier."
        ),
    }
