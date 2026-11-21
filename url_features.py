"""Deterministic URL-only features shared by training and live prediction."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit


FEATURE_NAMES = [
    "UsingIP",
    "LongURL",
    "ShortURL",
    "Symbol@",
    "Redirecting//",
    "PrefixSuffix-",
    "SubDomains",
    "HTTPS",
    "NonStdPort",
    "HTTPSDomainURL",
]

SHORTENER_HOSTS = {
    "bit.ly",
    "buff.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "rebrand.ly",
    "shorturl.at",
    "t.co",
    "tiny.cc",
    "tinyurl.com",
}


class InvalidURL(ValueError):
    """Raised when a submitted URL cannot be safely analyzed."""


def normalize_url(value: str) -> str:
    """Return a parseable HTTP(S) URL without making a network request."""
    if not isinstance(value, str):
        raise InvalidURL("URL must be text.")

    value = value.strip()
    if not value:
        raise InvalidURL("URL is required.")
    if len(value) > 2048:
        raise InvalidURL("URL must be 2,048 characters or fewer.")
    if any(ord(character) < 32 for character in value):
        raise InvalidURL("URL contains invalid control characters.")

    candidate = value if re.match(r"^https?://", value, re.IGNORECASE) else f"http://{value}"
    parsed = urlsplit(candidate)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise InvalidURL("Only HTTP and HTTPS URLs are supported.")
    if not parsed.hostname:
        raise InvalidURL("Enter a URL with a valid hostname.")
    if " " in parsed.netloc:
        raise InvalidURL("The hostname cannot contain spaces.")

    try:
        _ = parsed.port
    except ValueError as exc:
        raise InvalidURL("The URL contains an invalid port.") from exc

    return candidate


def _is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False


def extract_url_features(value: str) -> dict[str, int]:
    """Extract features with the same names and value convention as the dataset.

    Values follow the source dataset convention: 1 is legitimate evidence,
    0 is indeterminate, and -1 is phishing evidence.
    """
    url = normalize_url(value)
    parsed = urlsplit(url)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    hostname_without_www = hostname[4:] if hostname.startswith("www.") else hostname
    dot_count = hostname_without_www.count(".")

    if len(url) < 54:
        length_signal = 1
    elif len(url) <= 75:
        length_signal = 0
    else:
        length_signal = -1

    scheme_marker = url.find("://")
    remainder = url[scheme_marker + 3 :] if scheme_marker >= 0 else url

    try:
        port = parsed.port
    except ValueError:
        port = None

    return {
        "UsingIP": -1 if _is_ip(hostname) else 1,
        "LongURL": length_signal,
        "ShortURL": -1 if hostname_without_www in SHORTENER_HOSTS else 1,
        "Symbol@": -1 if "@" in remainder else 1,
        "Redirecting//": -1 if "//" in remainder else 1,
        "PrefixSuffix-": -1 if "-" in hostname_without_www else 1,
        "SubDomains": 1 if dot_count <= 1 else (0 if dot_count == 2 else -1),
        "HTTPS": 1 if parsed.scheme.lower() == "https" else -1,
        "NonStdPort": -1 if port is not None and port not in {80, 443} else 1,
        "HTTPSDomainURL": -1 if "https" in hostname_without_www else 1,
    }

