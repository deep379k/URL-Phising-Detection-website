"""Live URL intelligence checks that complement, but do not replace, the ML model."""

from __future__ import annotations

import base64
import ipaddress
import os
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit

import requests


REQUEST_TIMEOUT = 4
TWO_LEVEL_SUFFIXES = {
    "co.in", "co.uk", "com.au", "com.br", "com.cn", "com.mx", "co.jp", "co.nz",
}


def _registrable_domain(hostname: str) -> str:
    labels = hostname.lower().rstrip(".").split(".")
    if len(labels) <= 2:
        return hostname
    last_two = ".".join(labels[-2:])
    return ".".join(labels[-3:]) if last_two in TWO_LEVEL_SUFFIXES else last_two


def _public_addresses(hostname: str) -> tuple[list[str], str | None]:
    try:
        records = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return [], f"DNS lookup failed: {exc}"

    addresses = sorted({record[4][0] for record in records})
    if not addresses:
        return [], "No DNS address records were returned."
    for address in addresses:
        parsed = ipaddress.ip_address(address)
        if not parsed.is_global:
            return [], "The hostname resolves to a private, local, or reserved address."
    return addresses, None


def _dns_check(hostname: str) -> dict[str, object]:
    addresses, error = _public_addresses(hostname)
    if error:
        return {"name": "DNS", "status": "failed", "severity": "high", "detail": error}
    return {
        "name": "DNS",
        "status": "passed",
        "severity": "info",
        "detail": f"Resolved to {len(addresses)} public IP address(es).",
    }


def _tls_check(hostname: str, scheme: str) -> dict[str, object]:
    if scheme != "https":
        return {
            "name": "TLS certificate",
            "status": "failed",
            "severity": "high",
            "detail": "The submitted URL does not use HTTPS.",
        }
    addresses, error = _public_addresses(hostname)
    if error:
        return {"name": "TLS certificate", "status": "unavailable", "severity": "info", "detail": error}
    try:
        context = ssl.create_default_context()
        # Connect to the already validated public address to avoid a second DNS
        # lookup that could be changed by a DNS-rebinding attacker. Preserve the
        # original hostname for SNI and certificate hostname verification.
        with socket.create_connection((addresses[0], 443), timeout=REQUEST_TIMEOUT) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
                certificate = tls_socket.getpeercert()
        expires_at = datetime.strptime(certificate["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        days_remaining = (expires_at - datetime.now(timezone.utc)).days
        if days_remaining < 0:
            return {
                "name": "TLS certificate", "status": "failed", "severity": "high",
                "detail": "The TLS certificate has expired.",
            }
        return {
            "name": "TLS certificate", "status": "passed", "severity": "info",
            "detail": f"Certificate hostname verified; expires in {days_remaining} day(s).",
        }
    except (OSError, ssl.SSLError, KeyError, ValueError) as exc:
        return {
            "name": "TLS certificate", "status": "failed", "severity": "medium",
            "detail": f"TLS verification failed: {exc}",
        }


def _rdap_check(hostname: str) -> dict[str, object]:
    domain = _registrable_domain(hostname)
    try:
        response = requests.get(
            f"https://rdap.org/domain/{quote(domain, safe='')}",
            headers={"Accept": "application/rdap+json", "User-Agent": "PhishGuard-AI/1.0"},
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code == 404:
            return {
                "name": "Domain registration", "status": "failed", "severity": "high",
                "detail": "No RDAP registration record was found for this domain.",
            }
        response.raise_for_status()
        payload = response.json()
        registration = next(
            (event.get("eventDate") for event in payload.get("events", [])
             if event.get("eventAction") == "registration"),
            None,
        )
        if not registration:
            return {
                "name": "Domain registration", "status": "unavailable", "severity": "info",
                "detail": "RDAP responded but did not expose a registration date.",
            }
        created_at = datetime.fromisoformat(registration.replace("Z", "+00:00"))
        age_days = max(0, (datetime.now(timezone.utc) - created_at).days)
        if age_days < 30:
            severity = "high"
            status = "failed"
        elif age_days < 180:
            severity = "medium"
            status = "warning"
        else:
            severity = "info"
            status = "passed"
        return {
            "name": "Domain registration", "status": status, "severity": severity,
            "detail": f"Domain age is approximately {age_days} day(s).",
            "age_days": age_days,
        }
    except (requests.RequestException, ValueError, TypeError) as exc:
        return {
            "name": "Domain registration", "status": "unavailable", "severity": "info",
            "detail": f"RDAP lookup unavailable: {exc}",
        }


def _google_safe_browsing_check(url: str) -> dict[str, object]:
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if not api_key:
        return {
            "name": "Google Safe Browsing", "status": "not_configured", "severity": "info",
            "detail": "Add GOOGLE_SAFE_BROWSING_API_KEY to enable this reputation check.",
        }
    payload = {
        "client": {"clientId": "phishguard-ai", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        response = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json=payload,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        matches = response.json().get("matches", [])
        return {
            "name": "Google Safe Browsing",
            "status": "failed" if matches else "passed",
            "severity": "critical" if matches else "info",
            "detail": "Google reported this URL as unsafe." if matches else "No Safe Browsing match was returned.",
        }
    except (requests.RequestException, ValueError) as exc:
        return {
            "name": "Google Safe Browsing", "status": "unavailable", "severity": "info",
            "detail": f"Safe Browsing lookup unavailable: {exc}",
        }


def _virustotal_check(url: str) -> dict[str, object]:
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return {
            "name": "VirusTotal", "status": "not_configured", "severity": "info",
            "detail": "Add VIRUSTOTAL_API_KEY to enable existing-report lookup.",
        }
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": api_key},
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code == 404:
            return {
                "name": "VirusTotal", "status": "unavailable", "severity": "info",
                "detail": "VirusTotal has no existing report; the URL was not submitted.",
            }
        response.raise_for_status()
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        flagged = malicious + suspicious
        return {
            "name": "VirusTotal",
            "status": "failed" if flagged else "passed",
            "severity": "critical" if malicious else ("medium" if suspicious else "info"),
            "detail": f"{malicious} malicious and {suspicious} suspicious engine result(s).",
        }
    except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
        return {
            "name": "VirusTotal", "status": "unavailable", "severity": "info",
            "detail": f"VirusTotal lookup unavailable: {exc}",
        }


def analyze_live_url(url: str) -> dict[str, object]:
    parsed = urlsplit(url)
    hostname = parsed.hostname or ""
    checks = [
        _dns_check(hostname),
        _tls_check(hostname, parsed.scheme.lower()),
        _rdap_check(hostname),
        _google_safe_browsing_check(url),
        _virustotal_check(url),
        {
            "name": "Page content and redirects", "status": "isolated_worker_required",
            "severity": "info",
            "detail": "Disabled in the web process to prevent SSRF; use an isolated scanner worker.",
        },
    ]
    malicious = any(check["severity"] in {"critical", "high"} and check["status"] == "failed" for check in checks)
    caution = malicious or any(check["severity"] == "medium" for check in checks)
    return {"checks": checks, "malicious": malicious, "caution": caution}
