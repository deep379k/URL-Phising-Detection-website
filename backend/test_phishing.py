#!/usr/bin/env python
"""Test phishing detection (Not Safe prediction)."""
import requests

# Data that should predict as suspicious/not safe
phishing_data = {
    "UsingIP": "1",  # Using IP instead of domain (phishing indicator)
    "PrefixSuffix-": "1",  # Dash in domain
    "SubDomains": "1",  # Multiple suspicious subdomains
    "HTTPS": "0",  # No HTTPS or uncertain
    "NonStdPort": "1",  # Non-standard port
    "HTTPSDomainURL": "1",  # HTTPS in domain URL
    "RequestURL": "1",  # External resources
    "AnchorURL": "1",  # Suspicious anchor URLs
    "LinksInScriptTags": "1",  # Links in script tags
    "ServerFormHandler": "1",  # Form handler on different server
    "InfoEmail": "1",  # Email info issues
    "AbnormalURL": "1",  # Abnormal URL
    "WebsiteForwarding": "1",  # URL forwarding
    "StatusBarCust": "1",  # Custom status bar
    "DisableRightClick": "1",  # Right-click disabled
    "AgeofDomain": "0",  # New domain
    "DNSRecording": "0",  # Missing DNS
    "WebsiteTraffic": "0",  # Low traffic
    "PageRank": "0",  # No PageRank
    "GoogleIndex": "0",  # Not in Google Index
    "StatsReport": "1",  # Negative stats
}

try:
    resp = requests.post("http://127.0.0.1:5000/output", data=phishing_data, timeout=10)
    print(f"Status: {resp.status_code}")
    if resp.status_code == 200:
        if "✅ SAFE" in resp.text:
            print("✓ Prediction: SAFE (Legitimate website)")
        elif "⚠️ NOT SAFE" in resp.text or "NOT SAFE" in resp.text:
            print("✓ Prediction: NOT SAFE (Phishing detected!)")
        elif "⚡ SUSPICIOUS" in resp.text:
            print("✓ Prediction: SUSPICIOUS (Use caution)")
        else:
            print("Response received, prediction visible in page")
except Exception as e:
    print(f"Request failed: {e}")
