#!/usr/bin/env python
"""Debug model predictions."""
import pickle
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
import numpy as np
from url_analyzer import analyze_url

# Load model
with (PROJECT_ROOT / 'Phishing_model.pkl').open('rb') as f:
    model = pickle.load(f)

# Sample data that should be "Safe" (from the form)
safe_features = {
    'UsingIP': -1, 'PrefixSuffix-': -1, 'SubDomains': -1, 'HTTPS': 1,
    'NonStdPort': -1, 'HTTPSDomainURL': -1, 'RequestURL': -1, 'AnchorURL': -1,
    'LinksInScriptTags': -1, 'ServerFormHandler': -1, 'InfoEmail': -1, 'AbnormalURL': -1,
    'WebsiteForwarding': -1, 'StatusBarCust': -1, 'DisableRightClick': -1,
    'AgeofDomain': 1, 'DNSRecording': 1, 'WebsiteTraffic': -1,
    'PageRank': 1, 'GoogleIndex': 1, 'StatsReport': -1
}

# URLs to test
test_urls = [
    "https://www.google.com",
    "http://192.168.1.1:8080/login",
]

feature_order = [
    "UsingIP", "PrefixSuffix-", "SubDomains", "HTTPS", "NonStdPort",
    "HTTPSDomainURL", "RequestURL", "AnchorURL", "LinksInScriptTags",
    "ServerFormHandler", "InfoEmail", "AbnormalURL", "WebsiteForwarding",
    "StatusBarCust", "DisableRightClick", "AgeofDomain", "DNSRecording",
    "WebsiteTraffic", "PageRank", "GoogleIndex", "StatsReport"
]

print("=" * 70)
print("TESTING MODEL PREDICTIONS")
print("=" * 70)

# Test 1: Sample safe features
print("\n1. Sample Safe Features (from form):")
safe_values = [safe_features[f] for f in feature_order]
safe_array = np.array(safe_values).reshape(1, -1)
safe_pred = model.predict(safe_array)[0]
print(f"   Features: {safe_values}")
print(f"   Prediction: {safe_pred}")
if safe_pred == 1:
    print("   Result: ✅ SAFE")
elif safe_pred == -1:
    print("   Result: ⚠️ NOT SAFE")
else:
    print("   Result: ⚡ SUSPICIOUS")

# Test 2: URL extracts
for url in test_urls:
    print(f"\n2. URL: {url}")
    url_features = analyze_url(url)
    url_values = [url_features[f] for f in feature_order]
    url_array = np.array(url_values).reshape(1, -1)
    url_pred = model.predict(url_array)[0]
    print(f"   Prediction: {url_pred}")
    if url_pred == 1:
        print("   Result: ✅ SAFE")
    elif url_pred == -1:
        print("   Result: ⚠️ NOT SAFE")
    else:
        print("   Result: ⚡ SUSPICIOUS")
        
    # Compare with sample
    print(f"   Feature differences from sample:")
    for feat, val_url, val_safe in zip(feature_order, url_values, safe_values):
        if val_url != val_safe:
            print(f"      {feat}: {val_url} (URL) vs {val_safe} (Sample)")

print("\n" + "=" * 70)
