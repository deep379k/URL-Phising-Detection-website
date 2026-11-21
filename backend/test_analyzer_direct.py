#!/usr/bin/env python
"""Test URL analyzer directly."""
from url_analyzer import analyze_url

test_urls = ["google.com", "192.168.1.1:8080/login"]

for url in test_urls:
    print(f"\nURL: {url}")
    features = analyze_url(url)
    print(f"Features: {features}")
    
    # Predict
    import pickle
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
    import numpy as np
    
    with (PROJECT_ROOT / 'Phishing_model.pkl').open('rb') as f:
        model = pickle.load(f)
    
    feature_order = [
        "UsingIP", "PrefixSuffix-", "SubDomains", "HTTPS", "NonStdPort",
        "HTTPSDomainURL", "RequestURL", "AnchorURL", "LinksInScriptTags",
        "ServerFormHandler", "InfoEmail", "AbnormalURL", "WebsiteForwarding",
        "StatusBarCust", "DisableRightClick", "AgeofDomain", "DNSRecording",
        "WebsiteTraffic", "PageRank", "GoogleIndex", "StatsReport"
    ]
    
    values = [features[f] for f in feature_order]
    print(f"Values: {values}")
    
    pred = model.predict(np.array(values).reshape(1, -1))[0]
    print(f"Prediction: {pred}")
    if pred == 1:
        print(f"Result: ✅ SAFE")
    elif pred == -1:
        print(f"Result: ⚠️ NOT SAFE")
    else:
        print(f"Result: ⚡ SUSPICIOUS")
