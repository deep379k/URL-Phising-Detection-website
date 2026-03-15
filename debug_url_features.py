#!/usr/bin/env python
"""Debug URL features."""
from url_analyzer import analyze_url

test_urls = ["google.com", "https://google.com"]

feature_order = [
    "UsingIP", "PrefixSuffix-", "SubDomains", "HTTPS", "NonStdPort",
    "HTTPSDomainURL", "RequestURL", "AnchorURL", "LinksInScriptTags",
    "ServerFormHandler", "InfoEmail", "AbnormalURL", "WebsiteForwarding",
    "StatusBarCust", "DisableRightClick", "AgeofDomain", "DNSRecording",
    "WebsiteTraffic", "PageRank", "GoogleIndex", "StatsReport"
]

for url in test_urls:
    print(f"\nURL: {url}")
    features = analyze_url(url)
    values = [features[f] for f in feature_order]
    print(f"Features: {values}")
    
    # Compare with safe sample
    safe_sample = [1, -1, -1, 1, 1, -1, -1, 0, -1, -1, -1, -1, 0, 1, 1, 1, -1, -1, 1, 1, -1]
    
    diff_count = 0
    print("Differences from safe sample:")
    for i, (feat, val_url, val_safe) in enumerate(zip(feature_order, values, safe_sample)):
        if val_url != val_safe:
            print(f"  {feat}: {val_url} (URL) vs {val_safe} (Safe Sample)")
            diff_count += 1
    
    if diff_count == 0:
        print("  (No differences - matches safe sample exactly!)")
