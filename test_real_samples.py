#!/usr/bin/env python
"""Test form with real sample data."""
import requests

# Real safe site sample from training data
safe_sample = {
    'UsingIP': 1, 'PrefixSuffix-': -1, 'SubDomains': -1, 'HTTPS': 1,
    'NonStdPort': 1, 'HTTPSDomainURL': -1, 'RequestURL': -1, 'AnchorURL': 0,
    'LinksInScriptTags': -1, 'ServerFormHandler': -1, 'InfoEmail': -1, 'AbnormalURL': -1,
    'WebsiteForwarding': 0, 'StatusBarCust': 1, 'DisableRightClick': 1,
    'AgeofDomain': 1, 'DNSRecording': -1, 'WebsiteTraffic': -1,
    'PageRank': 1, 'GoogleIndex': 1, 'StatsReport': -1
}

# Real phishing site sample from training data
phishing_sample = {
    'UsingIP': 1, 'PrefixSuffix-': -1, 'SubDomains': -1, 'HTTPS': 1,
    'NonStdPort': 1, 'HTTPSDomainURL': 1, 'RequestURL': 1, 'AnchorURL': 0,
    'LinksInScriptTags': 1, 'ServerFormHandler': -1, 'InfoEmail': 1, 'AbnormalURL': 1,
    'WebsiteForwarding': 0, 'StatusBarCust': 1, 'DisableRightClick': 1,
    'AgeofDomain': 1, 'DNSRecording': -1, 'WebsiteTraffic': 0,
    'PageRank': -1, 'GoogleIndex': 1, 'StatsReport': 1
}

print("=" * 70)
print("TESTING FORM WITH REAL SAMPLE DATA")
print("=" * 70)

print("\n1. Testing Safe Site Sample:")
try:
    resp = requests.post("http://127.0.0.1:5000/output", data=safe_sample, timeout=10)
    if resp.status_code == 200:
        if "✅ SAFE" in resp.text:
            print("   ✅ Result: SAFE (Correct!)")
        elif "⚠️ NOT SAFE" in resp.text or "NOT SAFE" in resp.text:
            print("   ❌ Result: NOT SAFE (Incorrect!)")
        elif "⚡ SUSPICIOUS" in resp.text:
            print("   ⚠️ Result: SUSPICIOUS")
except Exception as e:
    print(f"   ❌ Error: {e}")

print("\n2. Testing Phishing Site Sample:")
try:
    resp = requests.post("http://127.0.0.1:5000/output", data=phishing_sample, timeout=10)
    if resp.status_code == 200:
        if "✅ SAFE" in resp.text:
            print("   ❌ Result: SAFE (Incorrect!)")
        elif "⚠️ NOT SAFE" in resp.text or "NOT SAFE" in resp.text:
            print("   ✅ Result: NOT SAFE (Correct!)")
        elif "⚡ SUSPICIOUS" in resp.text:
            print("   ⚠️ Result: SUSPICIOUS")
except Exception as e:
    print(f"   ❌ Error: {e}")

print("\n" + "=" * 70)
print("✅ Form Testing Complete!")
print("=" * 70)
