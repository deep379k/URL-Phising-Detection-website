#!/usr/bin/env python
"""Quick Test Cases - Pre-built URLs to test the phishing detector."""

import requests

TEST_CASES = {
    "1": {
        "name": "Google.com (Legitimate)",
        "data": {
            "UsingIP": "-1",
            "PrefixSuffix-": "-1",
            "SubDomains": "-1",
            "HTTPS": "1",
            "NonStdPort": "-1",
            "HTTPSDomainURL": "-1",
            "RequestURL": "-1",
            "AnchorURL": "-1",
            "LinksInScriptTags": "-1",
            "ServerFormHandler": "-1",
            "InfoEmail": "-1",
            "AbnormalURL": "-1",
            "WebsiteForwarding": "-1",
            "StatusBarCust": "-1",
            "DisableRightClick": "-1",
            "AgeofDomain": "1",
            "DNSRecording": "1",
            "WebsiteTraffic": "1",
            "PageRank": "1",
            "GoogleIndex": "1",
            "StatsReport": "-1",
        }
    },
    "2": {
        "name": "Facebook.com (Legitimate)",
        "data": {
            "UsingIP": "-1",
            "PrefixSuffix-": "-1",
            "SubDomains": "-1",
            "HTTPS": "1",
            "NonStdPort": "-1",
            "HTTPSDomainURL": "-1",
            "RequestURL": "-1",
            "AnchorURL": "-1",
            "LinksInScriptTags": "-1",
            "ServerFormHandler": "-1",
            "InfoEmail": "-1",
            "AbnormalURL": "-1",
            "WebsiteForwarding": "-1",
            "StatusBarCust": "-1",
            "DisableRightClick": "-1",
            "AgeofDomain": "1",
            "DNSRecording": "1",
            "WebsiteTraffic": "1",
            "PageRank": "1",
            "GoogleIndex": "1",
            "StatsReport": "-1",
        }
    },
    "3": {
        "name": "Obvious Phishing (IP Address)",
        "data": {
            "UsingIP": "1",
            "PrefixSuffix-": "1",
            "SubDomains": "1",
            "HTTPS": "0",
            "NonStdPort": "1",
            "HTTPSDomainURL": "1",
            "RequestURL": "1",
            "AnchorURL": "1",
            "LinksInScriptTags": "1",
            "ServerFormHandler": "1",
            "InfoEmail": "1",
            "AbnormalURL": "1",
            "WebsiteForwarding": "1",
            "StatusBarCust": "1",
            "DisableRightClick": "1",
            "AgeofDomain": "0",
            "DNSRecording": "0",
            "WebsiteTraffic": "0",
            "PageRank": "0",
            "GoogleIndex": "0",
            "StatsReport": "1",
        }
    },
    "4": {
        "name": "Medium Suspicious",
        "data": {
            "UsingIP": "0",
            "PrefixSuffix-": "1",
            "SubDomains": "0",
            "HTTPS": "0",
            "NonStdPort": "0",
            "HTTPSDomainURL": "1",
            "RequestURL": "0",
            "AnchorURL": "1",
            "LinksInScriptTags": "0",
            "ServerFormHandler": "1",
            "InfoEmail": "0",
            "AbnormalURL": "0",
            "WebsiteForwarding": "1",
            "StatusBarCust": "0",
            "DisableRightClick": "1",
            "AgeofDomain": "0",
            "DNSRecording": "0",
            "WebsiteTraffic": "-1",
            "PageRank": "-1",
            "GoogleIndex": "-1",
            "StatsReport": "0",
        }
    },
    "5": {
        "name": "GitHub.com (Tech Legitimate)",
        "data": {
            "UsingIP": "-1",
            "PrefixSuffix-": "-1",
            "SubDomains": "0",
            "HTTPS": "1",
            "NonStdPort": "-1",
            "HTTPSDomainURL": "-1",
            "RequestURL": "-1",
            "AnchorURL": "-1",
            "LinksInScriptTags": "-1",
            "ServerFormHandler": "-1",
            "InfoEmail": "-1",
            "AbnormalURL": "-1",
            "WebsiteForwarding": "-1",
            "StatusBarCust": "-1",
            "DisableRightClick": "-1",
            "AgeofDomain": "1",
            "DNSRecording": "1",
            "WebsiteTraffic": "1",
            "PageRank": "1",
            "GoogleIndex": "1",
            "StatsReport": "-1",
        }
    }
}

def run_prediction(case_id):
    """Run a prediction test case."""
    if case_id not in TEST_CASES:
        print("❌ Invalid selection!")
        return
    
    case = TEST_CASES[case_id]
    print(f"\n🔍 Testing: {case['name']}")
    print("=" * 60)
    
    try:
        response = requests.post("http://127.0.0.1:5000/output", data=case['data'], timeout=10)
        
        if response.status_code == 200:
            if "✅ SAFE" in response.text:
                print("✅ RESULT: SAFE (Legitimate Website)")
            elif "⚠️ NOT SAFE" in response.text or "NOT SAFE" in response.text:
                print("⚠️ RESULT: NOT SAFE (Phishing Detected!)")
            elif "⚡ SUSPICIOUS" in response.text:
                print("⚡ RESULT: SUSPICIOUS (Use Caution)")
            else:
                print("🤔 RESULT: Unknown prediction")
            print("=" * 60)
        else:
            print(f"❌ Server error: {response.status_code}")
    
    except Exception as e:
        print(f"❌ Connection error: {e}")
        print("   Make sure Flask is running on http://127.0.0.1:5000")

def main():
    """Display menu and run tests."""
    print("\n" + "=" * 60)
    print("  🔒 PHISHING DETECTION - QUICK TEST CASES")
    print("=" * 60)
    print("\nSelect a test case:\n")
    
    for case_id, case in TEST_CASES.items():
        print(f"  {case_id}. {case['name']}")
    
    print(f"  0. Exit")
    print("\n" + "=" * 60)
    
    while True:
        choice = input("\nEnter choice (0-5): ").strip()
        
        if choice == "0":
            print("\n👋 Goodbye!")
            break
        elif choice in TEST_CASES:
            run_prediction(choice)
        else:
            print("❌ Invalid choice. Please enter 0-5.")

if __name__ == "__main__":
    main()
