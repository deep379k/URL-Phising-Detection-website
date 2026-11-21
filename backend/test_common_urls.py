#!/usr/bin/env python
"""Test URL analyzer with common sites."""
import requests

test_urls = [
    "google.com",
    "https://google.com",
    "facebook.com",
    "https://github.com",
    "192.168.1.1:8080/login",
]

print("=" * 70)
print("TESTING URL ANALYZER WITH IMPROVED LOGIC")
print("=" * 70)

for url in test_urls:
    print(f"\n🔗 URL: {url}")
    
    try:
        response = requests.post(
            "http://127.0.0.1:5000/analyze_url",
            json={"url": url},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            prediction = data.get("prediction")
            
            if prediction == "Safe":
                icon = "✅"
            elif prediction == "Not Safe":
                icon = "⚠️"
            else:
                icon = "⚡"
            
            print(f"   Result: {icon} {prediction}")
        else:
            print(f"   Error: {response.status_code}")
    
    except Exception as e:
        print(f"   Error: {e}")

print("\n" + "=" * 70)
