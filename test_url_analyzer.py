#!/usr/bin/env python
"""Test URL analysis endpoint."""
import requests
import json

test_urls = [
    "https://www.google.com",
    "https://www.facebook.com",
    "http://192.168.1.1:8080/login",
]

print("\n🔒 Testing URL Analysis Endpoint")
print("=" * 70)

for url in test_urls:
    print(f"\n🔗 URL: {url}")
    print("-" * 70)
    
    try:
        response = requests.post(
            "http://127.0.0.1:5000/analyze_url",
            json={"url": url},
            timeout=15
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
            
            print(f"Prediction: {icon} {prediction}")
            print(f"\nExtracted Features:")
            features = data.get("features", {})
            for key, value in features.items():
                print(f"  {key}: {value}")
        else:
            print(f"❌ Error: {response.status_code}")
            print(response.json())
    
    except Exception as e:
        print(f"❌ Exception: {e}")

print("\n" + "=" * 70)
print("✅ URL Analysis Testing Complete!")
