import requests

data = {
    "UsingIP": "0",
    "PrefixSuffix-": "0",
    "SubDomains": "0",
    "HTTPS": "1",
    "NonStdPort": "0",
    "HTTPSDomainURL": "1",
    "RequestURL": "0",
    "AnchorURL": "0",
    "LinksInScriptTags": "0",
    "ServerFormHandler": "0",
    "InfoEmail": "0",
    "AbnormalURL": "0",
    "WebsiteForwarding": "0",
    "StatusBarCust": "0",
    "DisableRightClick": "0",
    "AgeofDomain": "1",
    "DNSRecording": "1",
    "WebsiteTraffic": "0",
    "PageRank": "0",
    "GoogleIndex": "1",
    "StatsReport": "0"
}

try:
    resp = requests.post("http://127.0.0.1:5000/output", data=data, timeout=10)
    print("Status:", resp.status_code)
    print(resp.text)
except Exception as e:
    print("Request failed:", e)
