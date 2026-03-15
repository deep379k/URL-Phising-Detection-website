# URL Testing Guide for Phishing Detection Model

## Quick Test URLs

### ✅ LEGITIMATE WEBSITES (Safe)
```
https://www.google.com
https://www.facebook.com
https://www.github.com
https://www.amazon.com
https://www.wikipedia.org
https://www.linkedin.com
https://www.twitter.com
```

### ⚠️ KNOWN PHISHING INDICATORS (Not Safe)
```
http://192.168.1.1/login.php          (Using IP instead of domain)
http://goo-gle.com/signin               (Dash in domain)
http://mail.google.verify.com/login    (Suspicious subdomain)
http://143.215.245.87:8080/secure     (IP with non-standard port)
http://paypal-confirm-account.ru       (Misspelled domain with unusual TLD)
```

---

## How to Analyze a URL - Feature Mapping

When you have a URL, examine it against these 21 features and enter the values in the form:

| Feature | What to Check | -1 (Safe) | 0 (Neutral) | 1 (Suspicious) |
|---------|---------------|-----------|------------|----------------|
| **UsingIP** | Does URL use IP address? | No (domain) | Maybe | Yes (IP address) |
| **PrefixSuffix-** | Is there "-" in domain? | No | Maybe | Yes |
| **SubDomains** | Multiple/unusual subdomains? | No | Few | Many suspicious |
| **HTTPS** | Has HTTPS protocol? | Yes (secure) | Maybe | No/Expired cert |
| **NonStdPort** | Non-standard port (1-1024)? | No | Maybe | Yes (8080, 3128, etc) |
| **HTTPSDomainURL** | HTTPS in domain part? | No | Maybe | Yes |
| **RequestURL** | External resources loaded? | Few/same server | Some | Many |
| **AnchorURL** | Anchor links point elsewhere? | Same site | Mixed | Different site |
| **LinksInScriptTags** | Links in script tags? | No | Few | Many |
| **ServerFormHandler** | Form posts to different server? | Same server | Maybe | Different |
| **InfoEmail** | Email address in content? | No | Maybe | Yes |
| **AbnormalURL** | Unusual/abnormal URL structure? | No | Maybe | Yes |
| **WebsiteForwarding** | URL redirects/forwards? | No | Maybe | Yes |
| **StatusBarCust** | Custom status bar? | No | Maybe | Yes |
| **DisableRightClick** | Right-click disabled? | No | Maybe | Yes |
| **AgeofDomain** | Domain age in months | >1yr old | 6mo-1yr | <6mo old |
| **DNSRecording** | DNS record exists? | Yes | Maybe | No/New |
| **WebsiteTraffic** | Website traffic (Alexa rank)? | High (>100k) | Medium | Low/None |
| **PageRank** | Google PageRank exists? | Yes (high) | Maybe | No/Low |
| **GoogleIndex** | In Google Index? | Yes | Maybe | No |
| **StatsReport** | In phishing databases? | No | Maybe | Yes |

---

## Example Analysis

### Example 1: Google (Safe)
```
URL: https://www.google.com

UsingIP: -1 (uses "google.com" domain, not IP)
PrefixSuffix-: -1 (no dashes)
SubDomains: -1 (only "www" is standard)
HTTPS: 1 (secure HTTPS)
NonStdPort: -1 (standard port 443)
HTTPSDomainURL: -1 (HTTPS not in domain part)
RequestURL: -1 (resources from same server)
AnchorURL: -1 (links within google.com)
LinksInScriptTags: -1 (safe script tags)
ServerFormHandler: -1 (forms to google servers)
InfoEmail: -1 (no email in URL)
AbnormalURL: -1 (normal structure)
WebsiteForwarding: -1 (no forwarding)
StatusBarCust: -1 (normal status bar)
DisableRightClick: -1 (right-click enabled)
AgeofDomain: 1 (Google old domain, >1yr)
DNSRecording: 1 (strong DNS record)
WebsiteTraffic: 1 (massive traffic - #1 website)
PageRank: 1 (highest PageRank)
GoogleIndex: 1 (heavily indexed)
StatsReport: -1 (not in phishing databases)
```

### Example 2: Suspicious Phishing URL
```
URL: http://192.168.1.1:8080/verify-account/secure-login.php

UsingIP: 1 (uses 192.168.1.1 IP address)
PrefixSuffix-: 1 (has dashes in path)
SubDomains: 0 (N/A for IP)
HTTPS: 0 (uses HTTP, not HTTPS)
NonStdPort: 1 (port 8080 is non-standard)
HTTPSDomainURL: 1 (trying to look secure but isn't)
RequestURL: 1 (likely loads external resources)
AnchorURL: 1 (likely suspicious links)
LinksInScriptTags: 1 (malicious scripts)
ServerFormHandler: 1 (form posts elsewhere)
InfoEmail: 1 (might steal credentials)
AbnormalURL: 1 (very abnormal structure)
WebsiteForwarding: 1 (redirects to steal data)
StatusBarCust: 1 (tries to hide real URL)
DisableRightClick: 1 (prevents inspection)
AgeofDomain: 0 (brand new IP)
DNSRecording: 0 (no real DNS)
WebsiteTraffic: 0 (no traffic)
PageRank: 0 (not indexed)
GoogleIndex: 0 (not in Google)
StatsReport: 1 (likely in phishing databases)
```

---

## Testing Steps

1. **Choose a URL** from the lists above
2. **Analyze it** using the feature mapping table
3. **Go to**: http://127.0.0.1:5000/inspect
4. **Enter the 21 feature values** based on your analysis
5. **Click "Predict"** to see if the model detects it correctly

---

## Quick Reference

**For Legitimate Sites (-1 values most common):**
- Uses domain name (not IP)
- Has HTTPS
- Old domain (1+ year)
- High traffic
- In Google Index
- No forwarding/redirects

**For Phishing Sites (1 values most common):**
- Uses IP address or suspicious domain
- No HTTPS or misused HTTPS
- Brand new domain (<6 months)
- Low/no traffic
- Not in any database
- Redirects and URL forwarding
- Disables right-click
- External form handlers
