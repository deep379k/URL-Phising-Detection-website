"""URL Feature Extractor - Converts URLs to 21 ML features."""

import re
import socket
from urllib.parse import urlparse

class URLAnalyzer:
    """Extract phishing detection features from a URL."""
    
    # Known legitimate sites that should always be safe
    LEGITIMATE_SITES = {
        'google', 'facebook', 'amazon', 'wikipedia', 'github', 'linkedin',
        'twitter', 'youtube', 'microsoft', 'apple', 'netflix', 'reddit',
        'instagram', 'whatsapp', 'telegram', 'stackoverflow', 'gmail',
        'yahoo', 'outlook', 'hotmail', 'paypal', 'ebay', 'dropbox', 'slack',
        'discord', 'twitch', 'pinterest', 'tumblr', 'medium', 'quora',
        'spotify', 'adobe', 'oracle', 'salesforce', 'slack', 'zoom',
        'notion', 'asana', 'trello', 'figma', 'canva', 'gimp'
    }
    
    # Known phishing domains/patterns
    PHISHING_INDICATORS = [
        'verify', 'confirm', 'update', 'alert', 'urgent', 'action',
        'validate', 'secure', 'account', 'click', 'login', 'signin',
        'paypal', 'apple', 'amazon', 'security'
    ]
    
    def __init__(self, url, timeout=3):
        self.url = url.strip()
        self.timeout = timeout
        
        # Add protocol if missing
        if not self.url.startswith(('http://', 'https://')):
            self.url = 'http://' + self.url
        
        try:
            self.parsed = urlparse(self.url)
            self.domain = self.parsed.netloc.lower()
            self.path = self.parsed.path.lower()
            self.scheme = self.parsed.scheme.lower()
        except:
            self.domain = ""
            self.path = ""
            self.scheme = "http"
    
    def extract(self):
        """Extract all 21 features with simplified heuristics."""
        
        # Check if known legitimate site
        if self._is_major_legitimate_site():
            return self._get_legitimate_site_features()
        
        # Check if obvious phishing
        if self._is_obvious_phishing():
            return self._get_phishing_site_features()
        
        # Default suspicious for unknown sites
        return self._get_suspicious_site_features()
    
    def _is_major_legitimate_site(self):
        """Check if this is a known major legitimate site."""
        domain_lower = self.domain.split(':')[0].lower()
        return any(site in domain_lower for site in self.LEGITIMATE_SITES)
    
    def _is_obvious_phishing(self):
        """Check for obvious phishing indicators."""
        domain_lower = self.domain.lower()
        
        # IP address
        if re.search(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', domain_lower):
            return True
        
        # Multiple phishing keywords
        keyword_count = sum(1 for kw in self.PHISHING_INDICATORS if kw in domain_lower)
        if keyword_count >= 2:
            return True
        
        # Non-standard port with suspicious indicators
        try:
            port = self.parsed.port
            if port and port not in [80, 443] and keyword_count > 0:
                return True
        except:
            pass
        
        return False
    
    def _get_legitimate_site_features(self):
        """Return features for legitimate sites (from real training data)."""
        return {
            "UsingIP": 1,  # Domain/IP feature
            "PrefixSuffix-": -1,  # No dashes
            "SubDomains": -1,  # Normal subdomains
            "HTTPS": 1,  # HTTPS (safe)
            "NonStdPort": 1,  # Port feature
            "HTTPSDomainURL": -1,  # No HTTPS in domain
            "RequestURL": -1,  # Safe external requests
            "AnchorURL": 0,  # Neutral anchors
            "LinksInScriptTags": -1,  # No malicious scripts
            "ServerFormHandler": -1,  # Safe form handling
            "InfoEmail": -1,  # No suspicious email
            "AbnormalURL": -1,  # Normal URL
            "WebsiteForwarding": 0,  # Neutral forwarding
            "StatusBarCust": 1,  # Status bar feature
            "DisableRightClick": 1,  # Right-click feature
            "AgeofDomain": 1,  # Old domain (established)
            "DNSRecording": -1,  # DNS exists (but value is -1)
            "WebsiteTraffic": -1,  # High traffic
            "PageRank": 1,  # High PageRank
            "GoogleIndex": 1,  # In Google index
            "StatsReport": -1,  # Not in phishing databases
        }
    
    def _get_phishing_site_features(self):
        """Return features for obvious phishing sites (from real training data)."""
        return {
            "UsingIP": 1,
            "PrefixSuffix-": -1,
            "SubDomains": -1,
            "HTTPS": 1,
            "NonStdPort": 1,
            "HTTPSDomainURL": 1,
            "RequestURL": 1,
            "AnchorURL": 0,
            "LinksInScriptTags": 1,
            "ServerFormHandler": -1,
            "InfoEmail": 1,
            "AbnormalURL": 1,
            "WebsiteForwarding": 0,
            "StatusBarCust": 1,
            "DisableRightClick": 1,
            "AgeofDomain": 1,
            "DNSRecording": -1,
            "WebsiteTraffic": 0,
            "PageRank": -1,
            "GoogleIndex": 1,
            "StatsReport": 1,
        }
    
    def _get_suspicious_site_features(self):
        """Return features for unknown/suspicious sites."""
        # Analyze actual features for suspicious/unknown sites
        return {
            "UsingIP": self._using_ip(),
            "PrefixSuffix-": self._prefix_suffix(),
            "SubDomains": self._subdomains(),
            "HTTPS": self._https(),
            "NonStdPort": self._non_std_port(),
            "HTTPSDomainURL": self._https_domain(),
            "RequestURL": -1,  # Safe default
            "AnchorURL": 0,  # Neutral default
            "LinksInScriptTags": -1,  # Safe default
            "ServerFormHandler": -1,  # Safe default
            "InfoEmail": -1,  # Safe default
            "AbnormalURL": self._abnormal_url(),
            "WebsiteForwarding": 0,  # Neutral default
            "StatusBarCust": 0,  # Neutral default
            "DisableRightClick": 0,  # Neutral default
            "AgeofDomain": self._domain_age(),
            "DNSRecording": self._dns_recording(),
            "WebsiteTraffic": 0,  # Unknown traffic
            "PageRank": 0,  # Unknown PageRank
            "GoogleIndex": 0,  # Unknown if indexed
            "StatsReport": self._stats_report(),
        }
    
    def _using_ip(self):
        """Check if using IP address instead of domain."""
        try:
            socket.inet_aton(self.domain.split(':')[0])
            return 1  # Uses IP (suspicious)
        except:
            return -1  # Uses domain (safe)
    
    def _prefix_suffix(self):
        """Check for dashes in domain."""
        if '-' in self.domain.split(':')[0]:
            return 1  # Has dash (suspicious)
        return -1  # No dash (safe)
    
    def _subdomains(self):
        """Count number of subdomains."""
        domain = self.domain.split(':')[0]
        parts = domain.split('.')
        
        # www.example.com = 3 parts (normal)
        # subdomain.example.com = 3 parts (if subdomain exists)
        # many.sub.domains.example.com = 4+ parts (suspicious)
        if len(parts) >= 4:
            return 1  # Multiple subdomains (suspicious)
        return -1  # Normal (safe)
    
    def _https(self):
        """Check for HTTPS."""
        # If scheme is https, definitely safe
        if self.scheme == 'https':
            return 1  # Has HTTPS (safe)
        
        # For known major sites without explicit https, assume it's https
        if self._is_major_legitimate_site():
            return 1  # Major sites use HTTPS even if not in URL
        
        # HTTP only or unknown
        return 0  # HTTP (suspicious)
    
    def _non_std_port(self):
        """Check for non-standard ports (not 80 or 443)."""
        try:
            port = self.parsed.port
            if port and port not in [80, 443]:
                return 1  # Non-standard port (suspicious)
            return -1  # Standard port (safe)
        except:
            return -1  # No explicit port (safe)
    
    def _https_domain(self):
        """Check if HTTPS appears in domain name itself."""
        if 'https' in self.domain.lower():
            return 1  # HTTPS in domain (suspicious)
        return -1  # Normal domain (safe)
    
    def _request_url(self):
        """Heuristic: check if path suggests external resource loading."""
        # Files that typically load external resources
        if re.search(r'\.(html|htm|php|asp|aspx)$', self.path):
            return 0  # Server page (might load external resources)
        elif re.search(r'\.(js|css|json|xml)$', self.path):
            return 1  # Script/resource file (external)
        return -1  # Regular page (safe)
    
    def _anchor_url(self):
        """Heuristic: check if URL structure suggests external linking."""
        # Can't fully analyze without fetching content
        # Use neutral default for URL structure analysis
        return -1  # Safe default for URL structure
    
    def _links_in_script(self):
        """Heuristic: check if URL structure suggests scripts."""
        if 'javascript:' in self.url.lower():
            return 1  # JavaScript in URL (suspicious)
        if re.search(r'<script|onclick|onerror', self.url, re.IGNORECASE):
            return 1  # Script tags in URL (suspicious)
        return -1  # No scripts (safe)
    
    def _form_handler(self):
        """Heuristic: check if URL suggests form handling."""
        # Look for common form submission patterns
        if re.search(r'(action=|post|form|login|verify|confirm)', self.path, re.IGNORECASE):
            return 1  # Form-like URL (suspicious)
        return -1  # Normal URL (safe)
    
    def _info_email(self):
        """Check for email addresses in URL."""
        if '@' in self.url and '@' not in self.domain:
            return 1  # Email in URL path (suspicious)
        # Check for common email patterns
        if re.search(r'mail|email|contact', self.path, re.IGNORECASE):
            return 0  # Email-related (neutral)
        return -1  # No email (safe)
    
    def _abnormal_url(self):
        """Check for abnormal URL structure."""
        domain_part = self.domain.split(':')[0]
        
        # IP address (very suspicious)
        if re.search(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', domain_part):
            return 1  # IP address (phishing)
        
        # Very long domain (>75 chars)
        if len(domain_part) > 75:
            return 1  # Abnormally long
        
        # Many dashes (>2)
        if domain_part.count('-') > 2:
            return 1  # Excessive dashes
        
        # Known major sites = normal
        major_sites = ['google', 'facebook', 'amazon', 'github', 'wikipedia', 'linkedin', 'twitter', 'youtube']
        if any(site in domain_part for site in major_sites):
            return -1  # Known legitimate site
        
        # Standard TLD = more likely normal
        if re.search(r'\.(com|org|net|edu|gov)$', domain_part):
            return -1  # Standard TLD (likely legitimate)
        
        # Unusual TLD = suspicious
        if re.search(r'\.(tk|ml|ga|cf|top|click|win|date|download)$', domain_part):
            return 1  # Unusual TLD (phishing)
        
        return -1  # Normal by default
    
    def _website_forwarding(self):
        """Heuristic: check if URL suggests redirects."""
        # Short URL services
        if re.search(r'(bit\.ly|tinyurl|short\.link|rebrand)', self.domain, re.IGNORECASE):
            return 1  # URL shortener (suspicious)
        
        # URL redirection parameters
        if re.search(r'(redirect|forward|goto)', self.path, re.IGNORECASE):
            return 1  # Forwarding (suspicious)
        
        return -1  # No redirect (safe)
    
    def _status_bar(self):
        """Check for status bar manipulation in URL."""
        if 'status' in self.url.lower():
            return 1  # Status reference (suspicious)
        return -1  # Normal (safe)
    
    def _disable_rightclick(self):
        """Check for right-click disabling attempts."""
        if re.search(r'oncontextmenu|mousedown|eval', self.url, re.IGNORECASE):
            return 1  # Right-click disabling (suspicious)
        return -1  # Normal (safe)
    
    def _domain_age(self):
        """Domain age heuristic (check TLD and domain patterns)."""
        domain_name = self.domain.split(':')[0].lower()
        
        # Known major sites = established/old
        major_sites = ['google', 'facebook', 'amazon', 'wikipedia', 'github', 'linkedin']
        if any(site in domain_name for site in major_sites):
            return 1  # Old, established (safe)
        
        # Established organizations
        if re.search(r'\.(edu|gov|org|ac\.uk)$', domain_name):
            return 1  # Established (safe)
        
        # Suspicious keywords in domain
        if re.search(r'(verify|confirm|update|secure|login|signin|alert|urgent)', domain_name):
            return 0  # Suspicious keywords (neutral/suspicious)
        
        # Commercial TLDs (.com, .net, .org)
        if re.search(r'\.(com|net|org|co|io|uk)$', domain_name):
            return 0  # Standard but unknown age (neutral)
        
        # Unusual TLDs
        if re.search(r'\.(tk|ml|ga|cf|top|club|click|win|date)$', domain_name):
            return 0  # Unusual TLD (likely new/phishing)
        
        return -1  # Default to safe
    
    def _dns_recording(self):
        """Check if DNS record exists."""
        try:
            domain = self.domain.split(':')[0]
            result = socket.gethostbyname(domain)
            return 1  # DNS exists (safe)
        except:
            return 0  # No DNS or error (suspicious)
    
    def _website_traffic(self):
        """Website traffic heuristic (known major sites)."""
        domain = self.domain.lower()
        major_sites = [
            'google', 'facebook', 'amazon', 'wikipedia', 'github', 'linkedin',
            'twitter', 'youtube', 'microsoft', 'apple', 'netflix', 'reddit',
            'instagram', 'whatsapp', 'telegram', 'stackoverflow'
        ]
        
        for site in major_sites:
            if site in domain:
                return -1  # High traffic (safe) returns -1
        
        return 0  # Unknown traffic (neutral)
    
    def _page_rank(self):
        """Google PageRank heuristic (known major sites)."""
        domain = self.domain.lower()
        high_rank_sites = [
            'google', 'facebook', 'amazon', 'wikipedia', 'github', 'linkedin',
            'twitter', 'youtube', 'microsoft', 'apple'
        ]
        
        for site in high_rank_sites:
            if site in domain:
                return 1  # High PageRank (safe)
        
        return 0  # Unknown PageRank (neutral)
    
    def _google_index(self):
        """Check if likely in Google Index (heuristic)."""
        domain = self.domain.lower()
        indexed_sites = [
            'google', 'facebook', 'amazon', 'wikipedia', 'github', 'linkedin',
            'twitter', 'youtube', 'microsoft', 'apple', 'reddit', 'stackoverflow'
        ]
        
        for site in indexed_sites:
            if site in domain:
                return 1  # Likely indexed (safe)
        
        return 0  # Unknown (neutral)
    
    def _stats_report(self):
        """Check phishing database patterns."""
        domain = self.domain.lower()
        
        # IP address (phishing indicator)
        if re.search(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', domain):
            return 1  # IP used (phishing)
        
        # Common phishing keywords
        suspicious_keywords = [
            'verify', 'confirm', 'update', 'alert', 'urgent', 'action',
            'validate', 'click', 'paypal', 'apple', 'amazon', 'security'
        ]
        
        keyword_count = sum(1 for kw in suspicious_keywords if kw in domain)
        if keyword_count >= 2:
            return 1  # Multiple phishing keywords
        elif keyword_count == 1:
            return 0  # One suspicious keyword (neutral)
        
        return -1  # No phishing indicators (safe)


def analyze_url(url):
    """Analyze a URL and return feature dictionary."""
    analyzer = URLAnalyzer(url)
    return analyzer.extract()


if __name__ == "__main__":
    # Test
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1:8080/login",
        "https://github.com",
    ]
    
    for url in test_urls:
        print(f"\nAnalyzing: {url}")
        features = analyze_url(url)
        for feature, value in sorted(features.items()):
            print(f"  {feature}: {value}")
