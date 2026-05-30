"""
PhishGuard - Advanced Phishing URL Detector
Cybersecurity Analysis Engine with Web Interface
Detects phishing attempts using intelligent heuristic analysis
"""

from flask import Flask, render_template, request, jsonify
import json
import re
from urllib.parse import urlparse, parse_qs

app = Flask(__name__)

# Threat intelligence patterns
PHISHING_INDICATORS = {
    "keywords": [
        "login", "verify", "secure", "account", "update", "confirm",
        "banking", "paypal", "amazon", "apple", "microsoft", "google",
        "facebook", "signin", "password", "reset", "urgent", "suspended",
        "blocked", "alert", "click", "free", "prize", "winner", "limited",
        "action required", "confirm identity", "verify account"
    ],
    "free_tlds": [
        ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz",
        ".top", ".club", ".online", ".site", ".info", ".work"
    ],
    "shorteners": [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl",
        "ow.ly", "short.link", "rebrand.ly", "is.gd"
    ]
}

LEGITIMATE_DOMAINS = [
    "google.com", "github.com", "microsoft.com", "apple.com",
    "amazon.com", "facebook.com", "twitter.com", "linkedin.com",
    "youtube.com", "wikipedia.org", "stackoverflow.com", "reddit.com",
    "paypal.com", "ebay.com", "instagram.com", "netflix.com",
    "slack.com", "github.com", "stackoverflow.com", "medium.com"
]

# Example URLs for demonstration
EXAMPLE_URLS = {
    "safe": [
        {"url": "https://www.google.com", "label": "Google Search"},
        {"url": "https://github.com", "label": "GitHub"},
        {"url": "https://stackoverflow.com", "label": "Stack Overflow"},
        {"url": "https://www.amazon.com/products", "label": "Amazon Shopping"},
        {"url": "https://www.wikipedia.org", "label": "Wikipedia"},
    ],
    "suspicious": [
        {"url": "http://pay-pal-verify.tk/login", "label": "Fake PayPal (Free TLD + HTTP)"},
        {"url": "https://appie-verify.goog.com/confirm-account", "label": "Apple Impersonation"},
        {"url": "http://192.168.1.100/secure/login", "label": "IP Address Login Page"},
        {"url": "https://bit.ly/verify-your-account", "label": "Shortened URL Phish"},
        {"url": "https://google-security-update.online/update", "label": "Google Spoofing"},
        {"url": "https://secure-amazon-verify-now.club/account", "label": "Amazon Phishing"},
        {"url": "https://verify.microsoft-update.cf/signin", "label": "Microsoft Impersonation"},
    ]
}



# URL Processing and Analysis Engine
def parse_url_components(url):
    """Extract URL components with proper error handling"""
    url = url.strip()
    
    # Ensure scheme is present
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    try:
        parsed = urlparse(url)
        return {
            "scheme": parsed.scheme or "https",
            "hostname": (parsed.hostname or "").lower(),
            "path": parsed.path or "/",
            "query": parsed.query or "",
            "full": url,
            "port": parsed.port
        }
    except Exception:
        return None

def extract_domain(hostname):
    """Extract root domain from hostname"""
    if not hostname:
        return ""
    
    # Handle IP addresses
    if is_valid_ip(hostname):
        return hostname
    
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname

def get_subdomain_part(hostname):
    """Get subdomain portion"""
    parts = hostname.split(".")
    if len(parts) > 2:
        return ".".join(parts[:-2])
    return ""

def is_valid_ip(host):
    """Check if hostname is a raw IP address"""
    try:
        parts = host.split(".")
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit() or not (0 <= int(part) <= 255):
                return False
        return True
    except:
        return False

def analyze_url(url):
    """Comprehensive phishing analysis with detailed heuristics"""
    url = url.strip()
    parsed = parse_url_components(url)
    
    if not parsed:
        return None
    
    hostname = parsed["hostname"]
    full_url = parsed["full"].lower()
    domain = extract_domain(hostname)
    subdomain = get_subdomain_part(hostname)
    tld = "." + hostname.split(".")[-1] if "." in hostname else ""
    
    findings = []
    risk_score = 0
    
    # Check 1: HTTPS Protocol
    if parsed["scheme"] == "https":
        findings.append(create_finding("Encryption", "PASS", "HTTPS protocol enabled", 0, "success"))
    else:
        findings.append(create_finding("Encryption", "FAIL", "No encryption - HTTP only", 20, "danger"))
        risk_score += 20
    
    # Check 2: IP Address Detection
    if is_valid_ip(hostname):
        findings.append(create_finding("Hostname", "FAIL", f"IP address used ({hostname}) instead of domain", 35, "danger"))
        risk_score += 35
    else:
        findings.append(create_finding("Hostname", "PASS", f"Legitimate domain format: {domain}", 0, "success"))
    
    # Check 3: URL Shortener
    shortener_match = any(short in hostname for short in PHISHING_INDICATORS["shorteners"])
    if shortener_match:
        findings.append(create_finding("Redirect", "WARN", "URL shortener used - hides actual destination", 25, "warning"))
        risk_score += 25
    else:
        findings.append(create_finding("Redirect", "PASS", "Full URL visible, not shortened", 0, "success"))
    
    # Check 4: Free TLD Analysis
    if tld and tld in PHISHING_INDICATORS["free_tlds"]:
        findings.append(create_finding("Domain TLD", "FAIL", f"Free/disposable TLD detected: {tld}", 32, "danger"))
        risk_score += 32
    else:
        findings.append(create_finding("Domain TLD", "PASS", f"Standard TLD: {tld}", 0, "success"))
    
    # Check 5: Subdomain Analysis
    subdomain_count = len(subdomain.split(".")) if subdomain else 0
    if subdomain_count > 3:
        findings.append(create_finding("Subdomains", "FAIL", f"Excessive subdomains ({subdomain_count} levels) - common in phishing", 20, "danger"))
        risk_score += 20
    elif subdomain_count == 2:
        findings.append(create_finding("Subdomains", "WARN", f"Multiple subdomains detected: {subdomain}", 8, "warning"))
        risk_score += 8
    else:
        findings.append(create_finding("Subdomains", "PASS", "Normal subdomain structure", 0, "success"))
    
    # Check 6: Brand Impersonation
    brand_impersonation = check_brand_impersonation(subdomain, domain)
    if brand_impersonation:
        findings.append(create_finding("Brand Safety", "FAIL", f"Potential brand impersonation detected: '{brand_impersonation}'", 40, "danger"))
        risk_score += 40
    else:
        findings.append(create_finding("Brand Safety", "PASS", "No brand impersonation patterns detected", 0, "success"))
    
    # Check 7: Suspicious Keywords
    keyword_matches = [w for w in PHISHING_INDICATORS["keywords"] if w.lower() in full_url]
    if len(keyword_matches) > 3:
        findings.append(create_finding("Suspicious Terms", "FAIL", f"Multiple phishing keywords: {', '.join(keyword_matches[:3])}", 18, "danger"))
        risk_score += 18
    elif len(keyword_matches) > 0:
        findings.append(create_finding("Suspicious Terms", "WARN", f"Phishing keywords found: {', '.join(keyword_matches)}", 10, "warning"))
        risk_score += 10
    else:
        findings.append(create_finding("Suspicious Terms", "PASS", "No suspicious keywords detected", 0, "success"))
    
    # Check 8: URL Length
    url_length = len(parsed["full"])
    if url_length > 120:
        findings.append(create_finding("URL Length", "FAIL", f"Unusually long URL ({url_length} chars) - may hide real destination", 12, "danger"))
        risk_score += 12
    elif url_length > 85:
        findings.append(create_finding("URL Length", "WARN", f"Long URL ({url_length} chars)", 5, "warning"))
        risk_score += 5
    else:
        findings.append(create_finding("URL Length", "PASS", f"Normal length ({url_length} chars)", 0, "success"))
    
    # Check 9: @ Symbol Abuse
    if "@" in parsed["full"]:
        findings.append(create_finding("URL Obfuscation", "FAIL", "@ symbol detected - browser may ignore everything before it", 30, "danger"))
        risk_score += 30
    else:
        findings.append(create_finding("URL Obfuscation", "PASS", "No obfuscation techniques detected", 0, "success"))
    
    # Check 10: Hyphen Analysis
    hyphen_count = domain.count("-")
    if hyphen_count >= 3:
        findings.append(create_finding("Domain Hyphens", "FAIL", f"Excessive hyphens ({hyphen_count}) - common in spoofed domains", 12, "danger"))
        risk_score += 12
    elif hyphen_count >= 1:
        findings.append(create_finding("Domain Hyphens", "WARN", f"Domain contains {hyphen_count} hyphen(s)", 3, "warning"))
        risk_score += 3
    else:
        findings.append(create_finding("Domain Hyphens", "PASS", "No suspicious hyphens", 0, "success"))
    
    # Trusted domain bonus
    if domain in LEGITIMATE_DOMAINS:
        risk_score = max(0, risk_score - 25)
        findings.insert(0, create_finding("Trusted Domain", "VERIFIED", "Recognized legitimate domain", -25, "success"))
    
    # Cap score at 100
    risk_score = min(max(risk_score, 0), 100)
    
    # Determine verdict
    if risk_score < 20:
        verdict = "SAFE"
        severity = "low"
        icon = "SAFE"
    elif risk_score < 50:
        verdict = "SUSPICIOUS"
        severity = "medium"
        icon = "WARN"
    else:
        verdict = "HIGH RISK"
        severity = "high"
        icon = "RISK"
    
    return {
        "url": parsed["full"],
        "hostname": hostname,
        "domain": domain,
        "subdomain": subdomain,
        "scheme": parsed["scheme"],
        "findings": findings,
        "risk_score": risk_score,
        "verdict": verdict,
        "severity": severity,
        "icon": icon
    }

def create_finding(check_name, status, detail, points, level):
    """Helper to create finding objects"""
    return {
        "check": check_name,
        "status": status,
        "detail": detail,
        "points": points,
        "level": level
    }

def check_brand_impersonation(subdomain, domain):
    """Detect if subdomain impersonates known brands"""
    brands = [d.split(".")[0] for d in LEGITIMATE_DOMAINS]
    
    for brand in brands:
        if brand.lower() in subdomain.lower() and brand not in domain.lower():
            return brand
    return None



# Flask Web Routes and Templates

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html', examples=EXAMPLE_URLS)

@app.route('/api/scan', methods=['POST'])
def scan():
    """API endpoint for URL scanning"""
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({"error": "URL is required"}), 400
    
    if len(url) < 4:
        return jsonify({"error": "Please enter a valid URL"}), 400
    
    result = analyze_url(url)
    
    if not result:
        return jsonify({"error": "Invalid URL format"}), 400
    
    return jsonify(result)

@app.route('/api/examples')
def get_examples():
    """Get example URLs"""
    return jsonify(EXAMPLE_URLS)

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)