import re
import requests
import socket
import ssl
import tldextract

# Google Safe Browsing API Key (replace with your actual key)
API_KEY = "your_google_safe_browsing_api_key"

# Trusted domains and TLDs
TRUSTED_DOMAINS = ["google.com", "paypal.com"]
TRUSTED_TLDS = [".gov", ".mil", ".edu"]

# Malicious domains for testing purposes
MALICIOUS_DOMAINS = ["malware.com", "phishing.net", "evil.com"]

def add_scheme_if_missing(url):
    """Add 'https://' to the URL if no scheme is present."""
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url

def validate_url_custom(url):
    """Custom function to validate if the URL is well-formed."""
    # Regex pattern for validating URLs
    pattern = re.compile(
        r'^(https?:\/\/)?'  # Optional scheme (http or https)
        r'(([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})'  # Domain name
        r'(\/[a-zA-Z0-9-._~:/?#[\]@!$&\'()*+,;%=]*)?$'  # Optional path/query
    )
    return re.match(pattern, url) is not None

def check_http(url):
    """Check if the URL uses HTTP instead of HTTPS."""
    if url.startswith("http://"):
        return False, "URL is unsafe because it does not use HTTPS."
    return True, ""

def check_ssl(url):
    """Check if the URL has a valid SSL certificate."""
    try:
        hostname = url.split("//")[-1].split("/")[0]  # Extract hostname
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                certificate = ssock.getpeercert()
                if certificate:
                    return True  # SSL certificate is valid
    except Exception:
        return False  # SSL certificate validation failed

def check_trusted_domains(url):
    """Check if the domain is in the list of trusted domains."""
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    if domain in TRUSTED_DOMAINS:
        return True, ""
    return False, ""

def check_malicious_domain(url):
    """Check if the domain is in a list of known malicious domains."""
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    if domain in MALICIOUS_DOMAINS:
        return False, f"URL belongs to a known malicious domain: {domain}."
    return True, ""

def check_tld(url):
    """Check if the TLD is in the list of trusted TLDs."""
    extracted = tldextract.extract(url)
    tld = f".{extracted.suffix}"
    if tld in TRUSTED_TLDS:
        return True, ""
    return False, f"URL uses an untrusted TLD: {tld}."

def check_google_safe_browsing(url):
    """Use Google Safe Browsing API to check for malicious URLs."""
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"
        payload = {
            "client": {
                "clientId": "url-safety-checker",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        response = requests.post(api_url, json=payload)
        if response.status_code == 200 and response.json():
            return False, "URL is flagged by Google Safe Browsing."
    except Exception as e:
        pass  # If API fails, assume URL is safe for now
    return True, ""

def check_url_safety(url):
    """Combine all safety checks into one function."""
    
    # Add scheme if missing
    url = add_scheme_if_missing(url)

    # Validate URL format
    if not validate_url_custom(url):
        return False, "Invalid URL format."

    # Check for HTTP usage
    is_safe, message = check_http(url)
    if not is_safe:
        return is_safe, message

    # Check SSL certificate
    if not check_ssl(url):
        return False, "URL does not have a valid SSL certificate."

    # Check against trusted domains
    is_safe, message = check_trusted_domains(url)
    if is_safe:
        return True, "The URL belongs to a trusted domain."

    # Check against known malicious domains
    is_safe, message = check_malicious_domain(url)
    if not is_safe:
        return is_safe, message

    # Check TLD trustworthiness
    is_safe, message = check_tld(url)
    if not is_safe:
        return is_safe, message

    # Check using Google Safe Browsing API
    is_safe, message = check_google_safe_browsing(url)
    if not is_safe:
        return is_safe, message

    # If all checks pass
    return True, "The URL appears to be safe."
