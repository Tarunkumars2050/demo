import validators
import requests
import urllib3
import socket
import ssl

# List of known malicious domains (can be expanded or fetched from external sources)
MALICIOUS_DOMAINS = ["malware.com", "phishing.net", "evil.com"]

# Google Safe Browsing API Key (replace with your actual key)
API_KEY = "your_google_safe_browsing_api_key"

def validate_url(url):
    """Validate if the URL is well-formed."""
    if validators.url(url):
        return True
    else:
        return False

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

def check_http(url):
    """Check if the URL uses HTTP instead of HTTPS."""
    if url.startswith("http://"):
        return False, "URL is unsafe because it does not use HTTPS."
    return True, ""

def check_malicious_domain(url):
    """Check if the domain is in a list of known malicious domains."""
    domain = url.split("//")[-1].split("/")[0]  # Extract domain from URL
    if domain in MALICIOUS_DOMAINS:
        return False, f"URL belongs to a known malicious domain: {domain}."
    return True, ""

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
        pass  # If API fails, assume URL is safe
    return True, ""

def check_url_safety(url):
    """Combine all safety checks into one function."""
    # Validate URL format
    if not validate_url(url):
        return False, "Invalid URL format."

    # Check for HTTP usage
    is_safe, message = check_http(url)
    if not is_safe:
        return is_safe, message

    # Check SSL certificate
    if not check_ssl(url):
        return False, "URL does not have a valid SSL certificate."

    # Check against known malicious domains
    is_safe, message = check_malicious_domain(url)
    if not is_safe:
        return is_safe, message

    # Check using Google Safe Browsing API
    is_safe, message = check_google_safe_browsing(url)
    if not is_safe:
        return is_safe, message

    # If all checks pass
    return True, "The URL appears to be safe."
