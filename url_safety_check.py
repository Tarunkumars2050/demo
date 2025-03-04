import validators
import urllib3
import requests

MALICIOUS_DOMAINS = ["evil.com", "malware.com", "phishing.net"]

API_KEY = "your_google_safe_browsing_api_key"

def validate_url(url):
    if validators.url(url):
        return True
    else:
        return False

def check_ssl(url):
    try:
        http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', ca_certs=urllib3.util.ssl_.DEFAULT_CA_BUNDLE_PATH)
        response = http.request('GET', url)
        return True
    except Exception as e:
        return False

def check_malicious_domain(url):
    domain = url.split("//")[-1].split("/")[0]
    if domain in MALICIOUS_DOMAINS:
        return True
    return False

def check_google_safe_browsing(url):
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"
    payload = {
        "client": {
            "clientId": "your_project_name",
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
        return True
    return False

def check_url_safety(url):
    if not validate_url(url):
        return False, "Invalid URL format."
    
    if not check_ssl(url):
        return False, "URL does not have a valid SSL certificate."
    
    if check_malicious_domain(url):
        return False, "URL belongs to a known malicious domain."
    
    if check_google_safe_browsing(url):
        return False, "URL flagged by Google Safe Browsing."
    
    return True, "The URL appears to be safe."

if __name__ == "__main__":
    url = input("Enter a URL to check: ")
    is_safe, message = check_url_safety(url)
    if is_safe:
        print(f"The URL is safe: {message}")
    else:
        print(f"The URL is unsafe: {message}")
