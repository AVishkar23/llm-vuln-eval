import urllib.request
from urllib.parse import urlparse

ALLOWED_HOSTS = {"example.com", "cdn.example.com"}

def fetch_preview(url):
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("URL host is not allowlisted")
    with urllib.request.urlopen(url) as response:
        return response.read()
