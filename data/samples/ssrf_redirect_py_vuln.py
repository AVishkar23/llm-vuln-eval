import requests
from urllib.parse import urlparse

ALLOWED_HOSTS = {"example.com", "cdn.example.com"}

def fetch_preview(url):
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("host is not allowlisted")
    response = requests.get(url, timeout=5)
    if response.is_redirect:
        # BUG: the redirect target is never re-validated -- an allowlisted
        # host can bounce the request to an internal address.
        target = response.headers["Location"]
        response = requests.get(target, timeout=5)
    return response.content
