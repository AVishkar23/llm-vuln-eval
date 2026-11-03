import requests
from urllib.parse import urlparse

ALLOWED_HOSTS = {"example.com", "cdn.example.com"}

def fetch_preview(url):
    return _fetch_validated(url, redirects_left=3)

def _fetch_validated(url, redirects_left):
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("URL is not allowlisted")
    response = requests.get(url, timeout=5, allow_redirects=False)
    if response.is_redirect:
        if redirects_left == 0:
            raise ValueError("too many redirects")
        # Every hop is re-validated: a redirect only moves the request
        # to another allowlisted https URL.
        return _fetch_validated(response.headers["Location"], redirects_left - 1)
    return response.content
