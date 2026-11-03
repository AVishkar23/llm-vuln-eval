import urllib.request

def fetch_preview(url):
    with urllib.request.urlopen(url) as response:
        return response.read()
