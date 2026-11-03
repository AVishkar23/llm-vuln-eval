import os

API_KEY = os.environ["SERVICE_API_KEY"]

def auth_headers():
    return {"Authorization": f"Bearer {API_KEY}"}
