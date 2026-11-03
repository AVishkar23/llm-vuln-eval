import base64
import json

def load_session(cookie_value):
    raw = base64.b64decode(cookie_value)
    session = json.loads(raw.decode("utf-8"))
    return session
