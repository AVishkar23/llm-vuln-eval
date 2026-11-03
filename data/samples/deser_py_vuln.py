import base64
import pickle

def load_session(cookie_value):
    raw = base64.b64decode(cookie_value)
    session = pickle.loads(raw)
    return session
