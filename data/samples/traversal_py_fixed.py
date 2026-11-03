import os

BASE_DIR = "/var/www/files"

def read_file(filename):
    safe_name = os.path.basename(filename)
    path = os.path.realpath(os.path.join(BASE_DIR, safe_name))
    if not path.startswith(os.path.realpath(BASE_DIR)):
        raise ValueError("path escapes base directory")
    with open(path, "r") as f:
        return f.read()
