import os

BASE_DIR = "/var/www/files"

def read_file(filename):
    path = os.path.join(BASE_DIR, filename)
    with open(path, "r") as f:
        return f.read()
