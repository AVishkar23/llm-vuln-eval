import yaml

def load_profile(yaml_text):
    # Loading with the default (full) Loader constructs arbitrary
    # Python objects -- a crafted document is code execution, not data.
    return yaml.load(yaml_text)
