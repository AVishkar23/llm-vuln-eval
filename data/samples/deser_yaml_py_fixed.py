import yaml

def load_profile(yaml_text):
    # SafeLoader only builds plain dicts/lists/scalars -- no objects.
    return yaml.load(yaml_text, Loader=yaml.SafeLoader)
