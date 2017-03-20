import os


def get_cache_home():
    try:
        return get_cache_home._value
    except AttributeError:
        pass
    try:
        cache_base = os.environ['XDG_CACHE_HOME']
    except KeyError:
        cache_base = os.path.expanduser('~/.cache')
    cache_dir = os.path.join(cache_base, 'dmarc_policy_parser')
    os.makedirs(cache_dir, exist_ok=True)
    get_cache_home._value = cache_dir
    return cache_dir


def set_cache_home(d):
    get_cache_home._value = d


def get_path(filename):
    return os.path.join(get_cache_home(), filename)
