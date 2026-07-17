# Fixture: arquivo Python com paths absolutos embutidos em strings.
# Cobre cenário "Path() literal" e "string interpolada" para adversarial threat tree.

CONFIG_PATH = r"C:\Users\usra\proj\config.json"
LOG_DIR = "/home/usra/logs/"
CACHE_DIR = "/Users/usra/Library/Caches"


def load_config():
    """Lê config de path absoluto Windows."""
    return open(CONFIG_PATH).read()


def write_log(msg):
    """Path Unix /home/."""
    with open(LOG_DIR + "run.log", "a") as f:
        f.write(msg)
