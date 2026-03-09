# config/loader.py

from pathlib import Path
import yaml

_config = None

def load_config() -> dict:
    global _config
    if _config is None:
        config_path = Path(__file__).parent / "rules.yaml"
        with open(config_path, "r") as f:
            _config = yaml.safe_load(f)
    return _config

def get_tetragon_rules() -> dict:
    return load_config().get("tetragon", {})

def get_system_namespaces() -> set:
    return set(load_config().get("system_namespaces", []))