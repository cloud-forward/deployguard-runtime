"""
config/loader.py

설정 로더.
변경 사항:
  - get_audit_rules() 유지 (하위 호환)
  - fact_registry 로드 경로 추가
"""

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


def reload_config() -> dict:
    global _config
    _config = None
    return load_config()


def get_tetragon_rules() -> dict:
    return load_config().get("tetragon", {})


def get_system_namespaces() -> set:
    return set(load_config().get("system_namespaces", []))


def get_system_users() -> set:
    return set(load_config().get("system_users", []))


def get_audit_rules() -> list[dict]:
    return load_config().get("audit_rules", [])


def get_sa_token_paths() -> list[str]:
    return get_tetragon_rules().get("sa_token_paths", [])


def get_sensitive_paths() -> list[str]:
    return get_tetragon_rules().get("sensitive_paths", [])


def get_suspicious_binaries() -> list[str]:
    return get_tetragon_rules().get("suspicious_binaries", [])


def get_imds_addresses() -> list[str]:
    return get_tetragon_rules().get("imds_addresses", [])


def get_kube_api_targets() -> list[str]:
    return get_tetragon_rules().get("kube_api_targets", [])


def get_file_open_functions() -> list[str]:
    return get_tetragon_rules().get("file_open_functions", [])


def get_network_connect_functions() -> list[str]:
    return get_tetragon_rules().get("network_connect_functions", [])
