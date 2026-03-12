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
    """강제 리로드 (테스트 또는 런타임 규칙 갱신용)"""
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
    """rules.yaml의 audit_rules 섹션 반환 — mapper가 동적으로 참조"""
    return load_config().get("audit_rules", [])


# ── Tetragon 세부 규칙 편의 함수 ─────────────────────────────────────

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
