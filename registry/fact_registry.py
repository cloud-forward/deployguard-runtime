"""
registry/fact_registry.py

Fact Type Registry — config/yaml 기반 확장 설계.

설계 원칙:
  - 코드에 fact_type / scenario_tag 를 하드코딩하지 않는다
  - fact_registry.yaml 또는 환경변수로 override 가능
  - 새 fact_type 추가 시 scanner core 로직 수정 불필요
  - 새 scenario 추가 시 YAML 항목 추가만으로 대응
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

import yaml


# ── 기본 내장 registry ────────────────────────────────────────────────
# 이 dict은 fallback용. 운영 환경에서는 fact_registry.yaml 로 override.

_BUILTIN_REGISTRY: dict[str, dict[str, Any]] = {

    # ── Credential Access ─────────────────────────────────────────────
    "sa_token_access": {
        "family":               "credential_access",
        "severity_hint":        "high",
        "confidence_hint":      0.85,
        "default_scenario_tags": [
            "irsa_chain",
            "credential_access",
            "aws_takeover",           # 시나리오 1
            "supply_chain_spread",    # 시나리오 2
        ],
        "description": "Service Account 토큰 파일 직접 접근",
    },
    "imds_access": {
        "family":               "credential_access",
        "severity_hint":        "high",
        "confidence_hint":      0.90,
        "default_scenario_tags": [
            "irsa_chain",
            "credential_access",
            "aws_takeover",
            "stale_resource_aws",     # 시나리오 3
        ],
        "description": "EC2 Instance Metadata Service 접근 (AWS 자격증명 탈취 시도)",
    },
    "secret_read": {
        "family":               "credential_access",
        "severity_hint":        "high",
        "confidence_hint":      0.80,
        "default_scenario_tags": [
            "credential_access",
            "irsa_chain",
            "supply_chain_spread",
        ],
        "description": "Kubernetes Secret 읽기",
    },
    "secret_list": {
        "family":               "discovery",
        "severity_hint":        "medium",
        "confidence_hint":      0.60,
        "default_scenario_tags": [
            "discovery",
            "credential_access",
        ],
        "description": "Kubernetes Secret 목록 조회",
    },

    # ── Execution ─────────────────────────────────────────────────────
    "suspicious_process": {
        "family":               "execution",
        "severity_hint":        "high",
        "confidence_hint":      0.75,
        "default_scenario_tags": [
            "execution",
            "supply_chain_spread",
            "aws_takeover",
        ],
        "description": "의심 바이너리 실행 (curl/nmap/bash 등)",
    },
    "pod_exec": {
        "family":               "execution",
        "severity_hint":        "high",
        "confidence_hint":      0.85,
        "default_scenario_tags": [
            "execution",
            "lateral_movement",
            "supply_chain_spread",
        ],
        "description": "Pod exec 요청 (kubectl exec 또는 API 직접 호출)",
    },

    # ── Persistence ───────────────────────────────────────────────────
    "rolebinding_create": {
        "family":               "persistence",
        "severity_hint":        "critical",
        "confidence_hint":      0.90,
        "default_scenario_tags": [
            "persistence",
            "privilege_escalation",
            "supply_chain_spread",
            "aws_takeover",
        ],
        "description": "RoleBinding/ClusterRoleBinding 생성 (권한 영속화)",
    },
    "cronjob_create": {
        "family":               "persistence",
        "severity_hint":        "high",
        "confidence_hint":      0.80,
        "default_scenario_tags": [
            "persistence",
            "supply_chain_spread",
        ],
        "description": "CronJob 생성 (스케줄 실행 영속화)",
    },
    "daemonset_create": {
        "family":               "persistence",
        "severity_hint":        "critical",
        "confidence_hint":      0.85,
        "default_scenario_tags": [
            "persistence",
            "lateral_movement",
            "supply_chain_spread",
        ],
        "description": "DaemonSet 생성 (전 노드 영속화)",
    },

    # ── Discovery ─────────────────────────────────────────────────────
    "kube_api_access": {
        "family":               "discovery",
        "severity_hint":        "medium",
        "confidence_hint":      0.60,
        "default_scenario_tags": [
            "discovery",
            "lateral_movement",
        ],
        "description": "Kubernetes API Server 직접 접근",
    },
    "host_sensitive_path_access": {
        "family":               "discovery",
        "severity_hint":        "high",
        "confidence_hint":      0.80,
        "default_scenario_tags": [
            "discovery",
            "privilege_escalation",
            "stale_resource_aws",
        ],
        "description": "호스트 민감 경로 접근 (/proc/1, /etc/shadow 등)",
    },

    # ── Cloud Access ──────────────────────────────────────────────────
    "aws_api_access": {
        "family":               "cloud_access",
        "severity_hint":        "high",
        "confidence_hint":      0.75,
        "default_scenario_tags": [
            "aws_takeover",
            "cloud_access",
            "irsa_chain",
        ],
        "description": "AWS API 직접 호출 (CloudTrail 연동 대상)",
    },
    "aws_credential_usage": {
        "family":               "cloud_access",
        "severity_hint":        "critical",
        "confidence_hint":      0.90,
        "default_scenario_tags": [
            "aws_takeover",
            "irsa_chain",
        ],
        "description": "AWS 자격증명 실제 사용 감지",
    },
}


# ── Registry 로더 ─────────────────────────────────────────────────────

_loaded_registry: Optional[dict[str, dict[str, Any]]] = None


def _registry_path() -> Optional[Path]:
    env_path = os.environ.get("FACT_REGISTRY_PATH")
    if env_path:
        return Path(env_path)
    candidates = [
        Path(__file__).parent / "fact_registry.yaml",
        Path("/etc/deployguard/fact_registry.yaml"),
        Path("/config/fact_registry.yaml"),
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def load_registry(force: bool = False) -> dict[str, dict[str, Any]]:
    """
    Registry 로드 순서:
      1) 이미 로드된 캐시
      2) fact_registry.yaml (파일 존재 시)
      3) builtin fallback

    YAML 파일의 항목은 builtin 항목을 override/extend 한다.
    """
    global _loaded_registry
    if _loaded_registry is not None and not force:
        return _loaded_registry

    registry = dict(_BUILTIN_REGISTRY)

    yaml_path = _registry_path()
    if yaml_path and yaml_path.exists():
        try:
            with open(yaml_path) as f:
                extra: dict = yaml.safe_load(f) or {}
            for fact_type, meta in extra.items():
                if fact_type in registry:
                    registry[fact_type].update(meta)
                else:
                    registry[fact_type] = meta
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(
                f"fact_registry.yaml 로드 실패 (builtin 사용): {e}"
            )

    _loaded_registry = registry
    return _loaded_registry


def get_fact_meta(fact_type: str) -> dict[str, Any]:
    """fact_type에 해당하는 registry 항목 반환. 없으면 빈 dict."""
    return load_registry().get(fact_type, {})


def get_scenario_tags(fact_type: str) -> list[str]:
    return get_fact_meta(fact_type).get("default_scenario_tags", [])


def get_family(fact_type: str) -> str:
    return get_fact_meta(fact_type).get("family", "unknown")


def get_severity_hint(fact_type: str) -> Optional[str]:
    return get_fact_meta(fact_type).get("severity_hint")


def get_confidence_hint(fact_type: str) -> Optional[float]:
    return get_fact_meta(fact_type).get("confidence_hint")


def reload_registry() -> dict[str, dict[str, Any]]:
    """런타임 규칙 갱신용 강제 리로드."""
    return load_registry(force=True)
