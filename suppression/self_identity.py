"""
suppression/self_identity.py

Scanner 자기 자신의 runtime identity 수집.

원칙:
  - POD_NAME / SERVICE_ACCOUNT 같은 env를 Helm/Downward API로 주입받아 사용
  - hardcoded 문자열 없음
  - 수집된 identity는 suppression label_map에 주입되어
    workload_labels 매칭에서 활용됨

Kubernetes Downward API 환경변수 (daemonset.yaml에서 주입):
  POD_NAME, POD_NAMESPACE, POD_UID, SERVICE_ACCOUNT, NODE_NAME

자기 라벨/어노테이션은 kubectl get pod $POD_NAME -o json 에서 읽는다.
Pod 자체 메타를 얻을 수 없을 때는 env만으로 fallback.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)


@dataclass
class ScannerIdentity:
    """
    Scanner Pod의 runtime identity.
    suppression 매칭 시 workload_labels/annotations로 주입.
    """
    pod_name:        Optional[str] = None
    pod_namespace:   Optional[str] = None
    pod_uid:         Optional[str] = None
    service_account: Optional[str] = None
    node_name:       Optional[str] = None
    labels:          dict[str, str] = field(default_factory=dict)
    annotations:     dict[str, str] = field(default_factory=dict)

    def is_self(self, pod_uid: Optional[str], pod_name: Optional[str]) -> bool:
        """다른 이벤트의 actor가 자기 자신인지 확인 (pod_uid 우선)."""
        if self.pod_uid and pod_uid:
            return self.pod_uid == pod_uid
        if self.pod_name and pod_name:
            return self.pod_name == pod_name
        return False


def load_scanner_identity() -> ScannerIdentity:
    """
    Downward API env + kubectl self-describe로 identity 수집.
    실패해도 예외를 올리지 않고 가용한 정보만 반환.
    """
    pod_name      = os.environ.get("POD_NAME")
    pod_namespace = os.environ.get("POD_NAMESPACE")
    pod_uid       = os.environ.get("POD_UID")
    service_account = os.environ.get("SERVICE_ACCOUNT")
    node_name     = os.environ.get("NODE_NAME")

    labels:      dict[str, str] = {}
    annotations: dict[str, str] = {}

    # kubectl로 자기 Pod 메타 조회 (라벨/어노테이션 포함)
    if pod_name and pod_namespace:
        try:
            result = subprocess.run(
                ["kubectl", "get", "pod", pod_name,
                 "-n", pod_namespace, "-o", "json"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                data        = json.loads(result.stdout)
                meta        = data.get("metadata", {})
                labels      = meta.get("labels", {})
                annotations = meta.get("annotations", {})
                # env에 없던 정보 보완
                pod_uid       = pod_uid or meta.get("uid")
                service_account = service_account or (
                    data.get("spec", {}).get("serviceAccountName")
                )
        except Exception as e:
            log.debug(f"self identity kubectl 조회 실패 (env fallback): {e}")

    identity = ScannerIdentity(
        pod_name=       pod_name,
        pod_namespace=  pod_namespace,
        pod_uid=        pod_uid,
        service_account=service_account,
        node_name=      node_name,
        labels=         labels,
        annotations=    annotations,
    )

    log.info(
        f"Scanner identity: pod={pod_name} ns={pod_namespace} "
        f"uid={pod_uid} labels={labels}"
    )
    return identity


# ── 싱글턴 ────────────────────────────────────────────────────────────

_identity: Optional[ScannerIdentity] = None


def get_identity() -> ScannerIdentity:
    global _identity
    if _identity is None:
        _identity = load_scanner_identity()
    return _identity
