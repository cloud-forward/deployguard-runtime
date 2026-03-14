from __future__ import annotations

import json
import logging
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

_NS_FILE = Path("/var/run/secrets/kubernetes.io/serviceaccount/namespace")


def _read_text(path: Path) -> Optional[str]:
    try:
        if path.exists():
            value = path.read_text(encoding="utf-8").strip()
            return value or None
    except Exception:
        pass
    return None


def _run_kubectl_get_pod(pod_name: str, namespace: str) -> Optional[dict]:
    try:
        result = subprocess.run(
            ["kubectl", "get", "pod", pod_name, "-n", namespace, "-o", "json"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            log.debug(
                "self identity kubectl 조회 실패: rc=%s stderr=%s",
                result.returncode,
                result.stderr.strip(),
            )
            return None
        return json.loads(result.stdout)
    except Exception as e:
        log.debug("self identity kubectl 조회 예외: %s", e)
        return None


def _infer_container_name_from_pod(data: Optional[dict]) -> Optional[str]:
    if not data:
        return None

    try:
        containers = data.get("spec", {}).get("containers", []) or []
        names = [c.get("name") for c in containers if c.get("name")]
        if not names:
            return None
        if len(names) == 1:
            return names[0]
        if "scanner" in names:
            return "scanner"
        return names[0]
    except Exception:
        return None


@dataclass
class ScannerIdentity:
    pod_name: Optional[str] = None
    pod_namespace: Optional[str] = None
    pod_uid: Optional[str] = None
    service_account: Optional[str] = None
    node_name: Optional[str] = None
    container_name: Optional[str] = None
    labels: dict[str, str] = field(default_factory=dict)
    annotations: dict[str, str] = field(default_factory=dict)

    def to_match_labels(self) -> dict[str, str]:
        merged = dict(self.labels)

        merged.setdefault("deployguard.io/internal-collector", "true")
        if self.service_account:
            merged.setdefault("deployguard.io/service-account", self.service_account)
        if self.container_name:
            merged.setdefault("deployguard.io/container-name", self.container_name)
        if self.pod_namespace:
            merged.setdefault("deployguard.io/namespace", self.pod_namespace)
        if self.node_name:
            merged.setdefault("deployguard.io/node-name", self.node_name)

        return merged

    def is_self(
        self,
        pod_uid: Optional[str],
        pod_name: Optional[str],
        namespace: Optional[str] = None,
        service_account: Optional[str] = None,
        container_name: Optional[str] = None,
        workload_name: Optional[str] = None,
        workload_kind: Optional[str] = None,
    ) -> bool:
        # 1) exact pod match
        if self.pod_uid and pod_uid and self.pod_uid == pod_uid:
            return True

        if (
            self.pod_name
            and pod_name
            and self.pod_name == pod_name
            and self.pod_namespace
            and namespace
            and self.pod_namespace == namespace
        ):
            return True

        # 2) rollout 이후에도 유지되는 stable identity
        if (
            self.pod_namespace
            and namespace
            and self.pod_namespace == namespace
            and self.service_account
            and service_account
            and self.service_account == service_account
        ):
            if self.container_name and container_name:
                return self.container_name == container_name
            return True

        return False


def load_scanner_identity() -> ScannerIdentity:
    pod_name = os.environ.get("POD_NAME") or os.environ.get("HOSTNAME")
    pod_namespace = os.environ.get("POD_NAMESPACE") or _read_text(_NS_FILE)
    pod_uid = os.environ.get("POD_UID")
    service_account = os.environ.get("SERVICE_ACCOUNT")
    node_name = os.environ.get("NODE_NAME")
    container_name = os.environ.get("SCANNER_CONTAINER_NAME") or "scanner"

    labels: dict[str, str] = {}
    annotations: dict[str, str] = {}

    pod_data: Optional[dict] = None
    if pod_name and pod_namespace:
        pod_data = _run_kubectl_get_pod(pod_name, pod_namespace)

    if pod_data:
        meta = pod_data.get("metadata", {}) or {}
        spec = pod_data.get("spec", {}) or {}

        labels = meta.get("labels", {}) or {}
        annotations = meta.get("annotations", {}) or {}

        pod_uid = pod_uid or meta.get("uid")
        service_account = service_account or spec.get("serviceAccountName")
        node_name = node_name or spec.get("nodeName")
        container_name = container_name or _infer_container_name_from_pod(pod_data)

    identity = ScannerIdentity(
        pod_name=pod_name,
        pod_namespace=pod_namespace,
        pod_uid=pod_uid,
        service_account=service_account,
        node_name=node_name,
        container_name=container_name,
        labels=labels,
        annotations=annotations,
    )

    log.info(
        "Scanner identity: pod=%s ns=%s uid=%s sa=%s container=%s labels=%s",
        identity.pod_name,
        identity.pod_namespace,
        identity.pod_uid,
        identity.service_account,
        identity.container_name,
        identity.labels,
    )
    return identity


_identity: Optional[ScannerIdentity] = None


def get_identity() -> ScannerIdentity:
    global _identity
    if _identity is None:
        _identity = load_scanner_identity()
    return _identity


def reload_identity() -> ScannerIdentity:
    global _identity
    _identity = load_scanner_identity()
    return _identity