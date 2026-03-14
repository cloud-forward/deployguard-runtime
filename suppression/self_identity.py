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


@dataclass
class ScannerIdentity:
    pod_name: Optional[str] = None
    pod_namespace: Optional[str] = None
    pod_uid: Optional[str] = None
    service_account: Optional[str] = None
    node_name: Optional[str] = None
    container_name: Optional[str] = None
    workload_name: Optional[str] = None
    workload_kind: Optional[str] = None
    labels: dict[str, str] = field(default_factory=dict)
    annotations: dict[str, str] = field(default_factory=dict)

    def to_match_labels(self) -> dict[str, str]:
        labels = dict(self.labels or {})
        labels.setdefault("deployguard.io/internal-collector", "true")
        if self.service_account:
            labels.setdefault("deployguard.io/service-account", self.service_account)
        if self.container_name:
            labels.setdefault("deployguard.io/container-name", self.container_name)
        return labels

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
        if self.pod_uid and pod_uid and self.pod_uid == pod_uid:
            return True

        if self.pod_name and pod_name and self.pod_name == pod_name:
            return True

        if (
            self.pod_namespace and namespace and self.pod_namespace == namespace
            and self.service_account and service_account and self.service_account == service_account
        ):
            if self.container_name and container_name:
                return self.container_name == container_name
            return True

        if (
            self.workload_name and workload_name and self.workload_name == workload_name
            and self.workload_kind and workload_kind and self.workload_kind == workload_kind
        ):
            return True

        return False


def _read_namespace_fallback() -> Optional[str]:
    try:
        if _NS_FILE.exists():
            value = _NS_FILE.read_text().strip()
            return value or None
    except Exception:
        pass
    return None


def load_scanner_identity() -> ScannerIdentity:
    pod_name = os.environ.get("POD_NAME") or os.environ.get("HOSTNAME")
    pod_namespace = os.environ.get("POD_NAMESPACE") or _read_namespace_fallback()
    pod_uid = os.environ.get("POD_UID")
    service_account = os.environ.get("SERVICE_ACCOUNT")
    node_name = os.environ.get("NODE_NAME")
    container_name = os.environ.get("SCANNER_CONTAINER_NAME") or "scanner"

    labels: dict[str, str] = {}
    annotations: dict[str, str] = {}
    workload_name: Optional[str] = None
    workload_kind: Optional[str] = None

    if pod_name and pod_namespace:
        try:
            result = subprocess.run(
                ["kubectl", "get", "pod", pod_name, "-n", pod_namespace, "-o", "json"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                meta = data.get("metadata", {}) or {}
                spec = data.get("spec", {}) or {}
                owners = meta.get("ownerReferences", []) or []

                labels = meta.get("labels", {}) or {}
                annotations = meta.get("annotations", {}) or {}
                pod_uid = pod_uid or meta.get("uid")
                service_account = service_account or spec.get("serviceAccountName")
                node_name = node_name or spec.get("nodeName")

                if owners:
                    workload_name = owners[0].get("name")
                    workload_kind = owners[0].get("kind")
            else:
                log.warning("self identity kubectl 조회 실패: rc=%s stderr=%s", result.returncode, result.stderr)
        except Exception as e:
            log.warning("self identity kubectl 조회 예외: %s", e)

    identity = ScannerIdentity(
        pod_name=pod_name,
        pod_namespace=pod_namespace,
        pod_uid=pod_uid,
        service_account=service_account,
        node_name=node_name,
        container_name=container_name,
        workload_name=workload_name,
        workload_kind=workload_kind,
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