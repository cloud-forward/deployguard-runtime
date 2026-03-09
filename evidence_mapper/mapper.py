import uuid
from datetime import datetime, timezone
from typing import Optional

from schemas.normalized_event import NormalizedEvent, EventSource, EventCategory
from schemas.evidence import Evidence, EvidenceType


# SA token 경로
SA_TOKEN_PATHS = [
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/secrets/kubernetes.io/serviceaccount",
]

# host 민감 경로
HOST_SENSITIVE_PATHS = [
    "/proc/1/environ",
    "/proc/1/cmdline",
    "/etc/shadow",
    "/etc/kubernetes",
    "/var/lib/kubelet",
    "/run/containerd",
    "/run/docker.sock",
    "/var/run/docker.sock",
]

# kube-apiserver IP 대역 (일반적으로 10.96.0.1 또는 클러스터 서비스 CIDR 첫 번째 IP)
KUBE_API_TARGETS = [
    "10.96.0.1",
    "kubernetes.default.svc",
    "kubernetes.default",
]

# IMDS IP
IMDS_IP = "169.254.169.254"


def map_to_evidence(event: NormalizedEvent) -> Optional[Evidence]:
    """
    NormalizedEvent 하나를 받아서 Evidence 하나를 반환.
    매핑이 안 되면 None 반환.
    """
    evidence_type = _determine_evidence_type(event)
    if evidence_type is None:
        return None

    return Evidence(
        evidence_id=str(uuid.uuid4()),
        evidence_type=evidence_type,
        timestamp=event.timestamp,
        namespace=event.actor.namespace,
        pod_name=event.actor.pod_name,
        service_account=event.actor.service_account,
        node_name=event.actor.node_name,
        detail=_build_detail(event, evidence_type),
        source_event_id=event.event_id,
        source=event.source.value,
    )


def _determine_evidence_type(event: NormalizedEvent) -> Optional[EvidenceType]:

    # ── Tetragon (FILE / NETWORK / PROCESS) ──────────────────────────────

    if event.source == EventSource.TETRAGON:

        # FILE: SA token 접근
        if event.category == EventCategory.FILE:
            if event.target and any(
                event.target.startswith(p) for p in SA_TOKEN_PATHS
            ):
                return EvidenceType.ACCESSED_SA_TOKEN

            # FILE: host 민감 경로 접근
            if event.target and any(
                event.target.startswith(p) for p in HOST_SENSITIVE_PATHS
            ):
                return EvidenceType.ACCESSED_HOST_SENSITIVE_PATH

        # NETWORK: IMDS 접근
        if event.category == EventCategory.NETWORK:
            if event.target == IMDS_IP:
                return EvidenceType.ACCESSED_IMDS

            # NETWORK: kube-apiserver 접근
            if event.target and any(
                event.target.startswith(t) for t in KUBE_API_TARGETS
            ):
                return EvidenceType.KUBE_API_ACCESS

        # PROCESS: 의심 실행
        if event.category == EventCategory.PROCESS:
            return EvidenceType.SUSPICIOUS_EXECUTION

    # ── Kubernetes Audit (K8S_API) ────────────────────────────────────────

    if event.source == EventSource.K8S_AUDIT:
        verb = event.action
        resource = event.target_resource

        if resource == "secrets":
            if verb == "get":
                return EvidenceType.READ_SECRET
            if verb == "list":
                return EvidenceType.LIST_SECRET

        if resource == "cronjobs" and verb == "create":
            return EvidenceType.CREATED_CRONJOB

        if resource == "daemonsets" and verb == "create":
            return EvidenceType.CREATED_DAEMONSET

        if resource in ("rolebindings", "clusterrolebindings") and verb == "create":
            return EvidenceType.CREATED_ROLEBINDING

        if resource == "pods" and event.raw:
            subresource = event.raw.get("objectRef", {}).get("subresource")
            if subresource == "exec":
                return EvidenceType.POD_EXEC_REQUEST

    return None


def _build_detail(event: NormalizedEvent, evidence_type: EvidenceType) -> dict:
    """evidence 타입별 추가 컨텍스트"""
    detail = {}

    if evidence_type in (
        EvidenceType.ACCESSED_SA_TOKEN,
        EvidenceType.ACCESSED_HOST_SENSITIVE_PATH,
    ):
        detail["path"] = event.target

    elif evidence_type in (
        EvidenceType.ACCESSED_IMDS,
        EvidenceType.KUBE_API_ACCESS,
    ):
        detail["destination"] = event.target

    elif evidence_type in (
        EvidenceType.READ_SECRET,
        EvidenceType.LIST_SECRET,
    ):
        detail["secret_name"] = event.target
        detail["namespace"] = event.target_namespace

    elif evidence_type in (
        EvidenceType.CREATED_CRONJOB,
        EvidenceType.CREATED_DAEMONSET,
        EvidenceType.CREATED_ROLEBINDING,
    ):
        detail["resource"] = event.target_resource
        detail["name"] = event.target
        detail["namespace"] = event.target_namespace

    elif evidence_type == EvidenceType.POD_EXEC_REQUEST:
        detail["pod"] = event.target
        detail["namespace"] = event.target_namespace

    elif evidence_type == EvidenceType.SUSPICIOUS_EXECUTION:
        detail["action"] = event.action
        detail["target"] = event.target

    return detail