import uuid
from typing import Optional

from schemas.normalized_event import NormalizedEvent, EventSource, EventCategory
from schemas.evidence import Evidence, EvidenceType
from config.loader import (
    get_sa_token_paths,
    get_sensitive_paths,
    get_imds_addresses,
    get_kube_api_targets,
    get_audit_rules,
)


def map_to_evidence(event: NormalizedEvent) -> Optional[Evidence]:
    """
    NormalizedEvent → Evidence 변환.
    매핑 불가 시 None 반환.
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


# ── Evidence 타입 결정 ────────────────────────────────────────────────

def _determine_evidence_type(event: NormalizedEvent) -> Optional[EvidenceType]:

    if event.source == EventSource.TETRAGON:
        return _map_tetragon_event(event)

    if event.source == EventSource.K8S_AUDIT:
        return _map_audit_event(event)

    return None


def _map_tetragon_event(event: NormalizedEvent) -> Optional[EvidenceType]:
    """Tetragon 이벤트 → EvidenceType"""

    # FILE 이벤트
    if event.category == EventCategory.FILE:
        if event.target:
            sa_token_paths = get_sa_token_paths()
            if any(event.target.startswith(p) for p in sa_token_paths):
                return EvidenceType.ACCESSED_SA_TOKEN

            sensitive_paths = get_sensitive_paths()
            if any(event.target.startswith(p) for p in sensitive_paths):
                return EvidenceType.ACCESSED_HOST_SENSITIVE_PATH

        return None  # FILE이지만 알려진 경로 아님 → 무시

    # NETWORK 이벤트
    if event.category == EventCategory.NETWORK:
        if event.target:
            imds_addresses = get_imds_addresses()
            if event.target in imds_addresses:
                return EvidenceType.ACCESSED_IMDS

            kube_api_targets = get_kube_api_targets()
            if any(event.target.startswith(t) for t in kube_api_targets):
                return EvidenceType.KUBE_API_ACCESS

        return None

    # PROCESS 이벤트
    if event.category == EventCategory.PROCESS:
        return EvidenceType.SUSPICIOUS_EXECUTION

    return None


def _map_audit_event(event: NormalizedEvent) -> Optional[EvidenceType]:
    """
    K8S_AUDIT 이벤트 → EvidenceType.
    rules.yaml의 audit_rules 섹션을 동적으로 참조하므로
    새 resource/verb 쌍은 YAML만 수정하면 됨.
    """
    verb     = event.action
    resource = event.target_resource

    # pod exec는 subresource 기반이라 별도 처리
    if resource == "pods" and event.raw:
        subresource = event.raw.get("objectRef", {}).get("subresource")
        if subresource == "exec":
            return EvidenceType.POD_EXEC_REQUEST

    # YAML 규칙 테이블 순회
    for rule in get_audit_rules():
        if rule.get("resource") == resource and rule.get("verb") == verb:
            evidence_type_str = rule.get("evidence_type")
            try:
                return EvidenceType(evidence_type_str)
            except ValueError:
                # YAML에 정의된 evidence_type이 EvidenceType enum에 없는 경우
                # → 조용히 무시하지 않고 경고를 올릴 수 있도록 예외를 위로 전파
                raise ValueError(
                    f"rules.yaml의 audit_rules에 알 수 없는 evidence_type: "
                    f"'{evidence_type_str}' (resource={resource}, verb={verb})"
                )

    return None


# ── Evidence 상세 정보 구성 ───────────────────────────────────────────

def _build_detail(event: NormalizedEvent, evidence_type: EvidenceType) -> dict:
    """evidence_type별 추가 컨텍스트 딕셔너리"""
    detail: dict = {}

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
        detail["namespace"]   = event.target_namespace

    elif evidence_type in (
        EvidenceType.CREATED_CRONJOB,
        EvidenceType.CREATED_DAEMONSET,
        EvidenceType.CREATED_ROLEBINDING,
    ):
        detail["resource"]  = event.target_resource
        detail["name"]      = event.target
        detail["namespace"] = event.target_namespace

    elif evidence_type == EvidenceType.POD_EXEC_REQUEST:
        detail["pod"]       = event.target
        detail["namespace"] = event.target_namespace

    elif evidence_type == EvidenceType.SUSPICIOUS_EXECUTION:
        detail["binary"] = event.target
        detail["action"] = event.action

    return detail
