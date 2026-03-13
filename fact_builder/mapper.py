"""
fact_builder/mapper.py

[Layer 2 → Layer 3] NormalizedRuntimeEvent → EvidenceFact 변환.

역할 변경:
  이전: NormalizedEvent → final Evidence (최종 판정 포함)
  이후: NormalizedRuntimeEvent → EvidenceFact (correlation 가능한 사실 단위)

원칙:
  - 최종 판정(path_verdict / final_risk) 절대 포함하지 않음
  - fact_type 분류는 registry 기반 (하드코딩 enum 강제 없음)
  - 매핑 불가 이벤트는 None 반환이 아닌 "unknown" fact로 보존 (선택적)
  - source_native_event_id / dedup_key / success / response_code 반드시 전달
  - raw_excerpt 주입 (외부에서 전달받음)
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Optional, Tuple

from schemas.normalized_event import (
    NormalizedRuntimeEvent,
    EventSource,
    EventCategory,
)
from schemas.evidence_fact import EvidenceFact, ActorContext
from registry.fact_registry import (
    get_family,
    get_scenario_tags,
    get_severity_hint,
    get_confidence_hint,
)
from config.loader import (
    get_sa_token_paths,
    get_sensitive_paths,
    get_imds_addresses,
    get_kube_api_targets,
    get_audit_rules,
)


# ── 공개 인터페이스 ───────────────────────────────────────────────────

def build_evidence_fact(
    event:       NormalizedRuntimeEvent,
    raw_excerpt: Optional[dict] = None,
    raw_full:    Optional[dict] = None,
    cluster_id:  str = "unknown",
    scanner_version: str = "unknown",
) -> Optional[EvidenceFact]:
    """
    NormalizedRuntimeEvent → EvidenceFact.

    반환 None 조건:
      - fact_type을 분류할 수 없고, drop_unclassified=True (기본값)
      - 향후 drop_unclassified=False 옵션으로 unknown fact 보존 가능

    raw_full: raw 전체 dict. raw_hash 계산에만 사용되며 payload에 포함하지 않음.
    """
    fact_type, attributes = _classify(event)
    if fact_type is None:
        return None

    fact_family = get_family(fact_type)

    actor = ActorContext(
        namespace=event.actor.namespace,
        pod_name=event.actor.pod_name,
        pod_uid=event.actor.pod_uid,
        container_name=event.actor.container_name,
        container_id=event.actor.container_id,
        service_account=event.actor.service_account,
        node_name=event.actor.node_name,
        workload_name=event.actor.workload_name,
        workload_kind=event.actor.workload_kind,
        workload_uid=event.actor.workload_uid,
        cloud_identity=event.actor.cloud_identity,
        image_ref=event.actor.image_ref,
    )

    dedup_key = _make_dedup_key(event, fact_type)

    raw_hash = None
    if raw_full:
        raw_hash = EvidenceFact.compute_raw_hash(raw_full)
    elif raw_excerpt:
        raw_hash = EvidenceFact.compute_raw_hash(raw_excerpt)

    # target_type 추론
    target_type = _infer_target_type(event)

    return EvidenceFact(
        schema_version=  "1.0",
        fact_version=    "1.0",
        scanner_version= scanner_version,
        cluster_id=      cluster_id,
        observed_at=     event.timestamp,
        collected_at=    datetime.now(timezone.utc),
        scanner_event_id=event.scanner_event_id,
        source=          event.source.value,
        source_native_event_id=event.source_native_event_id,
        dedup_key=       dedup_key,

        fact_family=     fact_family,
        fact_type=       fact_type,
        category=        event.category.value,
        action=          event.action,

        actor=           actor,

        target=          event.target,
        target_type=     target_type,
        target_resource= event.target_resource,
        target_namespace=event.target_namespace,

        success=         event.success,
        response_code=   event.response_code,

        confidence_hint= get_confidence_hint(fact_type),
        severity_hint=   get_severity_hint(fact_type),

        scenario_tags=   get_scenario_tags(fact_type),
        correlation_keys={},   # model_validator가 actor에서 자동 채움
        attributes=      attributes,

        raw_excerpt=     raw_excerpt,
        raw_hash=        raw_hash,
    )


# ── fact_type 분류 ────────────────────────────────────────────────────

def _classify(
    event: NormalizedRuntimeEvent,
) -> Tuple[Optional[str], dict]:
    """
    (fact_type, attributes) 반환.
    fact_type=None → 분류 불가.
    """
    if event.source == EventSource.TETRAGON:
        return _classify_tetragon(event)
    if event.source == EventSource.K8S_AUDIT:
        return _classify_audit(event)
    return None, {}


def _classify_tetragon(
    event: NormalizedRuntimeEvent,
) -> Tuple[Optional[str], dict]:

    # ── FILE ──────────────────────────────────────────────────────────
    if event.category == EventCategory.FILE:
        if event.target:
            sa_paths = get_sa_token_paths()
            if any(event.target.startswith(p) for p in sa_paths):
                return "sa_token_access", {"path": event.target}

            sensitive = get_sensitive_paths()
            if any(event.target.startswith(p) for p in sensitive):
                return "host_sensitive_path_access", {"path": event.target}

        # 알려진 경로 아님 → None으로 버리지 않고 generic file_access로 보존
        # 운영 환경에서 노이즈가 많으면 아래를 None으로 변경
        return "file_access", {"path": event.target}

    # ── NETWORK ───────────────────────────────────────────────────────
    if event.category == EventCategory.NETWORK:
        if event.target:
            imds = get_imds_addresses()
            if event.target in imds:
                return "imds_access", {"destination": event.target}

            kube_targets = get_kube_api_targets()
            if any(event.target.startswith(t) for t in kube_targets):
                return "kube_api_access", {"destination": event.target}

        # 알 수 없는 네트워크 연결 — 선택적으로 보존
        return "network_connect", {"destination": event.target}

    # ── PROCESS ───────────────────────────────────────────────────────
    if event.category == EventCategory.PROCESS:
        return "suspicious_process", {
            "binary": event.target,
            "action": event.action,
        }

    return None, {}


def _classify_audit(
    event: NormalizedRuntimeEvent,
) -> Tuple[Optional[str], dict]:
    """
    K8S_AUDIT 이벤트 분류.
    rules.yaml audit_rules 기반 동적 매핑.
    """
    verb     = event.action
    resource = event.target_resource

    # pod exec (subresource 기반)
    if resource == "pods" and event.raw:
        subresource = event.raw.get("objectRef", {}).get("subresource")
        if subresource == "exec":
            return "pod_exec", {
                "pod":       event.target,
                "namespace": event.target_namespace,
            }

    # audit_rules YAML 매핑
    for rule in get_audit_rules():
        if rule.get("resource") == resource and rule.get("verb") == verb:
            # evidence_type 문자열을 fact_type으로 변환 (하위 호환)
            evidence_type_str = rule.get("evidence_type", "")
            fact_type         = _evidence_type_to_fact_type(evidence_type_str)
            attrs: dict       = {
                "resource":  resource,
                "verb":      verb,
                "name":      event.target,
                "namespace": event.target_namespace,
            }
            return fact_type, attrs

    # 매핑 안 된 audit 이벤트 → k8s_api_call로 보존 (버리지 않음)
    return "k8s_api_call", {
        "resource": resource,
        "verb":     verb,
        "name":     event.target,
        "namespace":event.target_namespace,
    }


# ── 보조 함수 ─────────────────────────────────────────────────────────

_EVIDENCE_TO_FACT: dict[str, str] = {
    "READ_SECRET":        "secret_read",
    "LIST_SECRET":        "secret_list",
    "CREATED_CRONJOB":    "cronjob_create",
    "CREATED_DAEMONSET":  "daemonset_create",
    "CREATED_ROLEBINDING":"rolebinding_create",
    "POD_EXEC_REQUEST":   "pod_exec",
    "AWS_API_ACCESS":     "aws_api_access",
    "AWS_CREDENTIAL_USAGE":"aws_credential_usage",
}


def _evidence_type_to_fact_type(evidence_type_str: str) -> str:
    """
    기존 EvidenceType 문자열 → fact_type 변환 (하위 호환 브릿지).
    알 수 없는 값은 소문자 변환으로 그대로 사용.
    """
    return _EVIDENCE_TO_FACT.get(
        evidence_type_str,
        evidence_type_str.lower(),
    )


def _make_dedup_key(event: NormalizedRuntimeEvent, fact_type: str) -> str:
    """
    dedup_key: source_native_event_id 우선, 없으면 (source+actor+target+fact_type) 해시.
    """
    if event.source_native_event_id:
        return f"{event.source.value}:{event.source_native_event_id}:{fact_type}"

    parts = ":".join(filter(None, [
        event.source.value,
        event.actor.namespace or "",
        event.actor.pod_name or "",
        event.target or "",
        fact_type,
        event.timestamp.isoformat(),
    ]))
    return hashlib.sha256(parts.encode()).hexdigest()[:32]


def _infer_target_type(event: NormalizedRuntimeEvent) -> Optional[str]:
    resource = event.target_resource
    if not resource:
        if event.category == EventCategory.FILE:
            return "file"
        if event.category == EventCategory.NETWORK:
            return "network_endpoint"
        return None

    type_map = {
        "secrets":             "secret",
        "pods":                "pod",
        "rolebindings":        "rolebinding",
        "clusterrolebindings": "clusterrolebinding",
        "cronjobs":            "cronjob",
        "daemonsets":          "daemonset",
        "deployments":         "deployment",
        "serviceaccounts":     "serviceaccount",
        "configmaps":          "configmap",
    }
    return type_map.get(resource, resource)
