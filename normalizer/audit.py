"""
normalizer/audit.py

[Layer 1 → Layer 2] K8s Audit 이벤트 → NormalizedRuntimeEvent 변환.

변경 사항:
  - source_native_event_id = auditID (절대 버리지 않음)
  - success / response_code 보존
  - raw_excerpt 생성 (raw 전체 저장 금지)
  - objectRef / requestURI / user.username / responseStatus / source.host / userAgent 보존
  - graph correlation 필요 식별자 최대 보존
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from schemas.normalized_event import (
    NormalizedRuntimeEvent,
    EventSource,
    EventCategory,
    WorkloadContext,
)
from config.loader import get_system_users


# ── 내부 유틸 ─────────────────────────────────────────────────────────

def _parse_service_account(username: str) -> Optional[str]:
    """
    'system:serviceaccount:<namespace>:<sa-name>' → SA 이름 추출.
    일반 유저 → None.
    """
    if "serviceaccount" not in username:
        return None
    parts = username.split(":")
    return parts[3] if len(parts) >= 4 else parts[-1]


def _build_audit_raw_excerpt(raw: dict) -> dict:
    """
    Audit 이벤트에서 correlation / 재현에 필요한 최소 필드만 추출.
    raw 전체 전송 금지 원칙에 따라 선별적으로 보존.
    """
    obj    = raw.get("objectRef", {})
    user   = raw.get("user", {})
    status = raw.get("responseStatus", {})
    source = raw.get("source", {})

    return {
        "auditID":        raw.get("auditID"),
        "verb":           raw.get("verb"),
        "requestURI":     raw.get("requestURI"),
        "userAgent":      raw.get("userAgent"),
        "sourceIPs":      raw.get("sourceIPs"),
        "stage":          raw.get("stage"),
        "user": {
            "username": user.get("username"),
            "groups":   user.get("groups"),
            "uid":      user.get("uid"),
        },
        "objectRef": {
            "resource":    obj.get("resource"),
            "subresource": obj.get("subresource"),
            "namespace":   obj.get("namespace"),
            "name":        obj.get("name"),
            "apiVersion":  obj.get("apiVersion"),
        },
        "responseStatus": {
            "code":    status.get("code"),
            "reason":  status.get("reason"),
            "message": status.get("message"),
        },
        "source_host": source.get("host"),
        # requestObject는 Secret 값 등 민감 데이터를 포함할 수 있어 제외
        # responseObject도 제외 (크기 문제 + 민감 데이터)
    }


# ── 메인 normalizer ───────────────────────────────────────────────────

def normalize(raw: dict) -> Optional[NormalizedRuntimeEvent]:
    """
    K8s Audit JSON → NormalizedRuntimeEvent.

    반환 None 조건:
      - kind != "Event"
      - 시스템 유저의 이벤트
    """
    if raw.get("kind") != "Event":
        return None

    obj    = raw.get("objectRef", {})
    user   = raw.get("user", {})
    status = raw.get("responseStatus", {})
    source = raw.get("source", {})

    # 타임스탬프
    ts_str = raw.get("requestReceivedTimestamp") or raw.get("stageTimestamp")
    timestamp = (
        datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        if ts_str
        else datetime.now(timezone.utc)
    )

    # 시스템 유저 필터링
    username     = user.get("username", "")
    system_users = get_system_users()
    if any(username.startswith(u) for u in system_users):
        return None

    sa          = _parse_service_account(username)
    resource    = obj.get("resource", "")
    subresource = obj.get("subresource")

    # source_native_event_id = auditID (원본 식별자 보존)
    audit_id = raw.get("auditID")

    # response code / success
    response_code = status.get("code")
    success = (response_code is not None and response_code < 400) if response_code else None

    # raw_excerpt: 의미 있는 필드만 선별
    raw_excerpt = _build_audit_raw_excerpt(raw)

    return NormalizedRuntimeEvent(
        scanner_event_id=str(uuid.uuid4()),
        source_native_event_id=audit_id,          # ← 원본 ID 보존
        timestamp=timestamp,
        source=EventSource.K8S_AUDIT,
        category=EventCategory.K8S_API,
        actor=WorkloadContext(
            namespace=obj.get("namespace"),
            pod_name=obj.get("name") if resource == "pods" else None,
            service_account=sa,
            node_name=source.get("host"),
        ),
        action=raw.get("verb", ""),
        target=obj.get("name"),
        target_resource=resource,
        target_namespace=obj.get("namespace"),
        success=success,
        response_code=response_code,
        raw=raw,                                  # 내부 처리용 (외부 전송 불가)
    ), raw_excerpt


def normalize_with_excerpt(raw: dict):
    """
    normalize()와 동일하나 (NormalizedRuntimeEvent, raw_excerpt) 튜플 반환.
    fact_builder가 raw_excerpt를 EvidenceFact에 주입할 때 사용.
    """
    if raw.get("kind") != "Event":
        return None, None

    result = normalize(raw)
    if result is None:
        return None, None

    # normalize()가 튜플을 반환하도록 이미 수정되어 있음
    # 단독 호출 시 역호환성을 위해 아래 분기 유지
    if isinstance(result, tuple):
        return result

    raw_excerpt = _build_audit_raw_excerpt(raw)
    return result, raw_excerpt
