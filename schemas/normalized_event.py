"""
schemas/normalized_event.py

[Layer 2] NormalizedRuntimeEvent — Scanner 내부 처리용 얇은 정규화 모델.

- Tetragon / K8s Audit 원본을 공통 구조로 변환
- EvidenceFact(Layer 3)로 승격되기 전 단계
- raw 전체를 보존하되 외부 전송 대상이 아님
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel


class EventSource(str, Enum):
    TETRAGON  = "tetragon"
    K8S_AUDIT = "k8s_audit"


class EventCategory(str, Enum):
    PROCESS   = "process"
    FILE      = "file"
    NETWORK   = "network"
    K8S_API   = "k8s_api"
    CLOUD_API = "cloud_api"


class WorkloadContext(BaseModel):
    """Layer 2 내부용 워크로드 컨텍스트 (ActorContext의 전신)."""

    cluster:         Optional[str] = None
    namespace:       Optional[str] = None
    pod_name:        Optional[str] = None
    pod_uid:         Optional[str] = None
    container_name:  Optional[str] = None
    container_id:    Optional[str] = None
    service_account: Optional[str] = None
    node_name:       Optional[str] = None
    workload_name:   Optional[str] = None
    workload_kind:   Optional[str] = None
    workload_uid:    Optional[str] = None
    cloud_identity:  Optional[str] = None
    image_ref:       Optional[str] = None


class NormalizedRuntimeEvent(BaseModel):
    """
    [Layer 2] 내부 정규화 이벤트.

    scanner_event_id : 내부 UUID
    source_native_event_id : auditID / exec_id 등 원본 식별자 (절대 버리지 않음)
    raw : 원본 전체 보존 — 내부 처리 전용, 외부 전송 불가
    """

    scanner_event_id:       str
    source_native_event_id: Optional[str] = None   # auditID / exec_id
    timestamp:              datetime
    source:                 EventSource
    category:               EventCategory
    actor:                  WorkloadContext
    action:                 str
    target:                 Optional[str] = None
    target_resource:        Optional[str] = None
    target_namespace:       Optional[str] = None
    success:                Optional[bool] = None
    response_code:          Optional[int]  = None
    raw:                    Optional[dict] = None   # 내부 전용


# ── 하위 호환 alias ───────────────────────────────────────────────────
# 기존 코드가 NormalizedEvent를 import하는 경우를 위한 shim
NormalizedEvent = NormalizedRuntimeEvent
