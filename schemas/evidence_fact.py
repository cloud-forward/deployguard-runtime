"""
schemas/evidence_fact.py

[Layer 3] EvidenceFact — Runtime Scanner의 최종 출력 모델.

이 모델은 "최종 evidence 판정"이 아니라,
엔진 또는 상위 레이어가 다음 작업에 사용할 수 있는 공통 계약(contract)이다:
  - graph lookup / node-edge join
  - static scanner fact correlation
  - attack scenario chain matching
  - evidence_score / final_risk weighting

설계 원칙:
  - schema_version / fact_version 으로 하위 호환 유지
  - fact_family / fact_type 은 문자열 기반 + registry 확장
  - scenario_tags 는 런타임에 registry가 주입 (하드코딩 없음)
  - raw 전체 전송 금지 / raw_excerpt + raw_hash 만 보존
  - source_native_event_id / dedup_key 필수 보존
  - correlation_keys 로 static scanner graph join 가능
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Optional
from pydantic import BaseModel, Field, model_validator


# ── 버전 상수 ─────────────────────────────────────────────────────────

EVIDENCE_FACT_SCHEMA_VERSION = "1.0"


# ── Actor 모델 ────────────────────────────────────────────────────────

class ActorContext(BaseModel):
    """워크로드 행위자 식별자. graph node join의 기본 단위."""

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
    cloud_identity:  Optional[str] = None   # IRSA role ARN, instance profile 등
    image_ref:       Optional[str] = None   # image:tag 또는 digest


# ── EvidenceFact 메인 모델 ────────────────────────────────────────────

class EvidenceFact(BaseModel):
    """
    [Layer 3] EvidenceFact

    Scanner가 생성하는 공통 fact 단위.
    최종 판정(path_verdict / final_risk)은 포함하지 않는다.
    """

    # ── 메타 ──────────────────────────────────────────────────────────
    schema_version:  str = Field(default=EVIDENCE_FACT_SCHEMA_VERSION)
    fact_version:    str = Field(default="1.0")
    scanner_version: str = Field(default="unknown")
    cluster_id:      str                            # 필수 — env/Helm 주입

    # ── 타임스탬프 ────────────────────────────────────────────────────
    observed_at:  datetime                          # 원본 이벤트 발생 시각
    collected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    # ── 식별자 ────────────────────────────────────────────────────────
    scanner_event_id:       str                     # 내부 UUID (dedup용)
    source:                 str                     # "tetragon" | "k8s_audit"
    source_native_event_id: Optional[str] = None    # auditID / exec_id
    dedup_key:              str                     # 중복 제거 키

    # ── Fact 분류 ─────────────────────────────────────────────────────
    fact_family: str
    # 예: "credential_access", "execution", "persistence",
    #     "discovery", "lateral_movement", "exfiltration",
    #     "cloud_access", "privilege_escalation"
    # → 하드코딩 enum 강제 없음. registry 기반 확장.

    fact_type: str
    # 예: "sa_token_access", "imds_access", "suspicious_process",
    #     "secret_read", "pod_exec_request", "rolebinding_create", "aws_api_access"
    # → 향후 추가 가능. registry에서 관리.

    category: str
    # "process" | "file" | "network" | "k8s_api" | "cloud_api"

    action: str

    # ── 행위자 ────────────────────────────────────────────────────────
    actor: ActorContext

    # ── 대상 ──────────────────────────────────────────────────────────
    target:           Optional[str] = None
    target_type:      Optional[str] = None   # "secret" | "pod" | "rolebinding" 등
    target_resource:  Optional[str] = None
    target_namespace: Optional[str] = None

    # ── 결과 ──────────────────────────────────────────────────────────
    success:       Optional[bool] = None
    response_code: Optional[int]  = None

    # ── 힌트 (엔진이 최종 판정에 참고하는 soft signal) ────────────────
    confidence_hint: Optional[float] = None   # 0.0 ~ 1.0
    severity_hint:   Optional[str]   = None   # "low" | "medium" | "high" | "critical"

    # ── 확장 태그 / 연관 키 ───────────────────────────────────────────
    scenario_tags:    list[str] = Field(default_factory=list)
    # 예: ["irsa_chain", "credential_access", "aws_takeover"]
    # → registry가 주입. scanner가 직접 결정하지 않음.

    correlation_keys: dict[str, Any] = Field(default_factory=dict)
    # static scanner graph join에 사용.
    # 예: {"cluster_id": ..., "namespace": ..., "pod_name": ...,
    #      "service_account": ..., "workload_name": ..., "image_ref": ...}

    attributes: dict[str, Any] = Field(default_factory=dict)
    # fact_type별 추가 컨텍스트. 자유 형식.

    # ── 원본 보존 (raw 전체 전송 금지) ───────────────────────────────
    raw_excerpt: Optional[dict] = None
    # 원본에서 의미 있는 필드만 추출한 최소 사본.

    raw_hash: Optional[str] = None
    # raw 전체의 SHA-256. 원본 추적 / 무결성 확인용.

    # ── validator ────────────────────────────────────────────────────

    @model_validator(mode="after")
    def _ensure_correlation_keys(self) -> "EvidenceFact":
        """correlation_keys에 최소 식별자 보장."""
        ck = self.correlation_keys
        if self.cluster_id and "cluster_id" not in ck:
            ck["cluster_id"] = self.cluster_id
        a = self.actor
        for field, val in [
            ("namespace",       a.namespace),
            ("pod_name",        a.pod_name),
            ("pod_uid",         a.pod_uid),
            ("service_account", a.service_account),
            ("workload_name",   a.workload_name),
            ("workload_kind",   a.workload_kind),
            ("image_ref",       a.image_ref),
            ("cloud_identity",  a.cloud_identity),
        ]:
            if val and field not in ck:
                ck[field] = val
        self.correlation_keys = ck
        return self

    # ── 직렬화 헬퍼 ──────────────────────────────────────────────────

    def to_jsonl(self) -> str:
        return self.model_dump_json()

    @staticmethod
    def compute_raw_hash(raw: dict) -> str:
        serialized = json.dumps(raw, sort_keys=True, ensure_ascii=False, default=str)
        return hashlib.sha256(serialized.encode()).hexdigest()


# ── NormalizedRuntimeEvent (Layer 2) — 내부 처리용 ────────────────────
# 별도 파일로 분리되어 있으나 참조 편의를 위해 import re-export

from schemas.normalized_event import NormalizedRuntimeEvent, EventSource, EventCategory, WorkloadContext  # noqa: E402, F401
