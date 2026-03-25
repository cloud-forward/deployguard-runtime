"""
runtime_api/schemas.py

Pydantic request/response 모델.

원칙:
  - raw EvidenceFact를 프론트에 그대로 노출하지 않는다.
  - dashboard용 summary/detail 모델만 노출.
  - "Correlated Risk / Confirmed Risk / Attack Detected" 표현 금지.
  - runtime_evidence / image_exposure / related_signals 상태형 표현 사용.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Ingest ────────────────────────────────────────────────────────────

class FactPayload(BaseModel):
    """
    scanner → POST /runtime/facts 단일 fact 페이로드.
    EvidenceFact.model_dump(mode='json') 결과와 동일한 구조.
    raw 원문은 포함하지 않는다.
    """
    schema_version:         str
    fact_version:           str
    scanner_version:        str
    cluster_id:             str

    observed_at:            datetime
    collected_at:           datetime

    scanner_event_id:       str
    source:                 str
    source_native_event_id: Optional[str] = None
    dedup_key:              str

    fact_family:            str
    fact_type:              str
    category:               str
    action:                 str

    actor:                  dict[str, Any]

    target:                 Optional[str] = None
    target_type:            Optional[str] = None
    target_resource:        Optional[str] = None
    target_namespace:       Optional[str] = None

    success:                Optional[bool] = None
    response_code:          Optional[int]  = None

    confidence_hint:        Optional[float] = None
    severity_hint:          Optional[str]   = None

    scenario_tags:          list[str] = Field(default_factory=list)
    correlation_keys:       dict[str, Any] = Field(default_factory=dict)
    attributes:             dict[str, Any] = Field(default_factory=dict)

    raw_excerpt:            Optional[dict] = None
    raw_hash:               Optional[str]  = None


class IngestResponse(BaseModel):
    accepted:  int
    duplicate: int
    total:     int


# ── Workload Summary ──────────────────────────────────────────────────

class RuntimeSignal(BaseModel):
    """단일 런타임 신호 요약. raw EvidenceFact 비노출."""
    fact_type:     str
    fact_family:   str
    category:      str
    severity_hint: Optional[str]
    observed_at:   datetime
    source:        str
    target:        Optional[str]
    scenario_tags: list[str]
    action:        str
    success:       Optional[bool]


class ImageExposure(BaseModel):
    """
    image_ref 기준 CVE/exposure join 결과.
    image scanner가 S3에 저장한 summary를 runtime_api가 읽어 병치.
    """
    image_ref:          str
    image_digest:       str = ""
    critical_cve_count: int = 0
    high_cve_count:     int = 0
    fix_available:      bool = False
    poc_exists:         bool = False
    sbom_available:     bool = False
    sbom_source:        Optional[str] = None
    last_scanned_at:    Optional[datetime] = None
    sample_cves:        list[str] = Field(default_factory=list)


# ── Aggregate 모델 ────────────────────────────────────────────────────

class ExposureAggregate(BaseModel):
    """
    image_exposure[] 전체에서 집계한 static exposure 요약.
    프론트가 카드/KPI/정렬에 직접 사용.
    """
    critical_cve_count:   int = 0
    high_cve_count:       int = 0
    has_fix_available:    bool = False
    has_poc:              bool = False
    image_count:          int = 0
    latest_scanned_at:    Optional[datetime] = None
    sources:              list[str] = Field(default_factory=list)


class EvidenceAggregate(BaseModel):
    """
    runtime_evidence(fact) 전체에서 집계한 동적 신호 요약.
    프론트가 카드/KPI/정렬에 직접 사용.
    """
    count:            int = 0
    latest_at:        Optional[datetime] = None
    fact_families:    list[str] = Field(default_factory=list)
    scenario_tags:    list[str] = Field(default_factory=list)
    highest_severity: Optional[str] = None   # low|medium|high|critical


# ── Workload Summary ──────────────────────────────────────────────────

class WorkloadSummary(BaseModel):
    """
    GET /runtime/workloads 응답 단위.
    workload 기준 집계된 runtime 상태 + aggregate exposure/evidence 포함.
    """
    workload_id:    str
    cluster_id:     str
    namespace:      str
    workload_kind:  str
    workload_name:  str

    # runtime 신호 집계 (하위 호환 유지)
    signal_count:           int
    latest_signal_at:       Optional[datetime]
    highest_severity:       Optional[str]
    active_fact_families:   list[str]
    active_scenario_tags:   list[str]

    # image exposure (SBOM join)
    image_refs:     list[str]
    image_exposure: list[ImageExposure] = Field(default_factory=list)

    # ── 신규: aggregate 필드 ──────────────────────────────────────────
    # exposure aggregate — 프론트 카드/KPI/정렬용
    exposure_critical_cve_count: int = 0
    exposure_high_cve_count:     int = 0
    exposure_has_fix_available:  bool = False
    exposure_has_poc:            bool = False
    exposure_image_count:        int = 0
    exposure_latest_scanned_at:  Optional[datetime] = None
    exposure_sources:            list[str] = Field(default_factory=list)

    # evidence aggregate — 프론트 카드/KPI/정렬용
    evidence_count:            int = 0
    evidence_latest_at:        Optional[datetime] = None
    evidence_fact_families:    list[str] = Field(default_factory=list)
    evidence_scenario_tags:    list[str] = Field(default_factory=list)
    evidence_highest_severity: Optional[str] = None

    # 대시보드 노출 자격
    dashboard_eligible: bool = False
    dashboard_category: Optional[str] = None
    dashboard_reason:   Optional[str] = None

    # 마지막 업데이트
    last_seen_at:   Optional[datetime]


class WorkloadListResponse(BaseModel):
    total:     int
    workloads: list[WorkloadSummary]


# ── Workload Detail ───────────────────────────────────────────────────

class WorkloadDetail(BaseModel):
    """
    GET /runtime/workloads/{workload_id} 응답.
    list는 압축, detail은 근거까지 충분히.
    """
    workload_id:   str
    cluster_id:    str
    namespace:     str
    workload_kind: str
    workload_name: str

    # 런타임 신호 목록 (최근 N개)
    runtime_evidence: list[RuntimeSignal]

    # 이미지 노출 (SBOM join)
    image_refs:       list[str]
    image_exposure:   list[ImageExposure]

    # 관련 신호 (scenario_tag 기준 cluster-wide 연관)
    related_signals:  list[RuntimeSignal] = Field(default_factory=list)

    # actor 컨텍스트 최신 스냅샷
    service_account:  Optional[str]
    node_name:        Optional[str]
    cloud_identity:   Optional[str]

    last_seen_at:     Optional[datetime]
    first_seen_at:    Optional[datetime]

    # ── 신규: aggregate 필드 (list와 동일 구조) ───────────────────────
    exposure_critical_cve_count: int = 0
    exposure_high_cve_count:     int = 0
    exposure_has_fix_available:  bool = False
    exposure_has_poc:            bool = False
    exposure_image_count:        int = 0
    exposure_latest_scanned_at:  Optional[datetime] = None
    exposure_sources:            list[str] = Field(default_factory=list)

    evidence_count:            int = 0
    evidence_latest_at:        Optional[datetime] = None
    evidence_fact_families:    list[str] = Field(default_factory=list)
    evidence_scenario_tags:    list[str] = Field(default_factory=list)
    evidence_highest_severity: Optional[str] = None

    dashboard_eligible: bool = False
    dashboard_category: Optional[str] = None
    dashboard_reason:   Optional[str] = None
