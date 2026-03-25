"""
runtime_api/services/workload_detail.py

workload list / detail 서비스 레이어.

변경 사항:
  - aggregate_image_exposure() : ImageExposure[] → ExposureAggregate
  - aggregate_runtime_evidence() : FactPayload[] → EvidenceAggregate
  - is_unknown_workload() : workload_name/namespace 미상 판별
  - is_noise_workload() : self-noise/deployguard 판별
  - is_dashboard_eligible() : 대시보드 노출 자격 판별
  - sort_workload_summaries() : exposure+evidence 기반 우선순위 정렬
  - list_workloads() : dashboard_eligible==True 만 반환 (기본값)
  - build_summary() : aggregate 필드 포함
  - get_workload_detail() : aggregate 필드 포함
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Any, List, Optional

from runtime_api.schemas import (
    EvidenceAggregate,
    ExposureAggregate,
    FactPayload,
    ImageExposure,
    RuntimeSignal,
    WorkloadDetail,
    WorkloadSummary,
)
from runtime_api.services.exposure_query import ImageExposureSummary, lookup_exposure
from runtime_api.store import FactStore, get_store

log = logging.getLogger(__name__)

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_DETAIL_SIGNAL_LIMIT = int(os.environ.get("DETAIL_SIGNAL_LIMIT", "50"))
_RELATED_LIMIT = int(os.environ.get("RELATED_SIGNAL_LIMIT", "20"))

# 노이즈로 간주할 네임스페이스 목록 (환경변수로 확장 가능)
_NOISE_NAMESPACES: set[str] = {
    "deployguard",
    "kube-system",
    "kube-public",
    "kube-node-lease",
    "kube-flannel",
    "cert-manager",
    "monitoring",
    "ingress-nginx",
}
_extra_noise = os.environ.get("NOISE_NAMESPACES", "")
if _extra_noise:
    _NOISE_NAMESPACES.update(n.strip() for n in _extra_noise.split(",") if n.strip())


# ── helpers ──────────────────────────────────────────────────────────────

def _to_signal(fact: FactPayload) -> RuntimeSignal:
    return RuntimeSignal(
        fact_type=fact.fact_type,
        fact_family=fact.fact_family,
        category=fact.category,
        severity_hint=fact.severity_hint,
        observed_at=fact.observed_at,
        source=fact.source,
        target=fact.target,
        scenario_tags=fact.scenario_tags,
        action=fact.action,
        success=fact.success,
    )


def _highest_severity(facts: List[FactPayload]) -> Optional[str]:
    best, best_val = None, 0
    for f in facts:
        val = _SEVERITY_ORDER.get(f.severity_hint or "", 0)
        if val > best_val:
            best_val, best = val, f.severity_hint
    return best


def _image_refs(facts: List[FactPayload]) -> List[str]:
    seen: set = set()
    refs: List[str] = []
    for f in facts:
        ref = f.actor.get("image_ref")
        if ref and ref not in seen:
            seen.add(ref)
            refs.append(ref)
    return refs


def _image_digests(facts: List[FactPayload]) -> List[str]:
    seen: set = set()
    out: List[str] = []
    for f in facts:
        d = f.actor.get("image_digest", "")
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out


def _parse_workload_id(wid: str) -> tuple[str, str, str, str]:
    parts = wid.split(":", 3)
    if len(parts) == 4:
        return parts[0], parts[1], parts[2], parts[3]
    return wid, "", "Pod", wid


def _exposure_to_schema(exp: ImageExposureSummary) -> ImageExposure:
    return ImageExposure(
        image_ref=exp.image_ref,
        image_digest=exp.image_digest,
        critical_cve_count=exp.critical_cve_count,
        high_cve_count=exp.high_cve_count,
        fix_available=exp.fix_available,
        poc_exists=exp.poc_exists,
        sample_cves=exp.sample_cves,
    )


# ── aggregate 함수 ────────────────────────────────────────────────────────

def aggregate_image_exposure(exposures: List[ImageExposure]) -> ExposureAggregate:
    """
    ImageExposure[] → ExposureAggregate.
    프론트 카드/KPI/정렬에 직접 사용할 집계값.
    """
    if not exposures:
        return ExposureAggregate()

    critical = sum(e.critical_cve_count for e in exposures)
    high = sum(e.high_cve_count for e in exposures)
    has_fix = any(e.fix_available for e in exposures)
    has_poc = any(e.poc_exists for e in exposures)
    scanned_dates = [e.last_scanned_at for e in exposures if e.last_scanned_at]
    latest_scanned = max(scanned_dates) if scanned_dates else None
    sources = sorted({e.sbom_source for e in exposures if e.sbom_source})

    return ExposureAggregate(
        critical_cve_count=critical,
        high_cve_count=high,
        has_fix_available=has_fix,
        has_poc=has_poc,
        image_count=len(exposures),
        latest_scanned_at=latest_scanned,
        sources=sources,
    )


def aggregate_runtime_evidence(facts: List[FactPayload]) -> EvidenceAggregate:
    """
    FactPayload[] → EvidenceAggregate.
    프론트 카드/KPI/정렬에 직접 사용할 집계값.
    """
    if not facts:
        return EvidenceAggregate()

    latest_at = max((f.observed_at for f in facts), default=None)
    families = sorted({f.fact_family for f in facts})
    tags = sorted({t for f in facts for t in f.scenario_tags})
    highest = _highest_severity(facts)

    return EvidenceAggregate(
        count=len(facts),
        latest_at=latest_at,
        fact_families=families,
        scenario_tags=tags,
        highest_severity=highest,
    )


# ── eligibility / filter 함수 ─────────────────────────────────────────────

def is_unknown_workload(workload_name: str, namespace: str) -> bool:
    """
    workload_name이 unknown이거나 namespace가 비어있으면 True.
    actor 정보가 부정확해 생긴 garbage summary를 걸러낸다.
    """
    if not workload_name or workload_name.lower() == "unknown":
        return True
    if not namespace:
        return True
    return False


def is_noise_workload(namespace: str, workload_name: str) -> bool:
    """
    deployguard/kube-system 등 self-noise 네임스페이스이면 True.
    운영 워크로드가 아닌 인프라 컴포넌트를 걸러낸다.
    """
    if namespace in _NOISE_NAMESPACES:
        return True
    return False


def is_dashboard_eligible(
    workload_name: str,
    namespace: str,
    image_exposure: List[ImageExposure],
) -> bool:
    """
    대시보드 목록에 노출할 자격 판별.

    조건 (모두 만족해야 True):
      1. unknown workload 아님
      2. noise namespace 아님
      3. image_exposure가 1개 이상 존재
    """
    if is_unknown_workload(workload_name, namespace):
        return False
    if is_noise_workload(namespace, workload_name):
        return False
    if not image_exposure:
        return False
    return True


# ── 정렬 함수 ─────────────────────────────────────────────────────────────

_SEV_KEY = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def sort_workload_summaries(summaries: List[WorkloadSummary]) -> List[WorkloadSummary]:
    """
    "대응 우선순위" 기준 정렬.

    우선순위 (내림차순):
      1. exposure_critical_cve_count
      2. exposure_high_cve_count
      3. exposure_has_fix_available
      4. exposure_has_poc
      5. evidence_highest_severity
      6. evidence_latest_at
      7. evidence_count
    """
    def _key(s: WorkloadSummary):
        return (
            s.exposure_critical_cve_count,
            s.exposure_high_cve_count,
            int(s.exposure_has_fix_available),
            int(s.exposure_has_poc),
            _SEV_KEY.get(s.evidence_highest_severity or "", 0),
            s.evidence_latest_at or datetime.min,
            s.evidence_count,
        )

    return sorted(summaries, key=_key, reverse=True)


# ── summary builder ───────────────────────────────────────────────────────

def build_summary(wid: str, facts: List[FactPayload]) -> WorkloadSummary:
    cluster_id, namespace, workload_kind, workload_name = _parse_workload_id(wid)

    refs = _image_refs(facts)
    digests = _image_digests(facts)
    exps = lookup_exposure(cluster_id, refs, digests)
    image_exposure = [_exposure_to_schema(e) for e in exps]

    families = sorted({f.fact_family for f in facts})
    tags = sorted({t for f in facts for t in f.scenario_tags})
    latest_at = max((f.observed_at for f in facts), default=None)

    # aggregate
    exp_agg = aggregate_image_exposure(image_exposure)
    evi_agg = aggregate_runtime_evidence(facts)

    eligible = is_dashboard_eligible(workload_name, namespace, image_exposure)

    return WorkloadSummary(
        workload_id=wid,
        cluster_id=cluster_id,
        namespace=namespace,
        workload_kind=workload_kind,
        workload_name=workload_name,
        signal_count=len(facts),
        latest_signal_at=latest_at,
        highest_severity=_highest_severity(facts),
        active_fact_families=families,
        active_scenario_tags=tags,
        image_refs=refs,
        image_exposure=image_exposure,
        last_seen_at=latest_at,

        # exposure aggregate
        exposure_critical_cve_count=exp_agg.critical_cve_count,
        exposure_high_cve_count=exp_agg.high_cve_count,
        exposure_has_fix_available=exp_agg.has_fix_available,
        exposure_has_poc=exp_agg.has_poc,
        exposure_image_count=exp_agg.image_count,
        exposure_latest_scanned_at=exp_agg.latest_scanned_at,
        exposure_sources=exp_agg.sources,

        # evidence aggregate
        evidence_count=evi_agg.count,
        evidence_latest_at=evi_agg.latest_at,
        evidence_fact_families=evi_agg.fact_families,
        evidence_scenario_tags=evi_agg.scenario_tags,
        evidence_highest_severity=evi_agg.highest_severity,

        dashboard_eligible=eligible,
    )


def list_workloads(
    cluster_id: Optional[str] = None,
    store: Optional[FactStore] = None,
    eligible_only: bool = True,
) -> List[WorkloadSummary]:
    """
    workload 목록 반환.

    eligible_only=True (기본값) : dashboard_eligible==True 만 반환.
    eligible_only=False         : 전체 반환 (디버그/admin용).
    """
    store = store or get_store()
    all_wfm = store.get_all_workload_facts(cluster_id)

    summaries = [build_summary(wid, facts) for wid, facts in all_wfm.items()]

    if eligible_only:
        summaries = [s for s in summaries if s.dashboard_eligible]

    return sort_workload_summaries(summaries)


# ── detail ───────────────────────────────────────────────────────────────

def get_workload_detail(
    workload_id: str,
    store: Optional[FactStore] = None,
) -> Optional[WorkloadDetail]:
    store = store or get_store()

    facts = store.get_facts(workload_id, limit=_DETAIL_SIGNAL_LIMIT)
    if not facts:
        return None

    cluster_id, namespace, workload_kind, workload_name = _parse_workload_id(workload_id)

    refs = _image_refs(facts)
    digests = _image_digests(facts)
    exps = lookup_exposure(cluster_id, refs, digests)
    image_exposure = [_exposure_to_schema(e) for e in exps]

    related = _find_related_signals(workload_id, facts, store)

    actor_latest = facts[0].actor if facts else {}
    times = sorted(f.observed_at for f in facts)

    # aggregate
    exp_agg = aggregate_image_exposure(image_exposure)
    evi_agg = aggregate_runtime_evidence(facts)
    eligible = is_dashboard_eligible(workload_name, namespace, image_exposure)

    return WorkloadDetail(
        workload_id=workload_id,
        cluster_id=cluster_id,
        namespace=namespace,
        workload_kind=workload_kind,
        workload_name=workload_name,
        runtime_evidence=[_to_signal(f) for f in facts],
        image_refs=refs,
        image_exposure=image_exposure,
        related_signals=related,
        service_account=actor_latest.get("service_account"),
        node_name=actor_latest.get("node_name"),
        cloud_identity=actor_latest.get("cloud_identity"),
        last_seen_at=times[-1] if times else None,
        first_seen_at=times[0] if times else None,

        # exposure aggregate
        exposure_critical_cve_count=exp_agg.critical_cve_count,
        exposure_high_cve_count=exp_agg.high_cve_count,
        exposure_has_fix_available=exp_agg.has_fix_available,
        exposure_has_poc=exp_agg.has_poc,
        exposure_image_count=exp_agg.image_count,
        exposure_latest_scanned_at=exp_agg.latest_scanned_at,
        exposure_sources=exp_agg.sources,

        # evidence aggregate
        evidence_count=evi_agg.count,
        evidence_latest_at=evi_agg.latest_at,
        evidence_fact_families=evi_agg.fact_families,
        evidence_scenario_tags=evi_agg.scenario_tags,
        evidence_highest_severity=evi_agg.highest_severity,

        dashboard_eligible=eligible,
    )


def _find_related_signals(
    self_wid: str,
    self_facts: List[FactPayload],
    store: FactStore,
) -> List[RuntimeSignal]:
    self_tags = {t for f in self_facts for t in f.scenario_tags}
    if not self_tags:
        return []

    cluster_id = self_facts[0].cluster_id if self_facts else None
    all_wfm = store.get_all_workload_facts(cluster_id)

    related: List[RuntimeSignal] = []

    for wid, facts in all_wfm.items():
        if wid == self_wid:
            continue

        for f in facts:
            if self_tags & set(f.scenario_tags):
                related.append(_to_signal(f))
                if len(related) >= _RELATED_LIMIT:
                    return related

    return related