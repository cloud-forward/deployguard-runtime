"""
runtime_api/service.py

summary / detail 집계 서비스.

원칙:
  - raw FactPayload를 dashboard 모델로 변환한다.
  - SBOM/CVE join은 placeholder 인터페이스로 분리한다.
  - 최종 판정 표현 금지. severity_hint / scenario_tags 기반 집계만.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Optional

from runtime_api.schemas import (
    FactPayload,
    ImageExposure,
    RuntimeSignal,
    WorkloadDetail,
    WorkloadSummary,
)
from runtime_api.store import FactStore, get_store, _make_workload_id

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}

_DETAIL_SIGNAL_LIMIT = int(os.environ.get("DETAIL_SIGNAL_LIMIT", "50"))
_RELATED_SIGNAL_LIMIT = int(os.environ.get("RELATED_SIGNAL_LIMIT", "20"))


# ── SBOM join placeholder ─────────────────────────────────────────────

class SbomClient:
    """
    SBOM/CVE join 인터페이스 placeholder.
    실제 구현 시 이 클래스를 교체하거나 환경변수 SBOM_API_URL로 연결.
    """
    _sbom_api_url = os.environ.get("SBOM_API_URL", "")

    def get_exposure(self, image_ref: str) -> ImageExposure:
        """
        image_ref 기준 노출 정보 조회.
        SBOM_API_URL 미설정 시 빈 placeholder 반환.
        """
        if not self._sbom_api_url or not image_ref:
            return ImageExposure(image_ref=image_ref)

        try:
            import urllib.request, json
            url = f"{self._sbom_api_url}/exposure?image_ref={image_ref}"
            with urllib.request.urlopen(url, timeout=3) as resp:
                data = json.loads(resp.read())
            return ImageExposure(
                image_ref=image_ref,
                critical_cve_count=data.get("critical", 0),
                high_cve_count=data.get("high", 0),
                sbom_available=data.get("sbom_available", False),
                sbom_source=data.get("source"),
                last_scanned_at=data.get("last_scanned_at"),
                sample_cves=data.get("sample_cves", [])[:5],
            )
        except Exception:
            return ImageExposure(image_ref=image_ref)


_sbom_client = SbomClient()


# ── 변환 헬퍼 ─────────────────────────────────────────────────────────

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


def _highest_severity(facts: list[FactPayload]) -> Optional[str]:
    best     = None
    best_val = 0
    for f in facts:
        val = _SEVERITY_ORDER.get(f.severity_hint or "", 0)
        if val > best_val:
            best_val = val
            best     = f.severity_hint
    return best


def _image_refs(facts: list[FactPayload]) -> list[str]:
    seen: set[str] = set()
    refs: list[str] = []
    for f in facts:
        ref = f.actor.get("image_ref")
        if ref and ref not in seen:
            seen.add(ref)
            refs.append(ref)
    return refs


def _parse_workload_id(wid: str) -> tuple[str, str, str, str]:
    """cluster_id:namespace:workload_kind:workload_name"""
    parts = wid.split(":", 3)
    if len(parts) == 4:
        return parts[0], parts[1], parts[2], parts[3]
    return wid, "", "Pod", wid


# ── Summary 서비스 ────────────────────────────────────────────────────

def build_summary(
    wid:   str,
    facts: list[FactPayload],
) -> WorkloadSummary:
    cluster_id, namespace, workload_kind, workload_name = _parse_workload_id(wid)

    families = sorted({f.fact_family for f in facts})
    tags     = sorted({t for f in facts for t in f.scenario_tags})
    refs     = _image_refs(facts)

    latest_at = max((f.observed_at for f in facts), default=None)

    image_exposure = [
        _sbom_client.get_exposure(ref) for ref in refs
    ]

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
    )


def list_workloads(
    cluster_id: Optional[str] = None,
    store:      Optional[FactStore] = None,
) -> list[WorkloadSummary]:
    store   = store or get_store()
    all_wfm = store.get_all_workload_facts(cluster_id)
    summaries = [build_summary(wid, facts) for wid, facts in all_wfm.items()]
    # 최신 신호 순 정렬
    summaries.sort(key=lambda s: s.latest_signal_at or datetime.min, reverse=True)
    return summaries


# ── Detail 서비스 ─────────────────────────────────────────────────────

def get_workload_detail(
    workload_id: str,
    store:       Optional[FactStore] = None,
) -> Optional[WorkloadDetail]:
    store = store or get_store()
    facts = store.get_facts(workload_id, limit=_DETAIL_SIGNAL_LIMIT)
    if not facts:
        return None

    cluster_id, namespace, workload_kind, workload_name = _parse_workload_id(workload_id)
    refs           = _image_refs(facts)
    image_exposure = [_sbom_client.get_exposure(ref) for ref in refs]

    # 관련 신호: 같은 cluster의 동일 scenario_tag를 가진 다른 워크로드 신호
    related = _find_related_signals(workload_id, facts, store)

    actor_latest = facts[0].actor if facts else {}
    times        = sorted(f.observed_at for f in facts)

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
    )


def _find_related_signals(
    self_wid: str,
    self_facts: list[FactPayload],
    store: FactStore,
) -> list[RuntimeSignal]:
    """
    같은 cluster에서 self_facts와 scenario_tag가 겹치는 다른 워크로드의 최신 신호.
    """
    self_tags = {t for f in self_facts for t in f.scenario_tags}
    if not self_tags:
        return []

    cluster_id = self_facts[0].cluster_id if self_facts else None
    all_wfm    = store.get_all_workload_facts(cluster_id)

    related: list[RuntimeSignal] = []
    for wid, facts in all_wfm.items():
        if wid == self_wid:
            continue
        for f in facts:
            if self_tags & set(f.scenario_tags):
                related.append(_to_signal(f))
                if len(related) >= _RELATED_SIGNAL_LIMIT:
                    return related
    return related
