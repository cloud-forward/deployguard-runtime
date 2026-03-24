from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from runtime_api.schemas import (
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
    """
    🔥 핵심 수정 포인트
    summary → schema 매핑을 실제 필드에 맞게 변경
    """
    return ImageExposure(
        image_ref=exp.image_ref,
        image_digest=exp.image_digest,  # 추가

        critical_cve_count=exp.critical_cve_count,
        high_cve_count=exp.high_cve_count,

        fix_available=exp.fix_available,  # 추가
        poc_exists=exp.poc_exists,        # 추가

        sample_cves=exp.sample_cves,
    )


# ── summary ──────────────────────────────────────────────────────────────

def build_summary(wid: str, facts: List[FactPayload]) -> WorkloadSummary:
    cluster_id, namespace, workload_kind, workload_name = _parse_workload_id(wid)

    refs = _image_refs(facts)
    digests = _image_digests(facts)
    exps = lookup_exposure(cluster_id, refs, digests)

    families = sorted({f.fact_family for f in facts})
    tags = sorted({t for f in facts for t in f.scenario_tags})
    latest_at = max((f.observed_at for f in facts), default=None)

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
        image_exposure=[_exposure_to_schema(e) for e in exps],
        last_seen_at=latest_at,
    )


def list_workloads(
    cluster_id: Optional[str] = None,
    store: Optional[FactStore] = None,
) -> List[WorkloadSummary]:
    store = store or get_store()
    all_wfm = store.get_all_workload_facts(cluster_id)

    summaries = [build_summary(wid, facts) for wid, facts in all_wfm.items()]
    summaries.sort(key=lambda s: s.latest_signal_at or datetime.min, reverse=True)

    return summaries


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

    related = _find_related_signals(workload_id, facts, store)

    actor_latest = facts[0].actor if facts else {}
    times = sorted(f.observed_at for f in facts)

    return WorkloadDetail(
        workload_id=workload_id,
        cluster_id=cluster_id,
        namespace=namespace,
        workload_kind=workload_kind,
        workload_name=workload_name,
        runtime_evidence=[_to_signal(f) for f in facts],
        image_refs=refs,
        image_exposure=[_exposure_to_schema(e) for e in exps],
        related_signals=related,
        service_account=actor_latest.get("service_account"),
        node_name=actor_latest.get("node_name"),
        cloud_identity=actor_latest.get("cloud_identity"),
        last_seen_at=times[-1] if times else None,
        first_seen_at=times[0] if times else None,
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