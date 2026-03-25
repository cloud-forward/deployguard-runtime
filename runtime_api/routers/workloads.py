"""
runtime_api/routers/workloads.py

GET /runtime/workloads         → curated workload list (dashboard_eligible 기본 필터)
GET /runtime/workloads/{id}    → workload 상세 + runtime_evidence + image_exposure

변경 사항:
  - eligible_only 쿼리 파라미터 추가 (기본값 true)
    true  : dashboard_eligible==True 인 workload만 반환 (운영 뷰)
    false : 전체 반환 (디버그/admin 뷰)
"""

from __future__ import annotations

import logging
from typing import Optional
from urllib.parse import unquote

from fastapi import APIRouter, HTTPException, Query

from runtime_api.schemas import WorkloadDetail, WorkloadListResponse, WorkloadSummary
from runtime_api.service import get_workload_detail, list_workloads

log = logging.getLogger(__name__)

router = APIRouter(prefix="/runtime", tags=["workloads"])


@router.get(
    "/workloads",
    response_model=WorkloadListResponse,
    summary="워크로드 runtime 신호 목록 (curated)",
    description=(
        "cluster_id 기준 필터링 가능. "
        "eligible_only=true(기본값)이면 dashboard_eligible 워크로드만 반환. "
        "unknown/self-noise/deployguard noise는 기본 제외. "
        "정렬 기준: exposure CVE 심각도 → runtime 징후 최신순."
    ),
)
async def list_workloads_endpoint(
    cluster_id:    Optional[str] = Query(None, description="cluster_id 필터"),
    limit:         int           = Query(100, ge=1, le=1000, description="최대 반환 건수"),
    eligible_only: bool          = Query(
        True,
        description=(
            "true(기본값): dashboard_eligible 워크로드만 반환. "
            "false: 전체 반환 (디버그/admin용)."
        ),
    ),
) -> WorkloadListResponse:
    summaries = list_workloads(cluster_id=cluster_id, eligible_only=eligible_only)
    return WorkloadListResponse(total=len(summaries), workloads=summaries[:limit])


@router.get(
    "/workloads/{workload_id:path}",
    response_model=WorkloadDetail,
    summary="워크로드 상세 (runtime_evidence + image_exposure + related_signals)",
    description=(
        "workload_id = cluster_id:namespace:workload_kind:workload_name. "
        "runtime_evidence는 최근 신호 목록. "
        "image_exposure는 SBOM API join. "
        "related_signals는 동일 scenario_tag 기준 cluster-wide 연관 신호. "
        "aggregate exposure/evidence 필드 포함 — 왜 이 workload가 위험한지 설명 가능."
    ),
)
async def get_workload_detail_endpoint(workload_id: str) -> WorkloadDetail:
    wid    = unquote(workload_id)
    detail = get_workload_detail(wid)
    if detail is None:
        raise HTTPException(status_code=404, detail=f"workload_id '{wid}' not found")
    return detail