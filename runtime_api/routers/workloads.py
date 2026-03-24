"""
runtime_api/routers/workloads.py

GET /runtime/workloads         → 워크로드 목록 + summary
GET /runtime/workloads/{id}    → 워크로드 상세 + runtime_evidence + image_exposure
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
    summary="워크로드 runtime 신호 목록",
    description=(
        "cluster_id 기준 필터링 가능. "
        "각 워크로드의 runtime_evidence 집계 + image_exposure placeholder 포함."
    ),
)
async def list_workloads_endpoint(
    cluster_id: Optional[str] = Query(None, description="cluster_id 필터"),
    limit:      int           = Query(100, ge=1, le=1000, description="최대 반환 건수"),
) -> WorkloadListResponse:
    summaries = list_workloads(cluster_id=cluster_id)
    return WorkloadListResponse(total=len(summaries), workloads=summaries[:limit])


@router.get(
    "/workloads/{workload_id:path}",
    response_model=WorkloadDetail,
    summary="워크로드 상세 (runtime_evidence + image_exposure + related_signals)",
    description=(
        "workload_id = cluster_id:namespace:workload_kind:workload_name. "
        "runtime_evidence는 최근 신호 목록. "
        "image_exposure는 SBOM API join (placeholder). "
        "related_signals는 동일 scenario_tag 기준 cluster-wide 연관 신호."
    ),
)
async def get_workload_detail_endpoint(workload_id: str) -> WorkloadDetail:
    wid    = unquote(workload_id)
    detail = get_workload_detail(wid)
    if detail is None:
        raise HTTPException(status_code=404, detail=f"workload_id '{wid}' not found")
    return detail
