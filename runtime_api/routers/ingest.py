"""
runtime_api/routers/ingest.py

POST /runtime/facts
scanner → runtime_api ingest endpoint.
"""

from __future__ import annotations

import logging
from typing import List

from fastapi import APIRouter, Request

from runtime_api.schemas import FactPayload, IngestResponse
from runtime_api.store import get_store

log = logging.getLogger(__name__)

router = APIRouter(prefix="/runtime", tags=["ingest"])


@router.post(
    "/facts",
    response_model=IngestResponse,
    summary="Scanner fact ingest",
    description=(
        "runtime scanner가 생성한 EvidenceFact 배열을 수신한다. "
        "dedup_key 기준 중복 제거. raw 전체 원문은 포함하지 않는다."
    ),
)
async def ingest_facts(
    request: Request,
    facts: List[FactPayload],
) -> IngestResponse:
    store = get_store()
    accepted, duplicate = store.add(facts)
    total = len(facts)

    log.info(
        "ingest: total=%d accepted=%d duplicate=%d source=%s",
        total, accepted, duplicate,
        request.headers.get("X-Scanner-Source", "unknown"),
    )

    return IngestResponse(accepted=accepted, duplicate=duplicate, total=total)
