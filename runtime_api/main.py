"""
runtime_api/main.py

DeployGuard Runtime API.

역할:
  - scanner fact ingest (POST /runtime/facts)
  - workload summary / detail (GET /runtime/workloads)
  - SBOM/CVE join placeholder
  - dashboard 응답

실행:
  uvicorn runtime_api.main:app --host 0.0.0.0 --port 8080
"""

from __future__ import annotations

import asyncio
import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from runtime_api.routers.ingest    import router as ingest_router
from runtime_api.routers.workloads import router as workloads_router
from runtime_api.store import get_store

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger(__name__)

_PURGE_INTERVAL = int(os.environ.get("STORE_PURGE_INTERVAL_SEC", "3600"))

app = FastAPI(
    title="DeployGuard Runtime API",
    description=(
        "runtime scanner EvidenceFact ingest + workload summary/detail API.\n\n"
        "scanner → POST /runtime/facts → runtime_api → dashboard"
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# CORS — dashboard origin 허용
_CORS_ORIGINS = os.environ.get("CORS_ALLOW_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ingest_router)
app.include_router(workloads_router)


@app.get("/healthz", tags=["health"])
async def healthz() -> dict:
    return {"status": "ok"}


@app.get("/readyz", tags=["health"])
async def readyz() -> dict:
    store = get_store()
    return {"status": "ok", "workload_count": len(store.get_workload_ids())}


# ── 백그라운드 TTL 정리 ───────────────────────────────────────────────

async def _purge_loop() -> None:
    while True:
        await asyncio.sleep(_PURGE_INTERVAL)
        try:
            removed = get_store().purge_expired()
            if removed:
                log.info("TTL purge: %d건 제거", removed)
        except Exception as e:
            log.error("purge 실패: %s", e)


@app.on_event("startup")
async def _startup() -> None:
    asyncio.create_task(_purge_loop())
    log.info("DeployGuard Runtime API 시작")


@app.on_event("shutdown")
async def _shutdown() -> None:
    log.info("DeployGuard Runtime API 종료")
