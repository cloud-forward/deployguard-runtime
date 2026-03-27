"""
forwarder/live_sink.py

Engine S3 Snapshot 전송 전용.

동작 순서 (Non-empty / Empty 공통):
  1. Envelope JSON 생성
  2. POST {ENGINE_BASE_URL}/api/v1/runtime/upload-url  → presigned URL + s3_key 수신
  3. PUT {presigned_url}                               → S3 직접 업로드
  4. POST {ENGINE_BASE_URL}/api/v1/runtime/complete    → Engine DB 기록

원칙:
  - outbound payload에 raw 전체 원문 포함 금지
  - empty cycle(facts=[])도 업로드 (liveness 확인용)
  - complete 실패 시 재업로드하지 않음 (중복 방지)
  - local fallback(file-jsonl)은 non-empty cycle의 S3 PUT 실패 시에만 허용
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from schemas.evidence_fact import EvidenceFact

log = logging.getLogger(__name__)

ENGINE_BASE_URL  = os.environ.get("ENGINE_BASE_URL", "").rstrip("/")
ENGINE_API_TOKEN = os.environ.get("ENGINE_API_TOKEN", "")
SCANNER_VERSION  = os.environ.get("SCANNER_VERSION", "unknown")
CLUSTER_ID       = os.environ.get("CLUSTER_ID", "")
OUTPUT_DIR       = Path(os.environ.get("OUTPUT_DIR", "/tmp/evidence"))

_HTTP_TIMEOUT = int(os.environ.get("FORWARD_HTTP_TIMEOUT", "30"))


# ── 직렬화 ────────────────────────────────────────────────────────────

def serialize(fact: EvidenceFact) -> dict:
    """
    EvidenceFact → outbound payload dict.
    포함 금지: raw 전체 원문, final_risk, path_verdict, attack_path_state
    """
    d = fact.model_dump(mode="json")
    for forbidden in ("raw", "final_risk", "path_verdict", "attack_path_state"):
        d.pop(forbidden, None)
    return d


# ── Envelope 생성 ─────────────────────────────────────────────────────

def _build_envelope(facts: Sequence[EvidenceFact]) -> dict:
    """
    Snapshot Envelope 구조:
      schema_version, scanner_version, cluster_id,
      snapshot_at, last_seen_at, fact_count, facts
    """
    now = datetime.now(timezone.utc)

    if facts:
        snapshot_at  = max(f.collected_at for f in facts)
        last_seen_at = max(f.observed_at  for f in facts)
    else:
        snapshot_at  = now
        last_seen_at = None

    return {
        "schema_version":  "1.0",
        "scanner_version": SCANNER_VERSION,
        "cluster_id":      CLUSTER_ID,
        "snapshot_at":     snapshot_at.isoformat(),
        "last_seen_at":    last_seen_at.isoformat() if last_seen_at else None,
        "fact_count":      len(facts),
        "facts":           [serialize(f) for f in facts],
    }


# ── Engine API 헬퍼 ───────────────────────────────────────────────────

def _engine_headers() -> dict:
    return {
        "Content-Type":  "application/json",
        "Authorization": f"Bearer {ENGINE_API_TOKEN}",
    }


def _post_json(url: str, body: dict) -> dict:
    payload = json.dumps(body, ensure_ascii=False, default=str).encode("utf-8")
    req = urllib.request.Request(url, data=payload, method="POST", headers=_engine_headers())
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _request_upload_url() -> tuple[str, str]:
    """
    POST /api/v1/runtime/upload-url
    반환: (upload_url, s3_key)
    """
    url  = f"{ENGINE_BASE_URL}/api/v1/runtime/upload-url"
    data = _post_json(url, {})
    return data["upload_url"], data["s3_key"]


def _upload_to_s3(upload_url: str, envelope: dict) -> None:
    """PUT presigned URL → S3 직접 업로드."""
    payload = json.dumps(envelope, ensure_ascii=False, default=str).encode("utf-8")
    req = urllib.request.Request(
        upload_url,
        data=payload,
        method="PUT",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
        log.info("S3 업로드 성공: status=%s", resp.status)


def _notify_complete(s3_key: str, snapshot_at: str, fact_count: int) -> None:
    """POST /api/v1/runtime/complete → Engine DB 기록."""
    url = f"{ENGINE_BASE_URL}/api/v1/runtime/complete"
    _post_json(url, {
        "s3_key":      s3_key,
        "snapshot_at": snapshot_at,
        "fact_count":  fact_count,
    })
    log.info("Engine complete 통지 성공: s3_key=%s fact_count=%d", s3_key, fact_count)


# ── local fallback (non-empty S3 실패 시에만) ─────────────────────────

def _fallback_file(facts: Sequence[EvidenceFact], envelope: dict) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ts       = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = OUTPUT_DIR / f"snapshot_fallback_{ts}.json"
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(envelope, f, ensure_ascii=False, default=str)
        log.warning("local fallback 저장 완료: %s (%d건)", out_path, len(facts))
    except Exception as e:
        log.error("local fallback 저장도 실패: %s", e)
        for fact in facts:
            print(json.dumps(serialize(fact), ensure_ascii=False, default=str), flush=True)


# ── 공개 인터페이스 ───────────────────────────────────────────────────

def send(facts: Sequence[EvidenceFact]) -> None:
    """
    Engine S3 Snapshot 전송.
    facts가 비어 있어도 liveness 목적으로 업로드 수행.
    """
    if not ENGINE_BASE_URL:
        log.error("ENGINE_BASE_URL 미설정 — 전송 불가")
        return
    if not ENGINE_API_TOKEN:
        log.error("ENGINE_API_TOKEN 미설정 — 전송 불가")
        return

    envelope    = _build_envelope(facts)
    snapshot_at = envelope["snapshot_at"]
    fact_count  = envelope["fact_count"]
    is_empty    = fact_count == 0

    # 1. upload-url 요청
    try:
        upload_url, s3_key = _request_upload_url()
        log.info("upload-url 수신: s3_key=%s", s3_key)
    except Exception as e:
        log.error("upload-url 요청 실패: %s", e)
        if not is_empty:
            _fallback_file(facts, envelope)
        return

    # 2. S3 PUT
    try:
        _upload_to_s3(upload_url, envelope)
    except Exception as e:
        log.error("S3 PUT 실패: %s", e)
        if not is_empty:
            _fallback_file(facts, envelope)
        return

    # 3. complete 통지 (실패해도 재업로드 없음)
    try:
        _notify_complete(s3_key, snapshot_at, fact_count)
    except Exception as e:
        log.error("complete 통지 실패 (재업로드 없음): %s", e)
