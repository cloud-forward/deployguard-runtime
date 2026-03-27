"""
forwarder/live_sink.py

대시보드용 live payload 전송. http-post가 기본 모드.

지원 모드 (FORWARD_MODE 환경변수):
  - http-post   : FORWARD_URL HTTP POST (기본값)
  - stdout      : JSONL stdout 출력 (로컬 디버그)
  - file-jsonl  : OUTPUT_DIR/facts_<timestamp>.jsonl 저장

원칙:
  - 모든 EvidenceFact를 받는다 (suppression 통과한 것만 도달)
  - outbound payload에 raw 전체 원문 포함 금지
  - FORWARD_URL 미설정 시 stdout fallback + 경고
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from schemas.evidence_fact import EvidenceFact

log = logging.getLogger(__name__)

# http-post가 기본값 (runtime_api 중심 구조)
FORWARD_MODE = os.environ.get("FORWARD_MODE", "http-post").lower()
FORWARD_URL  = os.environ.get("FORWARD_URL", "")   # e.g. http://runtime-api:8080/runtime/facts
ENGINE_BASE_URL = os.environ.get("ENGINE_BASE_URL", "")
ENGINE_API_TOKEN = os.environ.get("ENGINE_API_TOKEN", "")
OUTPUT_DIR   = Path(os.environ.get("OUTPUT_DIR", "/tmp/evidence"))

# HTTP 전송 설정
_HTTP_TIMEOUT  = int(os.environ.get("FORWARD_HTTP_TIMEOUT", "10"))
_HTTP_BATCH_SIZE = int(os.environ.get("FORWARD_HTTP_BATCH_SIZE", "100"))


# ── 직렬화 ────────────────────────────────────────────────────────────

def serialize(fact: EvidenceFact) -> dict:
    """
    EvidenceFact → outbound payload dict.

    포함 금지: raw 전체 원문, final_risk, path_verdict, attack_path_state
    반드시 포함: source_native_event_id, dedup_key, success, response_code,
                raw_excerpt, raw_hash, actor, correlation_keys,
                fact_family, fact_type, scenario_tags
    """
    d = fact.model_dump(mode="json")
    for forbidden in ("raw", "final_risk", "path_verdict", "attack_path_state"):
        d.pop(forbidden, None)
    return d


# ── 공개 인터페이스 ───────────────────────────────────────────────────

def send(facts: Sequence[EvidenceFact]) -> None:
    """모드에 따라 EvidenceFact 전체를 live sink로 전송."""
    if not facts:
        return

    if FORWARD_MODE == "stdout":
        _send_stdout(facts)
    elif FORWARD_MODE == "file-jsonl":
        _send_file(facts)
    else:
        # 기본: http-post
        _send_http(facts)


def send_snapshot(
    envelope: Mapping[str, Any],
    *,
    allow_local_fallback: bool,
) -> None:
    """engine-s3 모드용 snapshot envelope 전송."""
    _send_engine_s3(envelope, allow_local_fallback=allow_local_fallback)


# ── 내부 전송 구현 ────────────────────────────────────────────────────

def _send_stdout(facts: Sequence[EvidenceFact]) -> None:
    for fact in facts:
        line = json.dumps(serialize(fact), ensure_ascii=False, default=str)
        print(line, flush=True)


def _send_file(facts: Sequence[EvidenceFact]) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ts       = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = OUTPUT_DIR / f"facts_{ts}.jsonl"
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            for fact in facts:
                line = json.dumps(serialize(fact), ensure_ascii=False, default=str)
                f.write(line + "\n")
        log.info("live_sink 저장: %s (%d건)", out_path, len(facts))
    except Exception as e:
        log.error("live_sink 파일 저장 실패: %s — stdout fallback", e)
        _send_stdout(facts)


def _write_snapshot_file(envelope: Mapping[str, Any]) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    snapshot_at = envelope.get("snapshot_at")
    if isinstance(snapshot_at, str):
        ts = snapshot_at.replace("-", "").replace(":", "").replace("+00:00", "Z")
    else:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = OUTPUT_DIR / f"snapshot_{ts}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(dict(envelope), f, indent=2, ensure_ascii=False, default=str)
    log.info("engine-s3 snapshot 저장: %s (%d건)", out_path, envelope.get("fact_count", 0))


def _engine_headers(*, include_json: bool) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {ENGINE_API_TOKEN}",
        "X-Scanner-Source": "deployguard-runtime-scanner",
    }
    if include_json:
        headers["Content-Type"] = "application/json"
    return headers


def _engine_endpoint(path: str) -> str:
    return f"{ENGINE_BASE_URL.rstrip('/')}{path}"


def _request_engine_upload_url() -> dict[str, Any]:
    req = urllib.request.Request(
        _engine_endpoint("/api/v1/runtime/upload-url"),
        data=b"",
        method="POST",
        headers=_engine_headers(include_json=False),
    )
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _put_snapshot_to_presigned_url(upload_url: str, envelope: Mapping[str, Any]) -> None:
    payload = json.dumps(dict(envelope), ensure_ascii=False, default=str).encode("utf-8")
    req = urllib.request.Request(
        upload_url,
        data=payload,
        method="PUT",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT):
        return


def _complete_engine_snapshot(s3_key: str, snapshot_at: str, fact_count: int) -> None:
    payload = json.dumps(
        {
            "s3_key": s3_key,
            "snapshot_at": snapshot_at,
            "fact_count": fact_count,
        },
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    req = urllib.request.Request(
        _engine_endpoint("/api/v1/runtime/complete"),
        data=payload,
        method="POST",
        headers=_engine_headers(include_json=True),
    )
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT):
        return


def _send_engine_s3(
    envelope: Mapping[str, Any],
    *,
    allow_local_fallback: bool,
) -> None:
    fact_count = int(envelope.get("fact_count", 0) or 0)
    missing = [
        name for name, value in [
            ("CLUSTER_ID", envelope.get("cluster_id")),
            ("ENGINE_BASE_URL", ENGINE_BASE_URL),
            ("ENGINE_API_TOKEN", ENGINE_API_TOKEN),
        ]
        if not value
    ]
    if missing:
        log.error("engine-s3 전송 설정 누락: %s", ", ".join(missing))
        if allow_local_fallback:
            _write_snapshot_file(envelope)
        return

    try:
        upload_meta = _request_engine_upload_url()
        upload_url = upload_meta["upload_url"]
        s3_key = upload_meta["s3_key"]
    except Exception as e:
        log.error("engine-s3 upload-url 요청 실패: %s", e)
        if allow_local_fallback:
            _write_snapshot_file(envelope)
        return

    try:
        _put_snapshot_to_presigned_url(upload_url, envelope)
        log.info("engine-s3 snapshot PUT 성공: s3_key=%s fact_count=%d", s3_key, fact_count)
    except Exception as e:
        log.error("engine-s3 snapshot PUT 실패: %s", e)
        if allow_local_fallback:
            _write_snapshot_file(envelope)
        return

    try:
        snapshot_at = str(envelope["snapshot_at"])
        _complete_engine_snapshot(s3_key, snapshot_at, fact_count)
        log.info("engine-s3 snapshot complete 성공: s3_key=%s fact_count=%d", s3_key, fact_count)
    except Exception as e:
        log.error("engine-s3 snapshot complete 실패: %s", e)


def _send_http(facts: Sequence[EvidenceFact]) -> None:
    """
    HTTP POST → runtime_api /runtime/facts.
    FORWARD_URL 미설정 시 stdout fallback.
    _HTTP_BATCH_SIZE 단위로 분할 전송.
    """
    if not FORWARD_URL:
        log.warning(
            "FORWARD_URL 미설정 — stdout fallback. "
            "운영 환경에서는 FORWARD_URL=http://runtime-api:8080/runtime/facts 설정 필요"
        )
        _send_stdout(facts)
        return

    serialized = [serialize(f) for f in facts]
    total      = len(serialized)
    sent       = 0

    for i in range(0, total, _HTTP_BATCH_SIZE):
        batch = serialized[i : i + _HTTP_BATCH_SIZE]
        try:
            payload = json.dumps(batch, ensure_ascii=False, default=str).encode("utf-8")
            req = urllib.request.Request(
                FORWARD_URL,
                data=payload,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "X-Scanner-Source": "deployguard-runtime-scanner",
                },
            )
            with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
                log.info(
                    "live_sink HTTP 전송 성공: status=%s batch=%d/%d",
                    resp.status, i // _HTTP_BATCH_SIZE + 1,
                    (total + _HTTP_BATCH_SIZE - 1) // _HTTP_BATCH_SIZE,
                )
            sent += len(batch)
        except Exception as e:
            log.error(
                "live_sink HTTP 전송 실패 (batch %d): %s — file-jsonl fallback",
                i // _HTTP_BATCH_SIZE + 1, e,
            )
            _send_file(facts[i : i + _HTTP_BATCH_SIZE])  # type: ignore[index]

    if sent:
        log.info("live_sink HTTP 전송 완료: %d/%d건", sent, total)
