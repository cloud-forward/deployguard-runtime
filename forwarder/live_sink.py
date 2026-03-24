"""
forwarder/live_sink.py

대시보드용 live payload 전송.
기존 forwarder/forward.py 의 직렬화·출력 로직을 이전.

지원 모드 (FORWARD_MODE 환경변수):
  - stdout      : JSONL stdout 출력
  - file-jsonl  : OUTPUT_DIR/facts_<timestamp>.jsonl 저장 (기본값)
  - http-post   : FORWARD_URL HTTP POST

원칙:
  - 모든 EvidenceFact를 받는다 (DB 저장 여부와 무관)
  - outbound payload에 raw 전체 원문 포함 금지
  - DB 미저장 fact도 반드시 이 경로로 내보낸다
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

FORWARD_MODE = os.environ.get("FORWARD_MODE", "file-jsonl").lower()
FORWARD_URL  = os.environ.get("FORWARD_URL", "")
OUTPUT_DIR   = Path(os.environ.get("OUTPUT_DIR", "/tmp/evidence"))


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
    elif FORWARD_MODE == "http-post":
        _send_http(facts)
    else:
        _send_file(facts)


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


def _send_http(facts: Sequence[EvidenceFact]) -> None:
    """HTTP POST. FORWARD_URL 미설정 시 file-jsonl fallback."""
    if not FORWARD_URL:
        log.warning("FORWARD_URL 미설정 — file-jsonl fallback")
        _send_file(facts)
        return

    try:
        payload = json.dumps(
            [serialize(f) for f in facts],
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")

        req = urllib.request.Request(
            FORWARD_URL,
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Scanner-Source": "deployguard-runtime-scanner",
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            log.info("live_sink HTTP 전송 성공: %s (%d건)", resp.status, len(facts))

    except Exception as e:
        log.error("live_sink HTTP 전송 실패: %s — file-jsonl fallback", e)
        _send_file(facts)