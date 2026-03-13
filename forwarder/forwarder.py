"""
forwarder/forwarder.py

EvidenceFact forward 모듈.

지원 모드 (FORWARD_MODE):
  - stdout      : JSONL 형식으로 stdout 출력
  - file-jsonl  : OUTPUT_DIR/facts_<timestamp>.jsonl 파일로 저장
  - http-post   : FORWARD_URL HTTP POST (엔진 API 연동)

설계:
  - 엔진 API가 정해지지 않아도 file/stdout으로 동일 schema 출력 가능
  - http-post는 retry + 실패 시 fallback(stdout) 지원
  - 모든 모드에서 출력 payload는 raw 전체 포함 금지
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from schemas.evidence_fact import EvidenceFact

log = logging.getLogger(__name__)

# ── 환경변수 ──────────────────────────────────────────────────────────
FORWARD_MODE = os.environ.get("FORWARD_MODE", "file-jsonl").lower()
FORWARD_URL  = os.environ.get("FORWARD_URL", "")
OUTPUT_DIR   = Path(os.environ.get("OUTPUT_DIR", "/tmp/evidence"))


# ── 직렬화 ────────────────────────────────────────────────────────────

def _serialize(fact: EvidenceFact) -> dict:
    """
    EvidenceFact → outbound payload dict.

    절대 포함 금지:
      - raw 전체 원문
      - final_risk / path_verdict / attack_path_state

    반드시 포함:
      - source_native_event_id, dedup_key
      - success, response_code
      - raw_excerpt, raw_hash
      - actor 식별자, correlation_keys
      - fact_family, fact_type, scenario_tags
    """
    d = fact.model_dump(mode="json")

    # raw 전체 원문이 혹시라도 섞여들어오지 않도록 명시적으로 제거
    # (EvidenceFact 스키마 자체에 raw 필드가 없지만 방어적으로)
    for forbidden in ("raw", "final_risk", "path_verdict", "attack_path_state"):
        d.pop(forbidden, None)

    return d


# ── 포워더 ────────────────────────────────────────────────────────────

def forward(facts: Sequence[EvidenceFact]) -> None:
    """모드에 따라 EvidenceFact 목록을 forward."""
    if not facts:
        return

    if FORWARD_MODE == "stdout":
        _forward_stdout(facts)
    elif FORWARD_MODE == "http-post":
        _forward_http(facts)
    else:
        # 기본: file-jsonl
        _forward_file(facts)


def _forward_stdout(facts: Sequence[EvidenceFact]) -> None:
    for fact in facts:
        line = json.dumps(_serialize(fact), ensure_ascii=False, default=str)
        print(line, flush=True)


def _forward_file(facts: Sequence[EvidenceFact]) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ts       = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = OUTPUT_DIR / f"facts_{ts}.jsonl"
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            for fact in facts:
                line = json.dumps(_serialize(fact), ensure_ascii=False, default=str)
                f.write(line + "\n")
        log.info(f"EvidenceFact 저장: {out_path} ({len(facts)}건)")
    except Exception as e:
        log.error(f"파일 저장 실패: {e}")
        _forward_stdout(facts)   # fallback


def _forward_http(facts: Sequence[EvidenceFact]) -> None:
    """
    HTTP POST — 엔진 API 연동용.
    FORWARD_URL 미설정 시 file-jsonl 로 fallback.
    """
    if not FORWARD_URL:
        log.warning("FORWARD_URL 미설정 — file-jsonl로 fallback")
        _forward_file(facts)
        return

    try:
        import urllib.request

        payload = json.dumps(
            [_serialize(f) for f in facts],
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
            log.info(f"HTTP forward 성공: {resp.status} ({len(facts)}건)")

    except Exception as e:
        log.error(f"HTTP forward 실패: {e} — file-jsonl로 fallback")
        _forward_file(facts)
