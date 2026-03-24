"""
forwarder/dispatcher.py

Evidence 분기 진입점. DB 경로 제거 — live_sink(HTTP POST) 전용.

흐름:
  dispatch(evidences) → live_sink.send()

원칙:
  - 비즈니스 로직은 두지 않는다.
  - scanner는 fact producer 역할만. DB 저장은 runtime_api 담당.
  - engine_projector / db_writer는 legacy로 보존하되 호출하지 않는다.
"""

from __future__ import annotations

import logging
from typing import Sequence

from schemas.evidence_fact import EvidenceFact
from forwarder.live_sink import send

log = logging.getLogger(__name__)


def dispatch(evidences: Sequence[EvidenceFact]) -> None:
    """
    Evidence → live_sink(HTTP POST / file-jsonl / stdout) 전송.
    DB 저장은 runtime_api가 담당하므로 여기서는 호출하지 않는다.
    """
    if not evidences:
        return

    log.info("dispatch: %d개 EvidenceFact → live_sink", len(evidences))
    send(list(evidences))
