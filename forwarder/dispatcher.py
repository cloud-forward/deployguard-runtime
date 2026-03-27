"""
forwarder/dispatcher.py

Evidence 분기 진입점. Engine S3 Snapshot 전용.

흐름:
  dispatch(evidences) → live_sink.send()

원칙:
  - facts가 비어 있어도 반드시 send() 호출 (empty cycle liveness 확인)
  - 비즈니스 로직 없음. fact producer 역할만.
"""

from __future__ import annotations

import logging
from typing import Sequence

from schemas.evidence_fact import EvidenceFact
from forwarder.live_sink import send

log = logging.getLogger(__name__)


def dispatch(evidences: Sequence[EvidenceFact]) -> None:
    """
    Evidence → Engine S3 Snapshot 전송.
    empty cycle(evidences=[])도 liveness 목적으로 반드시 send() 호출.
    """
    log.info("dispatch: %d개 EvidenceFact → Engine S3", len(evidences))
    send(list(evidences))
