"""
forwarder/dispatcher.py

Evidence 분기 진입점. 얇게 유지한다.

흐름:
  dispatch(evidences)
    ├─ engine_projector.project()  → DB row 변환 (None이면 DB skip)
    ├─ db_writer.write()           → runtime_events INSERT
    └─ live_sink.send()            → live payload 전송 (전체)

원칙:
  - 비즈니스 로직은 두지 않는다
  - DB 저장 실패가 live 경로를 막지 않는다
  - cluster_id 미설정 시 db_writer 내부에서 skip 처리
"""

from __future__ import annotations

import logging
from typing import Sequence

from schemas.evidence_fact import EvidenceFact
from forwarder.engine_projector import project
from forwarder.db_writer        import write
from forwarder.live_sink        import send

log = logging.getLogger(__name__)


def dispatch(evidences: Sequence[EvidenceFact]) -> None:
    """
    Evidence 분기 진입점.

    1) DB 경로  : project() → None이 아닌 row만 write()
    2) live 경로: 전체 evidences → send()
    """
    if not evidences:
        return

    # ── 1) DB 저장 경로 ───────────────────────────────────────────────
    db_rows = []
    for ev in evidences:
        row = project(ev)
        if row is not None:
            db_rows.append(row)

    log.info(
        "dispatch: 전체=%d  DB 대상=%d  live=%d",
        len(evidences), len(db_rows), len(evidences),
    )

    write(db_rows)

    # ── 2) live payload 경로 (전체, DB 저장 여부 무관) ────────────────
    send(list(evidences))