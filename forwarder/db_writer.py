"""
forwarder/db_writer.py

PostgreSQL 연결 및 runtime_events INSERT.

규칙:
  - cluster_id 빈 문자열이면 DB 저장 skip + warning (live sink는 영향 없음)
  - event_id UNIQUE 충돌 → ON CONFLICT DO NOTHING
  - DB 연결 실패 → 예외 잡아 로그만 남김, live 경로 계속 진행
  - metadata는 psycopg2.extras.Json으로 감싸서 JSONB로 insert
  - 연결 정보는 환경변수 우선:
      DB_HOST / DB_PORT / DB_NAME / DB_USER / DB_PASS

runtime_events 스키마 (변경 금지):
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid()
  cluster_id  UUID NOT NULL REFERENCES clusters(id)
  event_id    VARCHAR(255) NOT NULL UNIQUE
  event_type  VARCHAR(100) NOT NULL
  pod_id      VARCHAR(500)
  timestamp   TIMESTAMPTZ NOT NULL
  metadata    JSONB NOT NULL DEFAULT '{}'
  source      VARCHAR(50) NOT NULL DEFAULT 'ebpf'
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
"""

from __future__ import annotations

import logging
import os
from typing import Sequence

import psycopg2
import psycopg2.extras
from psycopg2.extras import execute_values, Json

log = logging.getLogger(__name__)

_DB_HOST = os.environ.get("DB_HOST", "localhost")
_DB_PORT = int(os.environ.get("DB_PORT", "5432"))
_DB_NAME = os.environ.get("DB_NAME", "deployguard")
_DB_USER = os.environ.get("DB_USER", "deploy_guard")
_DB_PASS = os.environ.get("DB_PASS", "cloudforward1!")

_INSERT_SQL = """
    INSERT INTO runtime_events
        (cluster_id, event_id, event_type, pod_id, timestamp, metadata, source)
    VALUES %s
    ON CONFLICT (event_id) DO NOTHING
"""


def _connect() -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=_DB_HOST,
        port=_DB_PORT,
        dbname=_DB_NAME,
        user=_DB_USER,
        password=_DB_PASS,
        connect_timeout=5,
    )


def write(rows: Sequence[dict]) -> None:
    """
    runtime_events에 rows를 일괄 INSERT.

    rows 각 항목은 engine_projector.project() 반환 dict.
    cluster_id 미설정(빈 문자열) row는 제거 후 진행.
    metadata는 Json()으로 감싸 JSONB 타입으로 insert.
    DB 연결 실패 시 예외를 잡아 로그만 남기고 live 경로는 계속 진행.
    """
    if not rows:
        return

    # cluster_id 없는 row 걸러냄
    valid_rows = [r for r in rows if r.get("cluster_id")]
    skipped = len(rows) - len(valid_rows)
    if skipped:
        log.warning(
            "cluster_id 미설정으로 DB 저장 skip: %d건 (live sink는 정상 동작)", skipped
        )
    if not valid_rows:
        return

    values = [
        (
            r["cluster_id"],
            r["event_id"],
            r["event_type"],
            r["pod_id"],
            r["timestamp"],
            Json(r["metadata"]),
            r["source"],
        )
        for r in valid_rows
    ]

    try:
        conn = _connect()
        with conn:
            with conn.cursor() as cur:
                execute_values(cur, _INSERT_SQL, values)
        conn.close()
        log.info("DB INSERT 완료: %d건", len(valid_rows))
    except psycopg2.OperationalError as e:
        log.error("DB 연결 실패: %s", e)
    except Exception as e:
        log.error("DB INSERT 실패: %s", e)