"""
runtime_api/store.py

In-memory fact 저장소.
초기 버전은 DB 없이 동작한다.
Redis / PostgreSQL 교체 시 이 파일의 FactStore만 교체하면 된다.

설계:
  - dedup_key 기준 중복 제거
  - workload_id 기준 인덱스 유지
  - cluster_id 기준 multi-cluster 대응
  - 최대 보관 건수 / TTL은 환경변수로 조정
"""

from __future__ import annotations

import logging
import os
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from threading import Lock
from typing import Optional

from runtime_api.schemas import FactPayload

log = logging.getLogger(__name__)

# 보관 설정
_MAX_FACTS_PER_WORKLOAD = int(os.environ.get("STORE_MAX_FACTS_PER_WORKLOAD", "500"))
_FACT_TTL_HOURS         = int(os.environ.get("STORE_FACT_TTL_HOURS", "24"))


def _make_workload_id(fact: FactPayload) -> str:
    """
    workload_id = cluster_id:namespace:workload_kind:workload_name
    fallback: pod_name 사용
    """
    actor = fact.actor
    ns    = actor.get("namespace") or ""
    kind  = actor.get("workload_kind") or "Pod"
    name  = actor.get("workload_name") or actor.get("pod_name") or "unknown"
    return f"{fact.cluster_id}:{ns}:{kind}:{name}"


class FactStore:
    """
    Thread-safe in-memory fact store.

    교체 인터페이스:
      add(facts) → (accepted, duplicate)
      get_workload_ids(cluster_id) → list[str]
      get_facts(workload_id, limit) → list[FactPayload]
      get_all_summaries(cluster_id) → dict[workload_id, list[FactPayload]]
    """

    def __init__(self) -> None:
        self._lock = Lock()
        # dedup_key → FactPayload
        self._by_dedup: dict[str, FactPayload] = {}
        # workload_id → list[dedup_key] (insertion order)
        self._by_workload: dict[str, list[str]] = defaultdict(list)
        # cluster_id → set[workload_id]
        self._by_cluster: dict[str, set[str]] = defaultdict(set)

    def add(self, facts: list[FactPayload]) -> tuple[int, int]:
        """
        반환: (accepted, duplicate)
        """
        accepted  = 0
        duplicate = 0
        cutoff    = datetime.now(timezone.utc) - timedelta(hours=_FACT_TTL_HOURS)

        with self._lock:
            for fact in facts:
                key = fact.dedup_key
                if key in self._by_dedup:
                    duplicate += 1
                    continue

                # TTL 초과 항목 제거 (lazy)
                if fact.observed_at < cutoff:
                    duplicate += 1
                    continue

                wid = _make_workload_id(fact)
                self._by_dedup[key] = fact
                self._by_workload[wid].append(key)
                self._by_cluster[fact.cluster_id].add(wid)
                accepted += 1

                # 워크로드당 최대 보관 건수 초과 시 오래된 것 제거
                keys = self._by_workload[wid]
                if len(keys) > _MAX_FACTS_PER_WORKLOAD:
                    oldest = keys.pop(0)
                    self._by_dedup.pop(oldest, None)

        return accepted, duplicate

    def get_workload_ids(self, cluster_id: Optional[str] = None) -> list[str]:
        with self._lock:
            if cluster_id:
                return sorted(self._by_cluster.get(cluster_id, set()))
            # 전체 클러스터
            all_wids: set[str] = set()
            for wids in self._by_cluster.values():
                all_wids |= wids
            return sorted(all_wids)

    def get_facts(
        self,
        workload_id: str,
        limit: int = 100,
        since: Optional[datetime] = None,
    ) -> list[FactPayload]:
        with self._lock:
            keys  = self._by_workload.get(workload_id, [])
            facts = [self._by_dedup[k] for k in keys if k in self._by_dedup]
        if since:
            facts = [f for f in facts if f.observed_at >= since]
        # 최신순
        facts.sort(key=lambda f: f.observed_at, reverse=True)
        return facts[:limit]

    def get_all_workload_facts(
        self,
        cluster_id: Optional[str] = None,
    ) -> dict[str, list[FactPayload]]:
        """summary 계층이 사용하는 전체 조회."""
        wids = self.get_workload_ids(cluster_id)
        result: dict[str, list[FactPayload]] = {}
        for wid in wids:
            facts = self.get_facts(wid, limit=_MAX_FACTS_PER_WORKLOAD)
            if facts:
                result[wid] = facts
        return result

    def purge_expired(self) -> int:
        """TTL 초과 항목 일괄 제거. 백그라운드 태스크에서 호출."""
        cutoff  = datetime.now(timezone.utc) - timedelta(hours=_FACT_TTL_HOURS)
        removed = 0
        with self._lock:
            expired = [k for k, f in self._by_dedup.items() if f.observed_at < cutoff]
            for k in expired:
                self._by_dedup.pop(k, None)
                removed += 1
            # workload 인덱스 정리
            for wid in list(self._by_workload.keys()):
                self._by_workload[wid] = [
                    k for k in self._by_workload[wid] if k in self._by_dedup
                ]
                if not self._by_workload[wid]:
                    del self._by_workload[wid]
            # cluster 인덱스 정리
            for cid in list(self._by_cluster.keys()):
                self._by_cluster[cid] = {
                    w for w in self._by_cluster[cid] if w in self._by_workload
                }
        if removed:
            log.info("store.purge_expired: %d건 제거", removed)
        return removed


# 싱글턴
_store: Optional[FactStore] = None


def get_store() -> FactStore:
    global _store
    if _store is None:
        _store = FactStore()
    return _store
