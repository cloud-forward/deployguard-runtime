"""
suppression/models.py

Suppression 관련 데이터 모델.

SuppressionResult : 매칭 결과 + 사유 + 카운터 정보
SuppressionRule   : YAML 규칙 한 항목의 파싱 모델
SuppressionMetric : 내부 진단용 카운터 (outbound 억제 후에도 유지)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


@dataclass
class SuppressionResult:
    """
    Suppression 매칭 결과.

    suppressed    : True이면 outbound EvidenceFact 전송 차단
    rule_id       : 매칭된 규칙 ID (None이면 미매칭)
    suppressed_reason: outbound payload에 기록 가능한 사유 문자열
    log_level     : 로그 출력 레벨
    emit_metric   : 내부 진단 카운터 유지 여부
    """
    suppressed:         bool
    rule_id:            Optional[str]   = None
    suppressed_reason:  Optional[str]   = None
    log_level:          str             = "debug"
    emit_metric:        bool            = True


@dataclass
class SuppressionMetric:
    """
    규칙별 내부 진단 카운터.
    outbound가 억제되어도 이 카운터는 유지된다.
    """
    rule_id:        str
    reason:         str
    match_count:    int         = 0
    last_matched:   Optional[datetime] = None
    sample_fact_ids: list[str]  = field(default_factory=list)  # 최근 5건 ID

    def increment(self, fact_id: Optional[str] = None) -> None:
        self.match_count += 1
        self.last_matched = datetime.now(timezone.utc)
        if fact_id:
            self.sample_fact_ids = (self.sample_fact_ids + [fact_id])[-5:]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id":       self.rule_id,
            "reason":        self.reason,
            "match_count":   self.match_count,
            "last_matched":  self.last_matched.isoformat() if self.last_matched else None,
            "sample_fact_ids": self.sample_fact_ids,
        }


@dataclass
class SuppressionRule:
    """
    YAML suppression_policy.yaml의 단일 규칙 파싱 결과.
    """
    id:          str
    description: str
    enabled:     bool
    reason:      str
    match:       dict[str, Any]   # raw match dict (정규식 문자열 포함)
    action:      dict[str, Any]

    @property
    def drop(self) -> bool:
        return self.action.get("drop", True)

    @property
    def log_level(self) -> str:
        return self.action.get("log_level", "debug")

    @property
    def emit_metric(self) -> bool:
        return self.action.get("emit_metric", True)
