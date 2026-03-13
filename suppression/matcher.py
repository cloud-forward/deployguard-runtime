"""
suppression/matcher.py

Suppression Matcher — EvidenceFact를 suppression_policy.yaml 규칙에 매칭.

매칭 기준 (모두 AND):
  - namespace / pod_name / pod_uid / service_account / workload_name / workload_kind / node_name
  - workload_labels  : dict — 모든 key/value 일치 (value는 정규식)
  - workload_annotations: dict — 동일
  - fact_type        : 정규식
  - category         : 정규식
  - binary           : 정규식 (attributes.binary 또는 raw_excerpt.binary)
  - arguments        : 정규식 (raw_excerpt.arguments)
  - target           : 정규식

설계 원칙:
  - pod_name / service_account 문자열을 코드에 하드코딩하지 않음
  - 모든 matcher 조건은 YAML에서 주입
  - workload_labels 기반 식별이 1순위 (runtime metadata)
  - suppress는 outbound EvidenceFact만 차단. 내부 카운터/로그는 유지.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any, Optional

import yaml

from suppression.models import SuppressionResult, SuppressionRule, SuppressionMetric
from schemas.evidence_fact import EvidenceFact

log = logging.getLogger(__name__)

# ── 정책 파일 경로 ────────────────────────────────────────────────────
_POLICY_PATH_ENV = "SUPPRESSION_POLICY_PATH"
_DEFAULT_CANDIDATES = [
    Path(__file__).parent / "suppression_policy.yaml",
    Path("/etc/deployguard/suppression_policy.yaml"),
    Path("/config/suppression_policy.yaml"),
]


# ── Matcher 클래스 ────────────────────────────────────────────────────

class SuppressionMatcher:
    """
    YAML 정책 기반 suppression 매처.

    사용법:
        matcher = SuppressionMatcher()
        result  = matcher.evaluate(fact, workload_labels={"deployguard.io/internal-collector": "true"})
        if result.suppressed:
            # outbound 전송 차단, 로그/카운터는 유지
    """

    def __init__(self, policy_path: Optional[Path] = None) -> None:
        self._rules:   list[SuppressionRule]         = []
        self._metrics: dict[str, SuppressionMetric]  = {}
        self._load(policy_path)

    # ── 정책 로드 ─────────────────────────────────────────────────────

    def _load(self, path: Optional[Path] = None) -> None:
        resolved = self._resolve_path(path)
        if resolved is None:
            log.warning("suppression_policy.yaml 없음 — suppression 비활성")
            return

        try:
            with open(resolved) as f:
                data: dict = yaml.safe_load(f) or {}
            raw_rules = data.get("rules", [])
            self._rules = [self._parse_rule(r) for r in raw_rules if r.get("enabled", True)]
            # 메트릭 슬롯 초기화
            for rule in self._rules:
                self._metrics[rule.id] = SuppressionMetric(
                    rule_id=rule.id,
                    reason=rule.reason,
                )
            log.info(f"Suppression 정책 로드: {len(self._rules)}개 규칙 (경로: {resolved})")
        except Exception as e:
            log.error(f"suppression_policy.yaml 로드 실패: {e}")

    def reload(self) -> None:
        """런타임 정책 갱신 (SIGHUP 등)."""
        self._rules   = []
        self._metrics = {}
        self._load()

    @staticmethod
    def _resolve_path(path: Optional[Path]) -> Optional[Path]:
        if path and path.exists():
            return path
        env = os.environ.get(_POLICY_PATH_ENV)
        if env:
            p = Path(env)
            if p.exists():
                return p
        for c in _DEFAULT_CANDIDATES:
            if c.exists():
                return c
        return None

    @staticmethod
    def _parse_rule(raw: dict) -> SuppressionRule:
        return SuppressionRule(
            id=raw.get("id", "unknown"),
            description=raw.get("description", ""),
            enabled=raw.get("enabled", True),
            reason=raw.get("reason", "suppressed"),
            match=raw.get("match", {}),
            action=raw.get("action", {"drop": True}),
        )

    # ── 공개 인터페이스 ───────────────────────────────────────────────

    def evaluate(
        self,
        fact: EvidenceFact,
        workload_labels:      Optional[dict[str, str]] = None,
        workload_annotations: Optional[dict[str, str]] = None,
    ) -> SuppressionResult:
        """
        EvidenceFact를 모든 규칙에 순서대로 매칭.
        첫 번째 매칭 규칙에서 결과 반환 (first-match).

        workload_labels / workload_annotations:
            enricher가 kubectl에서 수집한 pod 라벨/어노테이션.
            없으면 빈 dict로 처리.
        """
        labels      = workload_labels      or {}
        annotations = workload_annotations or {}

        for rule in self._rules:
            if self._matches(rule, fact, labels, annotations):
                result = SuppressionResult(
                    suppressed=        rule.drop,
                    rule_id=           rule.id,
                    suppressed_reason= rule.reason,
                    log_level=         rule.log_level,
                    emit_metric=       rule.emit_metric,
                )
                self._record(rule, fact, result)
                return result

        return SuppressionResult(suppressed=False)

    def metrics_snapshot(self) -> list[dict]:
        """진단 카운터 스냅샷. 엔진 또는 메트릭 엔드포인트에서 호출."""
        return [m.to_dict() for m in self._metrics.values()]

    # ── 매칭 로직 ─────────────────────────────────────────────────────

    def _matches(
        self,
        rule:        SuppressionRule,
        fact:        EvidenceFact,
        labels:      dict[str, str],
        annotations: dict[str, str],
    ) -> bool:
        m = rule.match

        # ── 문자열 필드 (정규식) ──────────────────────────────────────
        field_map = {
            "namespace":       fact.actor.namespace,
            "pod_name":        fact.actor.pod_name,
            "pod_uid":         fact.actor.pod_uid,
            "service_account": fact.actor.service_account,
            "workload_name":   fact.actor.workload_name,
            "workload_kind":   fact.actor.workload_kind,
            "node_name":       fact.actor.node_name,
            "fact_type":       fact.fact_type,
            "category":        fact.category,
            "target":          fact.target,
        }
        for key, val in field_map.items():
            if key in m:
                if not _re_match(m[key], val):
                    return False

        # ── binary / arguments (raw_excerpt 또는 attributes) ──────────
        if "binary" in m:
            binary = (
                (fact.attributes or {}).get("binary")
                or (fact.raw_excerpt or {}).get("binary")
            )
            if not _re_match(m["binary"], binary):
                return False

        if "arguments" in m:
            arguments = (fact.raw_excerpt or {}).get("arguments")
            if not _re_match(m["arguments"], arguments):
                return False

        # ── workload_labels (모든 key/value AND) ──────────────────────
        if "workload_labels" in m:
            for lk, lv in m["workload_labels"].items():
                actual = labels.get(lk)
                if not _re_match(lv, actual):
                    return False

        # ── workload_annotations ─────────────────────────────────────
        if "workload_annotations" in m:
            for ak, av in m["workload_annotations"].items():
                actual = annotations.get(ak)
                if not _re_match(av, actual):
                    return False

        return True

    # ── 기록 ──────────────────────────────────────────────────────────

    def _record(
        self,
        rule:   SuppressionRule,
        fact:   EvidenceFact,
        result: SuppressionResult,
    ) -> None:
        # 내부 카운터 (emit_metric=True이면 항상 유지)
        if result.emit_metric and rule.id in self._metrics:
            self._metrics[rule.id].increment(fact.scanner_event_id)

        # 로그 (suppress되어도 로그는 남긴다)
        msg = (
            f"[suppression] rule={rule.id} "
            f"fact_type={fact.fact_type} "
            f"pod={fact.actor.pod_name} "
            f"ns={fact.actor.namespace} "
            f"reason={rule.reason} "
            f"drop={result.suppressed}"
        )
        level = result.log_level.upper()
        getattr(log, result.log_level, log.debug)(msg)


# ── 유틸 ──────────────────────────────────────────────────────────────

def _re_match(pattern: str, value: Optional[str]) -> bool:
    """
    pattern이 value 전체에 매칭되는지 확인.
    value가 None이면 False.
    """
    if value is None:
        return False
    try:
        return bool(re.fullmatch(pattern, value))
    except re.error:
        log.warning(f"잘못된 정규식 패턴: {pattern!r}")
        return False


# ── 싱글턴 ────────────────────────────────────────────────────────────
# runner.py에서 전역 인스턴스로 사용

_matcher: Optional[SuppressionMatcher] = None


def get_matcher() -> SuppressionMatcher:
    global _matcher
    if _matcher is None:
        _matcher = SuppressionMatcher()
    return _matcher


def reload_matcher() -> SuppressionMatcher:
    global _matcher
    _matcher = SuppressionMatcher()
    return _matcher
