from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Optional

import yaml

from suppression.models import SuppressionMetric, SuppressionResult, SuppressionRule
from suppression.self_identity import get_identity
from schemas.evidence_fact import EvidenceFact

log = logging.getLogger(__name__)

_POLICY_PATH_ENV = "SUPPRESSION_POLICY_PATH"
_DEFAULT_CANDIDATES = [
    Path(__file__).parent / "suppression_policy.yaml",
    Path("/etc/deployguard/suppression_policy.yaml"),
    Path("/config/suppression_policy.yaml"),
]


class SuppressionMatcher:
    """
    YAML 정책 기반 suppression 매처.

    특징
      - 정책 파일은 suppression_policy.yaml에서 로드
      - self fact로 판단되면 scanner identity labels/annotations를 자동 주입
      - pod rollout 후 이전 Pod 이벤트도 stable identity 기준으로 suppress 가능
    """

    def __init__(self, policy_path: Optional[Path] = None) -> None:
        self._rules: list[SuppressionRule] = []
        self._metrics: dict[str, SuppressionMetric] = {}
        self._load(policy_path)

    def _load(self, path: Optional[Path] = None) -> None:
        resolved = self._resolve_path(path)
        if resolved is None:
            log.warning("suppression_policy.yaml 없음 — suppression 비활성")
            return

        try:
            with open(resolved, encoding="utf-8") as f:
                data: dict = yaml.safe_load(f) or {}

            raw_rules = data.get("rules", []) or []
            self._rules = [
                self._parse_rule(r) for r in raw_rules if r.get("enabled", True)
            ]

            self._metrics = {}
            for rule in self._rules:
                self._metrics[rule.id] = SuppressionMetric(
                    rule_id=rule.id,
                    reason=rule.reason,
                )

            log.info(
                "Suppression 정책 로드: %s개 규칙 (경로: %s)",
                len(self._rules),
                resolved,
            )
        except Exception as e:
            log.error("suppression_policy.yaml 로드 실패: %s", e)

    def reload(self) -> None:
        self._rules = []
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
            match=raw.get("match", {}) or {},
            action=raw.get("action", {"drop": True}) or {"drop": True},
        )

    def evaluate(
        self,
        fact: EvidenceFact,
        workload_labels: Optional[dict[str, str]] = None,
        workload_annotations: Optional[dict[str, str]] = None,
    ) -> SuppressionResult:
        """
        EvidenceFact를 규칙에 순서대로 매칭한다.
        first-match 방식.

        workload_labels / workload_annotations:
          actor workload에서 수집한 메타데이터.
          self fact면 현재 scanner identity의 labels/annotations를 자동 merge한다.
        """
        labels = dict(workload_labels or {})
        annotations = dict(workload_annotations or {})

        identity = get_identity()
        if self._is_self_fact(identity, fact):
            merged_self_labels = identity.to_match_labels()
            merged_self_annotations = dict(identity.annotations or {})

            for k, v in merged_self_labels.items():
                labels.setdefault(k, v)
            for k, v in merged_self_annotations.items():
                annotations.setdefault(k, v)

        for rule in self._rules:
            if self._matches(rule, fact, labels, annotations):
                result = SuppressionResult(
                    suppressed=rule.drop,
                    rule_id=rule.id,
                    suppressed_reason=rule.reason,
                    log_level=rule.log_level,
                    emit_metric=rule.emit_metric,
                )
                self._record(rule, fact, result)
                return result

        return SuppressionResult(suppressed=False)

    def metrics_snapshot(self) -> list[dict]:
        return [m.to_dict() for m in self._metrics.values()]

    @staticmethod
    def _is_self_fact(identity, fact: EvidenceFact) -> bool:
        actor = fact.actor
        return identity.is_self(
            pod_uid=getattr(actor, "pod_uid", None),
            pod_name=getattr(actor, "pod_name", None),
            namespace=getattr(actor, "namespace", None),
            service_account=getattr(actor, "service_account", None),
            container_name=getattr(actor, "container_name", None),
            workload_name=getattr(actor, "workload_name", None),
            workload_kind=getattr(actor, "workload_kind", None),
        )

    def _matches(
        self,
        rule: SuppressionRule,
        fact: EvidenceFact,
        labels: dict[str, str],
        annotations: dict[str, str],
    ) -> bool:
        m = rule.match or {}
        actor = fact.actor

        field_map = {
            "namespace": getattr(actor, "namespace", None),
            "pod_name": getattr(actor, "pod_name", None),
            "pod_uid": getattr(actor, "pod_uid", None),
            "service_account": getattr(actor, "service_account", None),
            "container_name": getattr(actor, "container_name", None),
            "workload_name": getattr(actor, "workload_name", None),
            "workload_kind": getattr(actor, "workload_kind", None),
            "node_name": getattr(actor, "node_name", None),
            "image_ref": getattr(actor, "image_ref", None),
            "fact_type": getattr(fact, "fact_type", None),
            "fact_family": getattr(fact, "fact_family", None),
            "category": getattr(fact, "category", None),
            "target": getattr(fact, "target", None),
            "target_type": getattr(fact, "target_type", None),
        }

        for key, actual in field_map.items():
            if key in m and not _re_match(str(m[key]), actual):
                return False

        if "binary" in m:
            binary = (
                (getattr(fact, "attributes", None) or {}).get("binary")
                or (getattr(fact, "raw_excerpt", None) or {}).get("binary")
            )
            if not _re_match(str(m["binary"]), binary):
                return False

        if "arguments" in m:
            arguments = (
                (getattr(fact, "attributes", None) or {}).get("arguments")
                or (getattr(fact, "raw_excerpt", None) or {}).get("arguments")
            )
            if not _re_match(str(m["arguments"]), arguments):
                return False

        if "workload_labels" in m:
            for lk, lv in (m["workload_labels"] or {}).items():
                actual = labels.get(lk)
                if not _re_match(str(lv), actual):
                    return False

        if "workload_annotations" in m:
            for ak, av in (m["workload_annotations"] or {}).items():
                actual = annotations.get(ak)
                if not _re_match(str(av), actual):
                    return False

        return True

    def _record(
        self,
        rule: SuppressionRule,
        fact: EvidenceFact,
        result: SuppressionResult,
    ) -> None:
        if result.emit_metric and rule.id in self._metrics:
            self._metrics[rule.id].increment(fact.scanner_event_id)

        msg = (
            f"[suppression] rule={rule.id} "
            f"fact_type={fact.fact_type} "
            f"pod={fact.actor.pod_name} "
            f"ns={fact.actor.namespace} "
            f"reason={rule.reason} "
            f"drop={result.suppressed}"
        )
        getattr(log, result.log_level, log.debug)(msg)


def _re_match(pattern: str, value: Optional[str]) -> bool:
    if value is None:
        return False
    try:
        return bool(re.fullmatch(pattern, value))
    except re.error:
        log.warning("잘못된 정규식 패턴: %r", pattern)
        return False


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