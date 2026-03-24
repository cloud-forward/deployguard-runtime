"""
forwarder/engine_projector.py

EvidenceFact → runtime_events INSERT row 변환.

역할:
  - DB 스키마 매핑 규칙만 여기에 둔다
  - DB 연결 / SQL 실행은 db_writer.py 담당
  - schemas / fact_builder 계층과 무관하게 유지

저장 대상 (Tetragon only, 이번 단계):
  sa_token_access            → SA_TOKEN_ACCESS
  imds_access                → IMDS_ACCESS
  suspicious_process         → SUSPICIOUS_PROCESS
  host_sensitive_path_access → SENSITIVE_FILE_ACCESS
  network_connect            → ABNORMAL_EGRESS

위 목록 외 fact_type → None 반환 (DB skip, live payload로만 내보냄)
source != "tetragon"        → None 반환 (Audit DB 저장은 추후)
"""

from __future__ import annotations

from typing import Optional

from schemas.evidence_fact import EvidenceFact

# ── Tetragon fact_type → DB event_type 매핑 ──────────────────────────
_FACT_TYPE_TO_EVENT_TYPE: dict[str, str] = {
    "sa_token_access":            "SA_TOKEN_ACCESS",
    "imds_access":                "IMDS_ACCESS",
    "suspicious_process":         "SUSPICIOUS_PROCESS",
    "host_sensitive_path_access": "SENSITIVE_FILE_ACCESS",
    "network_connect":            "ABNORMAL_EGRESS",
}


def project(evidence: EvidenceFact) -> Optional[dict]:
    """
    EvidenceFact → runtime_events INSERT용 dict.

    반환 None 조건:
      - source != "tetragon"
      - fact_type이 매핑 대상이 아님
    """
    if evidence.source != "tetragon":
        return None

    event_type = _FACT_TYPE_TO_EVENT_TYPE.get(evidence.fact_type)
    if event_type is None:
        return None

    actor    = evidence.actor
    ns       = actor.namespace or ""
    pod_name = actor.pod_name  or ""
    pod_id   = f"pod:{ns}:{pod_name}" if (ns or pod_name) else None

    # metadata는 dict 그대로 유지 — db_writer에서 Json()으로 감싸서 insert
    metadata = {
        "actor":                  actor.model_dump(exclude_none=True),
        "target":                 evidence.target,
        "attributes":             evidence.attributes,
        "raw_excerpt":            evidence.raw_excerpt,
        "scenario_tags":          evidence.scenario_tags,
        "severity_hint":          evidence.severity_hint,
        "confidence_hint":        evidence.confidence_hint,
        "source_native_event_id": evidence.source_native_event_id,
    }

    return {
        "cluster_id": evidence.cluster_id,
        "event_id":   evidence.dedup_key,
        "event_type": event_type,
        "pod_id":     pod_id,
        "timestamp":  evidence.observed_at,
        "metadata":   metadata,
        "source":     "ebpf",
    }