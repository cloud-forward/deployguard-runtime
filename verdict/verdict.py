from typing import List
from datetime import datetime, timezone

from schemas.evidence import Evidence, EvidenceType, PathVerdict, AttackPathState


# 시나리오별 evidence 매핑
SCENARIO_RULES = {
    "scenario_1_external_exposure_aws": {
        "description": "외부 노출 → CVE 악용 → IRSA/AWS 접근 → 클라우드 권한 확장 시도",
        "rules": [
            # (verdict, required evidence 중 하나라도 있으면)
            (PathVerdict.EXPANSION_ATTEMPT_OBSERVED, {
                EvidenceType.ACCESSED_IMDS,
                EvidenceType.AWS_API_ACCESS,
                EvidenceType.AWS_CREDENTIAL_USAGE,
            }),
            (PathVerdict.PATH_PARTIALLY_CONFIRMED, {
                EvidenceType.READ_SECRET,
                EvidenceType.KUBE_API_ACCESS,
            }),
            (PathVerdict.PATH_OBSERVED, {
                EvidenceType.SUSPICIOUS_EXECUTION,
                EvidenceType.ACCESSED_SA_TOKEN,
            }),
        ],
    },

    "scenario_2_supply_chain_data_exfil": {
        "description": "공급망 공격 → 내부 확산 → 데이터 유출 시도",
        "rules": [
            (PathVerdict.DATA_EXFIL_ATTEMPT_OBSERVED, {
                EvidenceType.AWS_API_ACCESS,
                EvidenceType.AWS_CREDENTIAL_USAGE,
            }),
            (PathVerdict.PATH_PARTIALLY_CONFIRMED, {
                EvidenceType.READ_SECRET,
                EvidenceType.LIST_SECRET,
                EvidenceType.POD_EXEC_REQUEST,
            }),
            (PathVerdict.PATH_OBSERVED, {
                EvidenceType.SUSPICIOUS_EXECUTION,
                EvidenceType.KUBE_API_ACCESS,
            }),
        ],
    },

    "scenario_3_neglected_resource_expansion": {
        "description": "방치된 자원 → 오래된 이미지/과권한 → AWS 또는 노드 확장 시도",
        "rules": [
            (PathVerdict.EXPANSION_ATTEMPT_OBSERVED, {
                EvidenceType.CREATED_DAEMONSET,
                EvidenceType.CREATED_ROLEBINDING,
                EvidenceType.ACCESSED_IMDS,
            }),
            (PathVerdict.PATH_PARTIALLY_CONFIRMED, {
                EvidenceType.ACCESSED_HOST_SENSITIVE_PATH,
                EvidenceType.CREATED_CRONJOB,
            }),
            (PathVerdict.PATH_OBSERVED, {
                EvidenceType.SUSPICIOUS_EXECUTION,
                EvidenceType.ACCESSED_SA_TOKEN,
            }),
        ],
    },
}


def determine_verdict(
    path_id: str,
    scenario_key: str,
    evidences: List[Evidence],
) -> AttackPathState:
    """
    evidence 목록을 받아서 해당 시나리오의 PathVerdict를 판정한다.
    rules는 위에서 아래로 순서대로 체크 — 가장 높은 verdict가 채택된다.
    """
    scenario = SCENARIO_RULES.get(scenario_key)
    if not scenario:
        raise ValueError(f"알 수 없는 시나리오: {scenario_key}")

    observed_types = {e.evidence_type for e in evidences}

    verdict = PathVerdict.PATH_POSSIBLE
    verdict_reason = "정적 조건만 충족 — 실제 행위 미관측"

    for rule_verdict, required_types in scenario["rules"]:
        if observed_types & required_types:  # 교집합이 있으면
            verdict = rule_verdict
            matched = observed_types & required_types
            verdict_reason = f"{rule_verdict.value} 판정 근거: {', '.join(t.value for t in matched)}"
            break

    return AttackPathState(
        path_id=path_id,
        scenario=scenario["description"],
        verdict=verdict,
        evidences=evidences,
        last_updated=datetime.now(timezone.utc),
        verdict_reason=verdict_reason,
    )