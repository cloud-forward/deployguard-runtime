from datetime import datetime, timedelta, timezone
import sys
import types

if "boto3" not in sys.modules:
    boto3 = types.ModuleType("boto3")
    boto3.client = lambda *args, **kwargs: None
    boto3.session = types.SimpleNamespace(Config=lambda **kwargs: kwargs)
    sys.modules["boto3"] = boto3

if "botocore.exceptions" not in sys.modules:
    botocore = types.ModuleType("botocore")
    exceptions = types.ModuleType("botocore.exceptions")

    class ClientError(Exception):
        pass

    exceptions.ClientError = ClientError
    botocore.exceptions = exceptions
    sys.modules["botocore"] = botocore
    sys.modules["botocore.exceptions"] = exceptions

from runtime_api.schemas import FactPayload
from runtime_api.services.exposure_query import ImageExposureSummary
from runtime_api.services.workload_detail import (
    aggregate_runtime_evidence,
    build_dashboard_reason,
    get_workload_detail,
    is_dashboard_eligible,
    list_workloads,
)
from runtime_api.store import FactStore


def _fact(
    *,
    dedup_key: str,
    cluster_id: str = "c1",
    namespace: str = "default",
    workload_name: str = "api",
    observed_at: datetime | None = None,
    severity_hint: str | None = "medium",
    fact_family: str = "execution",
    scenario_tags: list[str] | None = None,
    image_ref: str = "",
    image_digest: str = "",
) -> FactPayload:
    observed_at = observed_at or datetime.now(timezone.utc)
    return FactPayload(
        schema_version="1",
        fact_version="1",
        scanner_version="1",
        cluster_id=cluster_id,
        observed_at=observed_at,
        collected_at=observed_at,
        scanner_event_id=f"evt-{dedup_key}",
        source="test",
        dedup_key=dedup_key,
        fact_family=fact_family,
        fact_type="test.fact",
        category="runtime",
        action="observe",
        actor={
            "namespace": namespace,
            "workload_kind": "Deployment",
            "workload_name": workload_name,
            "pod_name": f"{workload_name}-pod",
            "image_ref": image_ref,
            "image_digest": image_digest,
        },
        severity_hint=severity_hint,
        scenario_tags=scenario_tags or [],
    )


def _exposure(
    *,
    image_ref: str,
    image_digest: str = "",
    critical: int = 0,
    high: int = 0,
    fix_available: bool = False,
    poc_exists: bool = False,
    source: str = "trivy",
    scanned_at: datetime | None = None,
) -> ImageExposureSummary:
    return ImageExposureSummary(
        {
            "image_ref": image_ref,
            "image_digest": image_digest,
            "critical_cve_count": critical,
            "high_cve_count": high,
            "fix_available": fix_available,
            "poc_exists": poc_exists,
            "sample_cves": ["CVE-1"] if critical or high else [],
            "source": source,
            "scanned_at": scanned_at or datetime.now(timezone.utc),
        }
    )


def test_unknown_workload_is_excluded() -> None:
    assert is_dashboard_eligible(
        "unknown",
        "prod",
        [],
        evidence_count=3,
        evidence_highest_severity="critical",
        evidence_scenario_tags=["aws_takeover"],
        evidence_fact_families=["credential_access"],
    ) is False


def test_deployguard_namespace_is_excluded() -> None:
    assert is_dashboard_eligible(
        "scanner",
        "deployguard",
        [],
        evidence_count=2,
        evidence_highest_severity="high",
        evidence_scenario_tags=["collector"],
        evidence_fact_families=["execution"],
    ) is False


def test_aggregate_runtime_evidence_populates_dashboard_fields() -> None:
    now = datetime.now(timezone.utc)
    facts = [
        _fact(
            dedup_key="a",
            observed_at=now - timedelta(minutes=5),
            severity_hint="medium",
            fact_family="execution",
            scenario_tags=["tag-a", "tag-b"],
        ),
        _fact(
            dedup_key="b",
            observed_at=now,
            severity_hint="high",
            fact_family="credential_access",
            scenario_tags=["tag-b", "tag-c"],
        ),
    ]

    agg = aggregate_runtime_evidence(facts)

    assert agg.count == 2
    assert agg.latest_at == now
    assert agg.highest_severity == "high"
    assert agg.fact_families == ["credential_access", "execution"]
    assert agg.scenario_tags == ["tag-a", "tag-b", "tag-c"]


def test_evidence_only_workload_requires_meaningful_signal() -> None:
    assert is_dashboard_eligible(
        "api",
        "prod",
        [],
        evidence_count=1,
        evidence_highest_severity="low",
        evidence_scenario_tags=[],
        evidence_fact_families=["unknown"],
    ) is False

    assert is_dashboard_eligible(
        "api",
        "prod",
        [],
        evidence_count=1,
        evidence_highest_severity="high",
        evidence_scenario_tags=[],
        evidence_fact_families=["unknown"],
    ) is True

    assert is_dashboard_eligible(
        "api",
        "prod",
        [],
        evidence_count=1,
        evidence_highest_severity="low",
        evidence_scenario_tags=["aws_takeover"],
        evidence_fact_families=["unknown"],
    ) is True

    assert is_dashboard_eligible(
        "api",
        "prod",
        [],
        evidence_count=1,
        evidence_highest_severity="low",
        evidence_scenario_tags=[],
        evidence_fact_families=["credential_access"],
    ) is True


def test_exposure_workload_sorts_ahead_of_evidence_only(monkeypatch) -> None:
    now = datetime.now(timezone.utc)

    def _lookup(cluster_id, image_refs, image_digests):
        if "repo/exposed:1" in image_refs:
            return [
                _exposure(
                    image_ref="repo/exposed:1",
                    image_digest="sha256:abc",
                    critical=2,
                    high=3,
                    fix_available=True,
                    poc_exists=True,
                    scanned_at=now,
                )
            ]
        return []

    monkeypatch.setattr("runtime_api.services.workload_detail.lookup_exposure", _lookup)

    store = FactStore()
    store.add(
        [
            _fact(
                dedup_key="exp-1",
                workload_name="exposed-app",
                severity_hint="medium",
                fact_family="execution",
                scenario_tags=[],
                image_ref="repo/exposed:1",
                image_digest="sha256:abc",
            ),
            _fact(
                dedup_key="evi-1",
                workload_name="evidence-app",
                severity_hint="critical",
                fact_family="credential_access",
                scenario_tags=["aws_takeover"],
            ),
        ]
    )

    summaries = list_workloads(store=store, eligible_only=True)

    assert [s.workload_name for s in summaries] == ["exposed-app", "evidence-app"]
    assert summaries[0].dashboard_category == "hybrid"
    assert summaries[0].exposure_image_count == 1
    assert summaries[1].dashboard_category == "runtime_evidence"


def test_dashboard_reason_and_category_are_generated() -> None:
    category, reason = build_dashboard_reason(
        "payments",
        "prod",
        [],
        evidence_count=2,
        evidence_highest_severity="high",
        evidence_scenario_tags=["aws_takeover"],
        evidence_fact_families=["credential_access"],
    )

    assert category == "runtime_evidence"
    assert "runtime evidence met dashboard gate" in reason
    assert "severity=high" in reason


def test_detail_includes_dashboard_metadata_and_aggregate_fields(monkeypatch) -> None:
    now = datetime.now(timezone.utc)

    monkeypatch.setattr(
        "runtime_api.services.workload_detail.lookup_exposure",
        lambda cluster_id, image_refs, image_digests: [
            _exposure(
                image_ref="repo/app:1",
                image_digest="sha256:def",
                critical=1,
                high=2,
                fix_available=True,
                source="grype",
                scanned_at=now,
            )
        ],
    )

    store = FactStore()
    fact = _fact(
        dedup_key="detail-1",
        workload_name="detail-app",
        observed_at=now,
        severity_hint="high",
        fact_family="credential_access",
        scenario_tags=["irsa_chain"],
        image_ref="repo/app:1",
        image_digest="sha256:def",
    )
    store.add([fact])

    detail = get_workload_detail("c1:default:Deployment:detail-app", store=store)

    assert detail is not None
    assert detail.dashboard_eligible is True
    assert detail.dashboard_category == "hybrid"
    assert detail.dashboard_reason == "image exposure present and runtime evidence met dashboard gate"
    assert detail.exposure_critical_cve_count == 1
    assert detail.exposure_high_cve_count == 2
    assert detail.exposure_has_fix_available is True
    assert detail.exposure_image_count == 1
    assert detail.exposure_sources == ["grype"]
