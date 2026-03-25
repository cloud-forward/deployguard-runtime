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
    build_alert_flags,
    build_alert_reason,
    compute_risk_level,
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
    assert is_dashboard_eligible("unknown", "prod", []) is False


def test_deployguard_namespace_is_excluded() -> None:
    assert is_dashboard_eligible("scanner", "deployguard", []) is False


def test_non_noise_workload_without_exposure_or_evidence_is_included() -> None:
    assert is_dashboard_eligible("api", "prod", []) is True


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


def test_risk_level_prefers_image_then_runtime_amplifies() -> None:
    assert compute_risk_level(1, 0, 1, "low") == "critical"
    assert compute_risk_level(1, 0, 0, None) == "high"
    assert compute_risk_level(0, 3, 1, "medium") == "high"
    assert compute_risk_level(0, 2, 0, None) == "medium"
    assert compute_risk_level(0, 0, 1, "high") == "high"
    assert compute_risk_level(0, 0, 1, "low") == "low"
    assert compute_risk_level(0, 0, 0, None) == "info"


def test_alert_flags_and_reason_are_generated() -> None:
    flags = build_alert_flags(1, 2, True, True, 1, "high")
    reason = build_alert_reason(1, 2, 1, "high")

    assert flags == [
        "has_critical_cve",
        "has_high_cve",
        "has_fix_available",
        "has_poc",
        "has_runtime_activity",
        "has_runtime_high_signal",
    ]
    assert reason == "Critical vulnerabilities actively used at runtime"


def test_list_workloads_includes_runtime_only_and_info_workloads_and_sorts_by_risk(monkeypatch) -> None:
    now = datetime.now(timezone.utc)

    def _lookup(cluster_id, image_refs, image_digests):
        if "repo/critical:1" in image_refs:
            return [
                _exposure(
                    image_ref="repo/critical:1",
                    image_digest="sha256:111",
                    critical=2,
                    high=1,
                    fix_available=True,
                    poc_exists=True,
                    scanned_at=now,
                )
            ]
        if "repo/high:1" in image_refs:
            return [
                _exposure(
                    image_ref="repo/high:1",
                    image_digest="sha256:222",
                    critical=0,
                    high=4,
                    fix_available=True,
                    scanned_at=now - timedelta(minutes=5),
                )
            ]
        return []

    monkeypatch.setattr("runtime_api.services.workload_detail.lookup_exposure", _lookup)

    store = FactStore()
    store.add(
        [
            _fact(
                dedup_key="crit-runtime",
                workload_name="critical-runtime",
                severity_hint="high",
                fact_family="credential_access",
                scenario_tags=["aws_takeover"],
                image_ref="repo/critical:1",
                image_digest="sha256:111",
            ),
            _fact(
                dedup_key="high-image",
                workload_name="high-image-only",
                severity_hint="low",
                image_ref="repo/high:1",
                image_digest="sha256:222",
            ),
            _fact(
                dedup_key="runtime-only",
                workload_name="runtime-only",
                severity_hint="high",
                fact_family="execution",
            ),
            _fact(
                dedup_key="low-runtime",
                workload_name="low-runtime",
                severity_hint="low",
                fact_family="execution",
            ),
        ]
    )

    summaries = list_workloads(store=store, eligible_only=True)

    assert [s.workload_name for s in summaries] == [
        "critical-runtime",
        "high-image-only",
        "runtime-only",
        "low-runtime",
    ]
    assert [s.risk_level for s in summaries] == ["critical", "high", "high", "low"]
    assert summaries[0].alert_reason == "Critical vulnerabilities actively used at runtime"
    assert "has_poc" in summaries[0].alert_flags


def test_detail_includes_risk_and_alert_fields(monkeypatch) -> None:
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
    assert detail.risk_level == "critical"
    assert detail.alert_reason == "Critical vulnerabilities actively used at runtime"
    assert "has_runtime_high_signal" in detail.alert_flags
    assert detail.exposure_critical_cve_count == 1
    assert detail.exposure_high_cve_count == 2
    assert detail.exposure_has_fix_available is True
    assert detail.exposure_image_count == 1
    assert detail.exposure_sources == ["grype"]
