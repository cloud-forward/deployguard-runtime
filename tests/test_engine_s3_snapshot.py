from __future__ import annotations

from datetime import datetime, timedelta, timezone

from schemas.evidence_fact import ActorContext, EvidenceFact


def _fact(*, dedup_key: str, observed_at: datetime, collected_at: datetime) -> EvidenceFact:
    return EvidenceFact(
        scanner_version="scanner-test",
        cluster_id="cluster-1",
        observed_at=observed_at,
        collected_at=collected_at,
        scanner_event_id=f"evt-{dedup_key}",
        source="test",
        dedup_key=dedup_key,
        fact_family="execution",
        fact_type="test.fact",
        category="runtime",
        action="observe",
        actor=ActorContext(namespace="default", pod_name="pod-1"),
    )


def test_send_snapshot_non_empty_success(monkeypatch) -> None:
    from forwarder import live_sink

    calls: list[tuple] = []
    envelope = {
        "schema_version": "1.0",
        "scanner_version": "scanner-test",
        "cluster_id": "cluster-1",
        "snapshot_at": "2026-03-27T00:00:10Z",
        "last_seen_at": "2026-03-27T00:00:05Z",
        "fact_count": 2,
        "facts": [{"dedup_key": "a"}, {"dedup_key": "b"}],
    }

    monkeypatch.setattr(live_sink, "ENGINE_BASE_URL", "http://engine")
    monkeypatch.setattr(live_sink, "ENGINE_API_TOKEN", "secret-token")
    monkeypatch.setattr(
        live_sink,
        "_request_engine_upload_url",
        lambda: {
            "upload_url": "https://presigned.example/upload",
            "s3_key": "runtime/cluster-1/20260327T000010Z/events.json",
            "expires_in": 600,
        },
    )
    monkeypatch.setattr(
        live_sink,
        "_put_snapshot_to_presigned_url",
        lambda upload_url, payload: calls.append(("put", upload_url, payload["fact_count"])),
    )
    monkeypatch.setattr(
        live_sink,
        "_complete_engine_snapshot",
        lambda s3_key, snapshot_at, fact_count: calls.append(
            ("complete", s3_key, snapshot_at, fact_count)
        ),
    )
    monkeypatch.setattr(
        live_sink,
        "_write_snapshot_file",
        lambda payload: calls.append(("fallback", payload["fact_count"])),
    )

    live_sink.send_snapshot(envelope, allow_local_fallback=True)

    assert calls == [
        ("put", "https://presigned.example/upload", 2),
        ("complete", "runtime/cluster-1/20260327T000010Z/events.json", "2026-03-27T00:00:10Z", 2),
    ]


def test_send_snapshot_empty_success(monkeypatch) -> None:
    from forwarder import live_sink

    calls: list[tuple] = []
    envelope = {
        "schema_version": "1.0",
        "scanner_version": "scanner-test",
        "cluster_id": "cluster-1",
        "snapshot_at": "2026-03-27T00:00:10Z",
        "last_seen_at": None,
        "fact_count": 0,
        "facts": [],
    }

    monkeypatch.setattr(live_sink, "ENGINE_BASE_URL", "http://engine")
    monkeypatch.setattr(live_sink, "ENGINE_API_TOKEN", "secret-token")
    monkeypatch.setattr(
        live_sink,
        "_request_engine_upload_url",
        lambda: {
            "upload_url": "https://presigned.example/upload",
            "s3_key": "runtime/cluster-1/20260327T000010Z/events.json",
            "expires_in": 600,
        },
    )
    monkeypatch.setattr(
        live_sink,
        "_put_snapshot_to_presigned_url",
        lambda upload_url, payload: calls.append(("put", len(payload["facts"]))),
    )
    monkeypatch.setattr(
        live_sink,
        "_complete_engine_snapshot",
        lambda s3_key, snapshot_at, fact_count: calls.append(("complete", fact_count)),
    )
    monkeypatch.setattr(
        live_sink,
        "_write_snapshot_file",
        lambda payload: calls.append(("fallback", payload["fact_count"])),
    )

    live_sink.send_snapshot(envelope, allow_local_fallback=False)

    assert calls == [("put", 0), ("complete", 0)]


def test_send_snapshot_upload_url_failure_uses_local_fallback_only_for_non_empty(monkeypatch) -> None:
    from forwarder import live_sink

    fallback_counts: list[int] = []
    envelope = {
        "schema_version": "1.0",
        "scanner_version": "scanner-test",
        "cluster_id": "cluster-1",
        "snapshot_at": "2026-03-27T00:00:10Z",
        "last_seen_at": "2026-03-27T00:00:05Z",
        "fact_count": 1,
        "facts": [{"dedup_key": "a"}],
    }

    monkeypatch.setattr(live_sink, "ENGINE_BASE_URL", "http://engine")
    monkeypatch.setattr(live_sink, "ENGINE_API_TOKEN", "secret-token")
    monkeypatch.setattr(
        live_sink,
        "_request_engine_upload_url",
        lambda: (_ for _ in ()).throw(RuntimeError("upload-url failed")),
    )
    monkeypatch.setattr(
        live_sink,
        "_write_snapshot_file",
        lambda payload: fallback_counts.append(payload["fact_count"]),
    )

    live_sink.send_snapshot(envelope, allow_local_fallback=True)
    live_sink.send_snapshot({**envelope, "fact_count": 0, "facts": [], "last_seen_at": None}, allow_local_fallback=False)

    assert fallback_counts == [1]


def test_send_snapshot_put_failure_uses_local_fallback_for_non_empty(monkeypatch) -> None:
    from forwarder import live_sink

    fallback_counts: list[int] = []
    envelope = {
        "schema_version": "1.0",
        "scanner_version": "scanner-test",
        "cluster_id": "cluster-1",
        "snapshot_at": "2026-03-27T00:00:10Z",
        "last_seen_at": "2026-03-27T00:00:05Z",
        "fact_count": 2,
        "facts": [{"dedup_key": "a"}, {"dedup_key": "b"}],
    }

    monkeypatch.setattr(live_sink, "ENGINE_BASE_URL", "http://engine")
    monkeypatch.setattr(live_sink, "ENGINE_API_TOKEN", "secret-token")
    monkeypatch.setattr(
        live_sink,
        "_request_engine_upload_url",
        lambda: {
            "upload_url": "https://presigned.example/upload",
            "s3_key": "runtime/cluster-1/20260327T000010Z/events.json",
            "expires_in": 600,
        },
    )
    monkeypatch.setattr(
        live_sink,
        "_put_snapshot_to_presigned_url",
        lambda upload_url, payload: (_ for _ in ()).throw(RuntimeError("put failed")),
    )
    monkeypatch.setattr(
        live_sink,
        "_write_snapshot_file",
        lambda payload: fallback_counts.append(payload["fact_count"]),
    )

    live_sink.send_snapshot(envelope, allow_local_fallback=True)

    assert fallback_counts == [2]


def test_send_snapshot_complete_failure_does_not_trigger_reupload_or_fallback(monkeypatch) -> None:
    from forwarder import live_sink

    calls: list[tuple] = []
    envelope = {
        "schema_version": "1.0",
        "scanner_version": "scanner-test",
        "cluster_id": "cluster-1",
        "snapshot_at": "2026-03-27T00:00:10Z",
        "last_seen_at": "2026-03-27T00:00:05Z",
        "fact_count": 1,
        "facts": [{"dedup_key": "a"}],
    }

    monkeypatch.setattr(live_sink, "ENGINE_BASE_URL", "http://engine")
    monkeypatch.setattr(live_sink, "ENGINE_API_TOKEN", "secret-token")
    monkeypatch.setattr(
        live_sink,
        "_request_engine_upload_url",
        lambda: {
            "upload_url": "https://presigned.example/upload",
            "s3_key": "runtime/cluster-1/20260327T000010Z/events.json",
            "expires_in": 600,
        },
    )
    monkeypatch.setattr(
        live_sink,
        "_put_snapshot_to_presigned_url",
        lambda upload_url, payload: calls.append(("put", payload["fact_count"])),
    )
    monkeypatch.setattr(
        live_sink,
        "_complete_engine_snapshot",
        lambda s3_key, snapshot_at, fact_count: (_ for _ in ()).throw(RuntimeError("complete failed")),
    )
    monkeypatch.setattr(
        live_sink,
        "_write_snapshot_file",
        lambda payload: calls.append(("fallback", payload["fact_count"])),
    )

    live_sink.send_snapshot(envelope, allow_local_fallback=True)

    assert calls == [("put", 1)]


def test_runner_engine_s3_builds_one_envelope_per_cycle(monkeypatch) -> None:
    import runner

    now = datetime(2026, 3, 27, 0, 0, 0, tzinfo=timezone.utc)
    fact1 = _fact(
        dedup_key="a",
        observed_at=now - timedelta(seconds=10),
        collected_at=now + timedelta(seconds=5),
    )
    fact2 = _fact(
        dedup_key="b",
        observed_at=now - timedelta(seconds=2),
        collected_at=now + timedelta(seconds=8),
    )

    captured: dict = {}

    monkeypatch.setattr(runner, "FORWARD_MODE", "engine-s3")
    monkeypatch.setattr(runner, "CLUSTER_ID", "cluster-1")
    monkeypatch.setattr(runner, "SCANNER_VERSION", "scanner-test")
    monkeypatch.setattr(runner, "get_system_namespaces", lambda: set())
    monkeypatch.setattr(runner, "get_pod_meta", lambda: ({}, {}))
    monkeypatch.setattr(runner, "collect_tetragon_events", lambda: [])
    monkeypatch.setattr(runner, "collect_audit_events", lambda: [])
    monkeypatch.setattr(runner, "tetragon_normalize", lambda raw: None)
    monkeypatch.setattr(runner, "audit_normalize", lambda raw: None)
    monkeypatch.setattr(runner, "build_evidence_fact", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner, "_apply_suppression", lambda fact, pod_meta_map: False)
    monkeypatch.setattr(runner, "dispatch", lambda facts: captured.setdefault("dispatch_called", True))
    monkeypatch.setattr(
        runner,
        "send_snapshot",
        lambda envelope, allow_local_fallback: captured.update(
            {"envelope": envelope, "allow_local_fallback": allow_local_fallback}
        ),
    )
    monkeypatch.setattr(runner, "TETRAGON_ENABLED", False)
    monkeypatch.setattr(runner, "AUDIT_ENABLED", False)

    envelope = runner._build_snapshot_envelope([fact1, fact2])
    assert envelope == {
        "schema_version": "1.0",
        "scanner_version": "scanner-test",
        "cluster_id": "cluster-1",
        "snapshot_at": "2026-03-27T00:00:08Z",
        "last_seen_at": "2026-03-26T23:59:58Z",
        "fact_count": 2,
        "facts": [runner.serialize(fact1), runner.serialize(fact2)],
    }

    monkeypatch.setattr(runner, "_build_snapshot_envelope", lambda facts: envelope)
    monkeypatch.setattr(runner, "collect_tetragon_events", lambda: [])
    monkeypatch.setattr(runner, "collect_audit_events", lambda: [])
    monkeypatch.setattr(runner, "SAVE_RAW", False)
    monkeypatch.setattr(runner, "get_matcher", lambda: type("M", (), {"metrics_snapshot": lambda self: []})())

    runner.run()

    assert captured["envelope"] == envelope
    assert captured["allow_local_fallback"] is False
    assert "dispatch_called" not in captured


def test_runner_old_modes_keep_dispatch_path(monkeypatch) -> None:
    import runner

    calls: list[str] = []

    monkeypatch.setattr(runner, "FORWARD_MODE", "http-post")
    monkeypatch.setattr(runner, "get_system_namespaces", lambda: set())
    monkeypatch.setattr(runner, "get_pod_meta", lambda: ({}, {}))
    monkeypatch.setattr(runner, "collect_tetragon_events", lambda: [])
    monkeypatch.setattr(runner, "collect_audit_events", lambda: [])
    monkeypatch.setattr(runner, "SAVE_RAW", False)
    monkeypatch.setattr(runner, "TETRAGON_ENABLED", False)
    monkeypatch.setattr(runner, "AUDIT_ENABLED", False)
    monkeypatch.setattr(runner, "dispatch", lambda facts: calls.append("dispatch"))
    monkeypatch.setattr(
        runner,
        "send_snapshot",
        lambda envelope, allow_local_fallback: calls.append("snapshot"),
    )
    monkeypatch.setattr(runner, "get_matcher", lambda: type("M", (), {"metrics_snapshot": lambda self: []})())

    runner.run()

    assert calls == ["dispatch"]
