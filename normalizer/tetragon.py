import uuid
from datetime import datetime, timezone
from schemas.normalized_event import NormalizedEvent, EventSource, EventCategory, WorkloadContext
from config.loader import (
    get_sa_token_paths,
    get_sensitive_paths,
    get_suspicious_binaries,
    get_file_open_functions,
    get_network_connect_functions,
)


def _parse_timestamp(ts: str) -> datetime:
    """
    Tetragon 타임스탬프를 파싱.
    - "2024-01-01T12:00:00Z"
    - "2024-01-01T12:00:00.123456Z"
    - "2024-01-01T12:00:00.123456789Z"  (nanosecond → microsecond truncate)
    모두 처리.
    """
    # Z → +00:00 치환
    ts = ts.replace("Z", "+00:00")

    # 나노초(9자리)는 fromisoformat이 파싱 못 함 → 마이크로초(6자리)로 잘라냄
    if "." in ts:
        dot_pos = ts.index(".")
        plus_pos = ts.index("+", dot_pos)
        frac = ts[dot_pos + 1:plus_pos]
        if len(frac) > 6:
            ts = ts[:dot_pos + 1] + frac[:6] + ts[plus_pos:]

    return datetime.fromisoformat(ts)


def _get_process_info(process: dict, raw: dict) -> WorkloadContext:
    pod = process.get("pod", {})
    return WorkloadContext(
        namespace=pod.get("namespace"),
        pod_name=pod.get("name"),
        container_name=pod.get("container", {}).get("name"),
        node_name=raw.get("node_name"),
        service_account=pod.get("serviceAccountName"),
    )


def normalize(raw: dict) -> NormalizedEvent | None:
    # ── process_kprobe (파일 / 네트워크 접근) ────────────────────────
    kprobe = raw.get("process_kprobe")
    if kprobe:
        process   = kprobe.get("process", {})
        actor     = _get_process_info(process, raw)
        func      = kprobe.get("function_name", "")
        args      = kprobe.get("args", [])
        timestamp = raw.get("time", datetime.now(timezone.utc).isoformat())

        file_open_funcs    = get_file_open_functions()
        net_connect_funcs  = get_network_connect_functions()

        if func in file_open_funcs:
            target = next((a["string_arg"] for a in args if "string_arg" in a), None)
            return NormalizedEvent(
                event_id=str(uuid.uuid4()),
                timestamp=_parse_timestamp(timestamp),
                source=EventSource.TETRAGON,
                category=EventCategory.FILE,
                actor=actor,
                action="open",
                target=target,
                raw=raw,
            )

        if func in net_connect_funcs:
            sock   = next((a["sock_arg"] for a in args if "sock_arg" in a), {})
            daddr  = sock.get("daddr")
            return NormalizedEvent(
                event_id=str(uuid.uuid4()),
                timestamp=_parse_timestamp(timestamp),
                source=EventSource.TETRAGON,
                category=EventCategory.NETWORK,
                actor=actor,
                action="connect",
                target=daddr,
                raw=raw,
            )

        # 위 두 분류에 해당 안 되는 kprobe → PROCESS 로 분류
        return NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=_parse_timestamp(timestamp),
            source=EventSource.TETRAGON,
            category=EventCategory.PROCESS,
            actor=actor,
            action=func,
            target=None,
            raw=raw,
        )

    # ── process_exec (프로세스 실행) ─────────────────────────────────
    exec_event = raw.get("process_exec")
    if exec_event:
        process   = exec_event.get("process", {})
        actor     = _get_process_info(process, raw)
        timestamp = raw.get("time", datetime.now(timezone.utc).isoformat())
        binary    = process.get("binary", "")
        arguments = process.get("arguments", "")

        suspicious_binaries = get_suspicious_binaries()
        sa_token_paths      = get_sa_token_paths()
        sensitive_paths     = get_sensitive_paths()

        # 1순위: 의심 바이너리 실행
        if any(binary.endswith(b) for b in suspicious_binaries):
            return NormalizedEvent(
                event_id=str(uuid.uuid4()),
                timestamp=_parse_timestamp(timestamp),
                source=EventSource.TETRAGON,
                category=EventCategory.PROCESS,
                actor=actor,
                action="exec",
                target=binary,
                raw=raw,
            )

        # 2순위: SA token 경로가 arguments에 포함
        matched_sa = next((p for p in sa_token_paths if p in arguments), None)
        if matched_sa:
            return NormalizedEvent(
                event_id=str(uuid.uuid4()),
                timestamp=_parse_timestamp(timestamp),
                source=EventSource.TETRAGON,
                category=EventCategory.FILE,
                actor=actor,
                action="open",
                target=matched_sa + "/token",
                raw=raw,
            )

        # 3순위: 민감 경로가 arguments에 포함
        matched_sensitive = next((p for p in sensitive_paths if p in arguments), None)
        if matched_sensitive:
            return NormalizedEvent(
                event_id=str(uuid.uuid4()),
                timestamp=_parse_timestamp(timestamp),
                source=EventSource.TETRAGON,
                category=EventCategory.FILE,
                actor=actor,
                action="open",
                target=matched_sensitive,
                raw=raw,
            )

        # 해당 없음 → 정상 프로세스로 간주, 버림
        return None

    return None
