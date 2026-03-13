"""
normalizer/tetragon.py

[Layer 1 → Layer 2] Tetragon 이벤트 → NormalizedRuntimeEvent 변환.

변경 사항:
  - source_native_event_id = exec_id (절대 버리지 않음)
  - file/network/process 이벤트별 raw_excerpt 생성
  - process.binary / arguments / exec_id / pod context / destination/path 보존
  - graph correlation 필요 pod/workload context 최대 보존
  - container_id / image_ref 추가 보존
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional, Tuple

from schemas.normalized_event import (
    NormalizedRuntimeEvent,
    EventSource,
    EventCategory,
    WorkloadContext,
)
from config.loader import (
    get_sa_token_paths,
    get_sensitive_paths,
    get_suspicious_binaries,
    get_file_open_functions,
    get_network_connect_functions,
)


# ── 타임스탬프 파서 ───────────────────────────────────────────────────

def _parse_timestamp(ts: str) -> datetime:
    """
    Tetragon 타임스탬프 파싱.
    nanosecond(9자리) → microsecond(6자리) truncate.
    """
    ts = ts.replace("Z", "+00:00")
    if "." in ts:
        dot_pos  = ts.index(".")
        plus_pos = ts.index("+", dot_pos)
        frac     = ts[dot_pos + 1:plus_pos]
        if len(frac) > 6:
            ts = ts[:dot_pos + 1] + frac[:6] + ts[plus_pos:]
    return datetime.fromisoformat(ts)


# ── WorkloadContext 추출 ──────────────────────────────────────────────

def _get_workload_context(process: dict, raw: dict) -> WorkloadContext:
    """
    Tetragon process 블록에서 WorkloadContext 추출.
    container_id / image_ref / pod_uid 도 최대한 보존.
    """
    pod       = process.get("pod", {})
    container = pod.get("container", {})
    image     = container.get("image", {})

    return WorkloadContext(
        namespace=pod.get("namespace"),
        pod_name=pod.get("name"),
        pod_uid=pod.get("pod_uid"),                       # graph node join
        container_name=container.get("name"),
        container_id=container.get("id"),                 # containerd ID
        service_account=pod.get("serviceAccountName"),
        node_name=raw.get("node_name"),
        image_ref=image.get("id") or image.get("name"),  # image digest or tag
    )


# ── raw_excerpt 빌더 ──────────────────────────────────────────────────

def _build_file_excerpt(process: dict, func: str, path: Optional[str], raw: dict) -> dict:
    return {
        "event_type":   "file",
        "function":     func,
        "path":         path,
        "exec_id":      process.get("exec_id"),
        "binary":       process.get("binary"),
        "arguments":    process.get("arguments"),
        "pid":          process.get("pid"),
        "node_name":    raw.get("node_name"),
    }


def _build_network_excerpt(process: dict, sock: dict, raw: dict) -> dict:
    return {
        "event_type":   "network",
        "function":     "tcp_connect",
        "dest_addr":    sock.get("daddr"),
        "dest_port":    sock.get("dport"),
        "src_addr":     sock.get("saddr"),
        "src_port":     sock.get("sport"),
        "exec_id":      process.get("exec_id"),
        "binary":       process.get("binary"),
        "node_name":    raw.get("node_name"),
    }


def _build_process_excerpt(process: dict, func: str, raw: dict) -> dict:
    return {
        "event_type":   "process",
        "function":     func,
        "exec_id":      process.get("exec_id"),
        "binary":       process.get("binary"),
        "arguments":    process.get("arguments"),
        "pid":          process.get("pid"),
        "node_name":    raw.get("node_name"),
    }


def _build_exec_excerpt(process: dict, raw: dict) -> dict:
    return {
        "event_type":   "exec",
        "exec_id":      process.get("exec_id"),
        "binary":       process.get("binary"),
        "arguments":    process.get("arguments"),
        "pid":          process.get("pid"),
        "uid":          process.get("uid"),
        "cwd":          process.get("cwd"),
        "node_name":    raw.get("node_name"),
    }


# ── 메인 normalizer ───────────────────────────────────────────────────

def normalize(raw: dict) -> Optional[NormalizedRuntimeEvent]:
    """
    Tetragon JSON → NormalizedRuntimeEvent.
    내부 호환성을 위해 (event, excerpt) 대신 event만 반환.
    fact_builder는 normalize_with_excerpt() 사용.
    """
    result = normalize_with_excerpt(raw)
    return result[0] if result else None


def normalize_with_excerpt(
    raw: dict,
) -> Optional[Tuple[NormalizedRuntimeEvent, dict]]:
    """
    (NormalizedRuntimeEvent, raw_excerpt) 튜플 반환.
    None 반환 시 해당 이벤트는 처리 대상 아님.
    """

    # ── process_kprobe ────────────────────────────────────────────────
    kprobe = raw.get("process_kprobe")
    if kprobe:
        process   = kprobe.get("process", {})
        actor     = _get_workload_context(process, raw)
        func      = kprobe.get("function_name", "")
        args      = kprobe.get("args", [])
        ts_str    = raw.get("time", datetime.now(timezone.utc).isoformat())
        timestamp = _parse_timestamp(ts_str)

        # source_native_event_id = exec_id
        exec_id = process.get("exec_id")

        file_open_funcs   = get_file_open_functions()
        net_connect_funcs = get_network_connect_functions()

        # FILE 이벤트
        if func in file_open_funcs:
            path    = next((a["string_arg"] for a in args if "string_arg" in a), None)
            excerpt = _build_file_excerpt(process, func, path, raw)
            event   = NormalizedRuntimeEvent(
                scanner_event_id=str(uuid.uuid4()),
                source_native_event_id=exec_id,
                timestamp=timestamp,
                source=EventSource.TETRAGON,
                category=EventCategory.FILE,
                actor=actor,
                action="open",
                target=path,
                raw=raw,
            )
            return event, excerpt

        # NETWORK 이벤트
        if func in net_connect_funcs:
            sock    = next((a["sock_arg"] for a in args if "sock_arg" in a), {})
            daddr   = sock.get("daddr")
            excerpt = _build_network_excerpt(process, sock, raw)
            event   = NormalizedRuntimeEvent(
                scanner_event_id=str(uuid.uuid4()),
                source_native_event_id=exec_id,
                timestamp=timestamp,
                source=EventSource.TETRAGON,
                category=EventCategory.NETWORK,
                actor=actor,
                action="connect",
                target=daddr,
                raw=raw,
            )
            return event, excerpt

        # 분류 안 되는 kprobe → PROCESS로 분류 (버리지 않음)
        excerpt = _build_process_excerpt(process, func, raw)
        event   = NormalizedRuntimeEvent(
            scanner_event_id=str(uuid.uuid4()),
            source_native_event_id=exec_id,
            timestamp=timestamp,
            source=EventSource.TETRAGON,
            category=EventCategory.PROCESS,
            actor=actor,
            action=func,
            target=None,
            raw=raw,
        )
        return event, excerpt

    # ── process_exec ──────────────────────────────────────────────────
    exec_event = raw.get("process_exec")
    if exec_event:
        process   = exec_event.get("process", {})
        actor     = _get_workload_context(process, raw)
        ts_str    = raw.get("time", datetime.now(timezone.utc).isoformat())
        timestamp = _parse_timestamp(ts_str)
        binary    = process.get("binary", "")
        arguments = process.get("arguments", "")
        exec_id   = process.get("exec_id")

        suspicious_binaries = get_suspicious_binaries()
        sa_token_paths      = get_sa_token_paths()
        sensitive_paths     = get_sensitive_paths()

        # 1순위: 의심 바이너리 실행
        if any(binary.endswith(b) for b in suspicious_binaries):
            excerpt = _build_exec_excerpt(process, raw)
            event   = NormalizedRuntimeEvent(
                scanner_event_id=str(uuid.uuid4()),
                source_native_event_id=exec_id,
                timestamp=timestamp,
                source=EventSource.TETRAGON,
                category=EventCategory.PROCESS,
                actor=actor,
                action="exec",
                target=binary,
                raw=raw,
            )
            return event, excerpt

        # 2순위: arguments에 SA token 경로 포함
        matched_sa = next((p for p in sa_token_paths if p in arguments), None)
        if matched_sa:
            excerpt = _build_exec_excerpt(process, raw)
            event   = NormalizedRuntimeEvent(
                scanner_event_id=str(uuid.uuid4()),
                source_native_event_id=exec_id,
                timestamp=timestamp,
                source=EventSource.TETRAGON,
                category=EventCategory.FILE,
                actor=actor,
                action="open",
                target=matched_sa + "/token",
                raw=raw,
            )
            return event, excerpt

        # 3순위: arguments에 민감 경로 포함
        matched_sensitive = next((p for p in sensitive_paths if p in arguments), None)
        if matched_sensitive:
            excerpt = _build_exec_excerpt(process, raw)
            event   = NormalizedRuntimeEvent(
                scanner_event_id=str(uuid.uuid4()),
                source_native_event_id=exec_id,
                timestamp=timestamp,
                source=EventSource.TETRAGON,
                category=EventCategory.FILE,
                actor=actor,
                action="open",
                target=matched_sensitive,
                raw=raw,
            )
            return event, excerpt

        # 해당 없음 → None (정상 프로세스)
        return None

    return None
