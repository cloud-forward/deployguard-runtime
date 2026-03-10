import uuid
from datetime import datetime
from schemas.normalized_event import NormalizedEvent, EventSource, EventCategory, WorkloadContext
from config.loader import get_tetragon_rules


def _parse_timestamp(ts: str) -> datetime:
    return datetime.fromisoformat(
        ts.replace("Z", "+00:00")[:26] + "+00:00"
        if "." in ts else ts.replace("Z", "+00:00")
    )


def _get_process_info(process: dict, raw: dict) -> tuple:
    pod = process.get("pod", {})
    sa_name = pod.get("serviceAccountName", None)
    return pod, WorkloadContext(
        namespace=pod.get("namespace"),
        pod_name=pod.get("name"),
        container_name=pod.get("container", {}).get("name"),
        node_name=raw.get("node_name"),
        service_account=sa_name,
    )


def normalize(raw: dict) -> NormalizedEvent | None:
    rules = get_tetragon_rules()
    sa_token_paths = rules.get("sa_token_paths", [])
    sensitive_paths = rules.get("sensitive_paths", [])
    suspicious_binaries = rules.get("suspicious_binaries", [])
    imds_addresses = rules.get("imds_addresses", [])

    # process_kprobe (파일/네트워크 접근)
    kprobe = raw.get("process_kprobe")
    if kprobe:
        process = kprobe.get("process", {})
        _, actor = _get_process_info(process, raw)
        func = kprobe.get("function_name", "")
        args = kprobe.get("args", [])
        timestamp = raw.get("time", datetime.utcnow().isoformat())

        if func in ("__x64_sys_openat", "sys_open", "sys_openat", "security_file_open"):
            category = EventCategory.FILE
            action = "open"
            target = next((a["string_arg"] for a in args if "string_arg" in a), None)

        elif func == "tcp_connect":
            sock = next((a["sock_arg"] for a in args if "sock_arg" in a), {})
            daddr = sock.get("daddr")
            category = EventCategory.NETWORK
            action = "connect"
            target = daddr

        else:
            category = EventCategory.PROCESS
            action = func
            target = None

        return NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=_parse_timestamp(timestamp),
            source=EventSource.TETRAGON,
            category=category,
            actor=actor,
            action=action,
            target=target,
            raw=raw,
        )

    # process_exec (프로세스 실행)
    exec_event = raw.get("process_exec")
    if exec_event:
        process = exec_event.get("process", {})
        _, actor = _get_process_info(process, raw)
        timestamp = raw.get("time", datetime.utcnow().isoformat())
        binary = process.get("binary", "")
        arguments = process.get("arguments", "")

        # 1순위: suspicious binary 먼저 체크
        if any(binary.endswith(b) for b in suspicious_binaries):
            category = EventCategory.PROCESS
            action = "exec"
            target = binary

        # 2순위: SA token 경로가 arguments에 있으면
        elif any(p in arguments for p in sa_token_paths):
            category = EventCategory.FILE
            action = "open"
            target = "/var/run/secrets/kubernetes.io/serviceaccount/token"

        # 3순위: 민감 경로가 arguments에 있으면
        elif any(p in arguments for p in sensitive_paths):
            category = EventCategory.FILE
            action = "open"
            target = arguments

        # 나머지는 그냥 버려 (정상 프로세스)
        else:
            return None

        return NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=_parse_timestamp(timestamp),
            source=EventSource.TETRAGON,
            category=category,
            actor=actor,
            action=action,
            target=target,
            raw=raw,
        )

    return None