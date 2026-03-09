import uuid
from datetime import datetime
from schemas.normalized_event import NormalizedEvent, EventSource, EventCategory, WorkloadContext

SA_TOKEN_PATHS = ["/var/run/secrets/kubernetes.io/serviceaccount"]
SENSITIVE_PATHS = ["/proc/1", "/etc/shadow", "/etc/kubernetes", "/var/lib/kubelet"]
SUSPICIOUS_BINARIES = ["/curl", "/nmap", "/nsenter", "/bash", "/sh", "/wget", "/python", "/nc"]


def _parse_timestamp(ts: str) -> datetime:
    return datetime.fromisoformat(
        ts.replace("Z", "+00:00")[:26] + "+00:00"
        if "." in ts else ts.replace("Z", "+00:00")
    )


def _get_process_info(process: dict) -> tuple:
    pod = process.get("pod", {})
    return pod, WorkloadContext(
        namespace=pod.get("namespace"),
        pod_name=pod.get("name"),
        container_name=pod.get("container", {}).get("name"),
        node_name=process.get("node_name"),
    )


def normalize(raw: dict) -> NormalizedEvent | None:

    # process_kprobe (파일/네트워크 접근)
    kprobe = raw.get("process_kprobe")
    if kprobe:
        process = kprobe.get("process", {})
        _, actor = _get_process_info(process)
        func = kprobe.get("function_name", "")
        args = kprobe.get("args", [])
        timestamp = raw.get("time", datetime.utcnow().isoformat())

        if func in ("sys_open", "sys_openat", "security_file_open"):
            category = EventCategory.FILE
            action = "open"
            target = next((a["file_arg"]["path"] for a in args if "file_arg" in a), None)
        elif func == "tcp_connect":
            category = EventCategory.NETWORK
            action = "connect"
            sock = next((a["sock_arg"] for a in args if "sock_arg" in a), {})
            target = sock.get("daddr")
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
        _, actor = _get_process_info(process)
        timestamp = raw.get("time", datetime.utcnow().isoformat())
        binary = process.get("binary", "")
        arguments = process.get("arguments", "")

        # arguments에서 파일 접근 패턴 감지
        if any(p in arguments for p in SA_TOKEN_PATHS):
            category = EventCategory.FILE
            action = "open"
            target = "/var/run/secrets/kubernetes.io/serviceaccount/token"

        elif any(p in arguments for p in SENSITIVE_PATHS):
            category = EventCategory.FILE
            action = "open"
            target = arguments

        # binary에서 의심 프로세스 감지
        elif any(binary.endswith(b) for b in SUSPICIOUS_BINARIES):
            category = EventCategory.PROCESS
            action = "exec"
            target = binary

        else:
            category = EventCategory.PROCESS
            action = "exec"
            target = binary

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