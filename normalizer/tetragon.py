import uuid
from datetime import datetime
from schemas.normalized_event import NormalizedEvent, EventSource, EventCategory, WorkloadContext


def normalize(raw: dict) -> NormalizedEvent | None:
    kprobe = raw.get("process_kprobe")
    if not kprobe:
        return None

    process = kprobe.get("process", {})
    pod = process.get("pod", {})
    func = kprobe.get("function_name", "")
    args = kprobe.get("args", [])
    timestamp = kprobe.get("time", datetime.utcnow().isoformat())

    # 카테고리 + action + target 결정
    if func in ("sys_open", "sys_openat"):
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
        timestamp=datetime.fromisoformat(timestamp.replace("Z", "+00:00")),
        source=EventSource.TETRAGON,
        category=category,
        actor=WorkloadContext(
            namespace=pod.get("namespace"),
            pod_name=pod.get("name"),
            container_name=pod.get("container", {}).get("name"),
            node_name=process.get("node_name"),
        ),
        action=action,
        target=target,
        raw=raw,
    )