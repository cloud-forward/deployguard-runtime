import uuid
from datetime import datetime, timezone
from schemas.normalized_event import NormalizedEvent, EventSource, EventCategory, WorkloadContext
from config.loader import get_system_users


def _parse_service_account(username: str) -> str | None:
    """
    'system:serviceaccount:<namespace>:<sa-name>' 형태에서 SA 이름만 추출.
    일반 유저면 None 반환.
    """
    if "serviceaccount" not in username:
        return None
    parts = username.split(":")
    # system:serviceaccount:namespace:sa-name → index 3
    return parts[3] if len(parts) >= 4 else parts[-1]


def normalize(raw: dict) -> NormalizedEvent | None:
    if raw.get("kind") != "Event":
        return None

    obj    = raw.get("objectRef", {})
    user   = raw.get("user", {})
    status = raw.get("responseStatus", {})
    source = raw.get("source", {})

    # 타임스탬프
    ts_str = raw.get("requestReceivedTimestamp") or raw.get("stageTimestamp")
    timestamp = (
        datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        if ts_str
        else datetime.now(timezone.utc)
    )

    # 시스템 유저 필터링
    username     = user.get("username", "")
    system_users = get_system_users()
    if any(username.startswith(u) for u in system_users):
        return None

    sa = _parse_service_account(username)

    # pod exec 여부
    subresource = obj.get("subresource")
    resource    = obj.get("resource", "")
    is_pod_exec = resource == "pods" and subresource == "exec"

    return NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=timestamp,
        source=EventSource.K8S_AUDIT,
        category=EventCategory.K8S_API,
        actor=WorkloadContext(
            namespace=obj.get("namespace"),
            pod_name=obj.get("name") if resource == "pods" else None,
            service_account=sa,
            node_name=source.get("host"),      # audit 이벤트의 노드 정보
        ),
        action=raw.get("verb", ""),
        target=obj.get("name"),
        target_resource=resource,
        target_namespace=obj.get("namespace"),
        success=status.get("code", 0) < 400,
        response_code=status.get("code"),
        raw=raw,
    )
