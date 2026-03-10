import uuid
from datetime import datetime
from schemas.normalized_event import NormalizedEvent, EventSource, EventCategory, WorkloadContext
from config.loader import get_system_users


def normalize(raw: dict) -> NormalizedEvent | None:
    if raw.get("kind") != "Event":
        return None

    obj = raw.get("objectRef", {})
    user = raw.get("user", {})
    status = raw.get("responseStatus", {})
    timestamp = raw.get("requestReceivedTimestamp", datetime.utcnow().isoformat())

    # 시스템 유저 필터링
    username = user.get("username", "")
    system_users = get_system_users()
    if any(username.startswith(u) for u in system_users):
        return None

    # service account 파싱
    sa = username.split(":")[-1] if "serviceaccount" in username else None

    return NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.fromisoformat(timestamp.replace("Z", "+00:00")),
        source=EventSource.K8S_AUDIT,
        category=EventCategory.K8S_API,
        actor=WorkloadContext(
            namespace=obj.get("namespace"),
            pod_name=obj.get("name") if obj.get("resource") == "pods" else None,
            service_account=sa,
        ),
        action=raw.get("verb", ""),
        target=obj.get("name"),
        target_resource=obj.get("resource"),
        target_namespace=obj.get("namespace"),
        success=status.get("code", 0) < 400,
        response_code=status.get("code"),
        raw=raw,
    )