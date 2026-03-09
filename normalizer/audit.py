import uuid
from datetime import datetime
from schemas.normalized_event import NormalizedEvent, EventSource, EventCategory, WorkloadContext


def normalize(raw: dict) -> NormalizedEvent | None:
    if raw.get("kind") != "Event":
        return None

    obj = raw.get("objectRef", {})
    user = raw.get("user", {})
    status = raw.get("responseStatus", {})
    timestamp = raw.get("requestReceivedTimestamp", datetime.utcnow().isoformat())

    # service account 파싱
    # "system:serviceaccount:default:api-sa" → "api-sa"
    username = user.get("username", "")
    sa = username.split(":")[-1] if "serviceaccount" in username else None

    return NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.fromisoformat(timestamp.replace("Z", "+00:00")),
        source=EventSource.K8S_AUDIT,
        category=EventCategory.K8S_API,
        actor=WorkloadContext(
            namespace=obj.get("namespace"),
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