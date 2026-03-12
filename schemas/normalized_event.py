from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from enum import Enum


class EventSource(str, Enum):
    TETRAGON  = "tetragon"
    K8S_AUDIT = "k8s_audit"


class EventCategory(str, Enum):
    PROCESS = "process"
    FILE    = "file"
    NETWORK = "network"
    K8S_API = "k8s_api"


class WorkloadContext(BaseModel):
    cluster:        Optional[str] = None
    namespace:      Optional[str] = None
    pod_name:       Optional[str] = None
    node_name:      Optional[str] = None
    container_name: Optional[str] = None
    service_account: Optional[str] = None
    workload_name:  Optional[str] = None
    workload_kind:  Optional[str] = None


class NormalizedEvent(BaseModel):
    event_id:         str
    timestamp:        datetime
    source:           EventSource
    category:         EventCategory
    actor:            WorkloadContext
    action:           str
    target:           Optional[str] = None
    target_resource:  Optional[str] = None
    target_namespace: Optional[str] = None
    success:          Optional[bool] = None
    response_code:    Optional[int]  = None
    raw:              Optional[dict] = None
