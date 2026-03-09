from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from enum import Enum


class EvidenceType(str, Enum):
    ACCESSED_SA_TOKEN           = "ACCESSED_SA_TOKEN"
    KUBE_API_ACCESS             = "KUBE_API_ACCESS"
    SUSPICIOUS_EXECUTION        = "SUSPICIOUS_EXECUTION"
    ACCESSED_IMDS               = "ACCESSED_IMDS"
    ACCESSED_HOST_SENSITIVE_PATH = "ACCESSED_HOST_SENSITIVE_PATH"
    READ_SECRET                 = "READ_SECRET"
    LIST_SECRET                 = "LIST_SECRET"
    CREATED_CRONJOB             = "CREATED_CRONJOB"
    CREATED_DAEMONSET           = "CREATED_DAEMONSET"
    CREATED_ROLEBINDING         = "CREATED_ROLEBINDING"
    POD_EXEC_REQUEST            = "POD_EXEC_REQUEST"


class PathVerdict(str, Enum):
    PATH_POSSIBLE               = "PATH_POSSIBLE"
    PATH_OBSERVED               = "PATH_OBSERVED"
    PATH_PARTIALLY_CONFIRMED    = "PATH_PARTIALLY_CONFIRMED"
    PERSISTENCE_OBSERVED        = "PERSISTENCE_OBSERVED"
    EXPANSION_ATTEMPT_OBSERVED  = "EXPANSION_ATTEMPT_OBSERVED"


class Evidence(BaseModel):
    evidence_id: str
    evidence_type: EvidenceType
    timestamp: datetime
    namespace: Optional[str] = None
    pod_name: Optional[str] = None
    service_account: Optional[str] = None
    node_name: Optional[str] = None
    detail: Optional[dict] = None
    source_event_id: Optional[str] = None
    source: Optional[str] = None


class AttackPathState(BaseModel):
    path_id: str
    scenario: str
    verdict: PathVerdict
    evidences: List[Evidence] = Field(default_factory=list)
    last_updated: Optional[datetime] = None
    verdict_reason: Optional[str] = None