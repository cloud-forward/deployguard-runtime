"""
fact_builder/enricher.py

[Layer 2 → Layer 3 전처리] NormalizedRuntimeEvent 보강 단계.

역할:
  - pod_uid / container_id / workload_name / workload_kind / workload_uid / image_ref
    같은 graph join 식별자를 kubectl 또는 캐시에서 주입
  - static scanner 결과와 join 가능한 correlation_keys 구성
  - cloud_identity (IRSA role ARN 등) 주입

이 단계는 선택적이며 실패해도 파이프라인을 중단하지 않는다.
"""

from __future__ import annotations

import logging
from typing import Optional

from schemas.normalized_event import NormalizedRuntimeEvent, WorkloadContext

log = logging.getLogger(__name__)


def enrich(
    event:      NormalizedRuntimeEvent,
    pod_meta_map: dict,              # {ns/pod_name → PodMeta}
    owner_map:  Optional[dict] = None,  # {ns/pod_name → OwnerRef}
) -> NormalizedRuntimeEvent:
    """
    event.actor 를 보강하여 반환.
    실패 시 원본 그대로 반환 (non-blocking).
    """
    try:
        actor   = event.actor
        ns      = actor.namespace or ""
        pod     = actor.pod_name or ""
        key     = f"{ns}/{pod}"

        meta    = pod_meta_map.get(key, {})
        owner   = (owner_map or {}).get(key, {})

        enriched = WorkloadContext(
            namespace=      actor.namespace,
            pod_name=       actor.pod_name,
            pod_uid=        actor.pod_uid or meta.get("pod_uid"),
            container_name= actor.container_name,
            container_id=   actor.container_id or meta.get("container_id"),
            service_account=actor.service_account or meta.get("service_account"),
            node_name=      actor.node_name or meta.get("node_name"),
            workload_name=  actor.workload_name or owner.get("name"),
            workload_kind=  actor.workload_kind or owner.get("kind"),
            workload_uid=   actor.workload_uid or owner.get("uid"),
            cloud_identity= actor.cloud_identity or meta.get("cloud_identity"),
            image_ref=      actor.image_ref or meta.get("image_ref"),
        )

        return event.model_copy(update={"actor": enriched})

    except Exception as e:
        log.warning(f"enrich 실패 (원본 사용): {e}")
        return event


def build_pod_meta_map(kubectl_pods_json: dict) -> dict:
    """
    kubectl get pods --all-namespaces -o json → pod_meta_map 빌드.

    반환 형식:
      { "namespace/pod_name": {
            "pod_uid":        str,
            "service_account":str,
            "node_name":      str,
            "image_ref":      str,    # 첫 번째 컨테이너
            "container_id":   str,    # 첫 번째 컨테이너 (prefix 제거)
            "cloud_identity": str,    # eks.amazonaws.com/role-arn annotation
        }
      }
    """
    mapping: dict = {}
    for item in kubectl_pods_json.get("items", []):
        meta   = item.get("metadata", {})
        spec   = item.get("spec", {})
        status = item.get("status", {})
        ns     = meta.get("namespace", "")
        name   = meta.get("name", "")
        key    = f"{ns}/{name}"

        # 첫 번째 컨테이너 이미지 / container_id
        containers        = spec.get("containers", [])
        container_statuses= status.get("containerStatuses", [])
        image_ref = containers[0].get("image", "") if containers else ""
        raw_cid   = (container_statuses[0].get("containerID", "")
                     if container_statuses else "")
        # "containerd://abc123..." → "abc123..."
        container_id = raw_cid.split("://")[-1] if "://" in raw_cid else raw_cid

        # IRSA role annotation
        annotations   = meta.get("annotations", {})
        cloud_identity= annotations.get(
            "eks.amazonaws.com/role-arn",
            annotations.get("iam.amazonaws.com/role", ""),
        )

        # ServiceAccount annotation의 role-arn 도 체크 (SA-level IRSA)
        sa_annotations = (
            item.get("spec", {})
            .get("serviceAccountAnnotations", {})
        )
        if not cloud_identity:
            cloud_identity = sa_annotations.get("eks.amazonaws.com/role-arn", "")

        mapping[key] = {
            "pod_uid":         meta.get("uid", ""),
            "service_account": spec.get("serviceAccountName", ""),
            "node_name":       spec.get("nodeName", ""),
            "image_ref":       image_ref,
            "container_id":    container_id,
            "cloud_identity":  cloud_identity or None,
        }

    return mapping


def build_owner_map(kubectl_pods_json: dict) -> dict:
    """
    ownerReferences에서 workload (Deployment / ReplicaSet / DaemonSet 등) 정보 추출.

    반환 형식:
      { "namespace/pod_name": {"kind": str, "name": str, "uid": str} }

    주의: Pod → ReplicaSet → Deployment 2단계 추적은 지원하지 않음.
    필요 시 별도 owner_chain_resolver 추가.
    """
    mapping: dict = {}
    for item in kubectl_pods_json.get("items", []):
        meta  = item.get("metadata", {})
        ns    = meta.get("namespace", "")
        name  = meta.get("name", "")
        key   = f"{ns}/{name}"
        owners= meta.get("ownerReferences", [])
        if owners:
            owner = owners[0]  # 보통 하나
            mapping[key] = {
                "kind": owner.get("kind", ""),
                "name": owner.get("name", ""),
                "uid":  owner.get("uid", ""),
            }
    return mapping
