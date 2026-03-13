"""
fact_builder/enricher.py

[Layer 2 → Layer 3 전처리] NormalizedRuntimeEvent 보강 단계.

변경 사항 (suppression 지원):
  - build_pod_meta_map()이 labels / annotations도 함께 수집
  - get_workload_labels() / get_workload_annotations() 추가
  - suppression matcher가 workload_labels를 직접 참조 가능
"""

from __future__ import annotations

import logging
from typing import Optional

from schemas.normalized_event import NormalizedRuntimeEvent, WorkloadContext

log = logging.getLogger(__name__)


# ── enrich ────────────────────────────────────────────────────────────

def enrich(
    event:        NormalizedRuntimeEvent,
    pod_meta_map: dict,
    owner_map:    Optional[dict] = None,
) -> NormalizedRuntimeEvent:
    """
    event.actor 를 보강하여 반환.
    실패 시 원본 그대로 반환 (non-blocking).
    """
    try:
        actor = event.actor
        key   = f"{actor.namespace or ''}/{actor.pod_name or ''}"
        meta  = pod_meta_map.get(key, {})
        owner = (owner_map or {}).get(key, {})

        enriched = WorkloadContext(
            namespace=       actor.namespace,
            pod_name=        actor.pod_name,
            pod_uid=         actor.pod_uid         or meta.get("pod_uid"),
            container_name=  actor.container_name,
            container_id=    actor.container_id    or meta.get("container_id"),
            service_account= actor.service_account or meta.get("service_account"),
            node_name=       actor.node_name       or meta.get("node_name"),
            workload_name=   actor.workload_name   or owner.get("name"),
            workload_kind=   actor.workload_kind   or owner.get("kind"),
            workload_uid=    actor.workload_uid    or owner.get("uid"),
            cloud_identity=  actor.cloud_identity  or meta.get("cloud_identity"),
            image_ref=       actor.image_ref       or meta.get("image_ref"),
        )
        return event.model_copy(update={"actor": enriched})

    except Exception as e:
        log.warning(f"enrich 실패 (원본 사용): {e}")
        return event


# ── pod_meta_map 빌더 ─────────────────────────────────────────────────

def build_pod_meta_map(kubectl_pods_json: dict) -> dict:
    """
    kubectl get pods --all-namespaces -o json → pod_meta_map 빌드.

    반환 형식:
      { "namespace/pod_name": {
            "pod_uid":        str,
            "service_account":str,
            "node_name":      str,
            "image_ref":      str,
            "container_id":   str,
            "cloud_identity": str | None,
            "labels":         dict[str, str],   ← suppression 매칭에 사용
            "annotations":    dict[str, str],   ← suppression 매칭에 사용
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

        containers         = spec.get("containers", [])
        container_statuses = status.get("containerStatuses", [])
        image_ref  = containers[0].get("image", "") if containers else ""
        raw_cid    = (container_statuses[0].get("containerID", "")
                      if container_statuses else "")
        container_id = raw_cid.split("://")[-1] if "://" in raw_cid else raw_cid

        annotations    = meta.get("annotations", {})
        cloud_identity = (
            annotations.get("eks.amazonaws.com/role-arn")
            or annotations.get("iam.amazonaws.com/role")
        )

        mapping[key] = {
            "pod_uid":         meta.get("uid", ""),
            "service_account": spec.get("serviceAccountName", ""),
            "node_name":       spec.get("nodeName", ""),
            "image_ref":       image_ref,
            "container_id":    container_id,
            "cloud_identity":  cloud_identity or None,
            "labels":          meta.get("labels", {}),          # ← 신규
            "annotations":     annotations,                     # ← 신규
        }

    return mapping


def build_owner_map(kubectl_pods_json: dict) -> dict:
    mapping: dict = {}
    for item in kubectl_pods_json.get("items", []):
        meta   = item.get("metadata", {})
        ns     = meta.get("namespace", "")
        name   = meta.get("name", "")
        key    = f"{ns}/{name}"
        owners = meta.get("ownerReferences", [])
        if owners:
            owner = owners[0]
            mapping[key] = {
                "kind": owner.get("kind", ""),
                "name": owner.get("name", ""),
                "uid":  owner.get("uid", ""),
            }
    return mapping


# ── 편의 조회 ─────────────────────────────────────────────────────────

def get_workload_labels(
    pod_meta_map: dict,
    namespace:    Optional[str],
    pod_name:     Optional[str],
) -> dict[str, str]:
    """pod_meta_map에서 해당 pod의 라벨 반환. 없으면 빈 dict."""
    key = f"{namespace or ''}/{pod_name or ''}"
    return pod_meta_map.get(key, {}).get("labels", {})


def get_workload_annotations(
    pod_meta_map: dict,
    namespace:    Optional[str],
    pod_name:     Optional[str],
) -> dict[str, str]:
    """pod_meta_map에서 해당 pod의 어노테이션 반환. 없으면 빈 dict."""
    key = f"{namespace or ''}/{pod_name or ''}"
    return pod_meta_map.get(key, {}).get("annotations", {})
