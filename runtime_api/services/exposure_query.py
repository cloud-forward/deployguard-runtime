"""
runtime_api/services/exposure_query.py

summary index 에서 image_digest (우선) / image_ref (fallback) 매칭.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from runtime_api.clients.s3_exposure_client import get_latest_summary

log = logging.getLogger(__name__)


def _repo_name(value: str) -> str:
    if not value:
        return ""
    repo = value.split("@", 1)[0]
    if ":" in repo.rsplit("/", 1)[-1]:
        repo = repo.rsplit(":", 1)[0]
    return repo


class ImageExposureSummary:
    """경량 DTO. Pydantic 의존 없음."""
    __slots__ = (
        "image_ref", "image_digest",
        "critical_cve_count", "high_cve_count",
        "fix_available", "poc_exists",
        "sample_cves", "source", "scanned_at",
    )

    def __init__(self, row: Dict[str, Any]) -> None:
        self.image_ref          = row.get("image_ref", "")
        self.image_digest       = row.get("image_digest", "")
        self.critical_cve_count = int(row.get("critical_cve_count", 0))
        self.high_cve_count     = int(row.get("high_cve_count", 0))
        self.fix_available      = bool(row.get("fix_available", False))
        self.poc_exists         = bool(row.get("poc_exists", False))
        self.sample_cves        = list(row.get("sample_cves", []))
        self.source             = row.get("source", "trivy")
        self.scanned_at         = row.get("scanned_at")

    def to_dict(self) -> Dict[str, Any]:
        return {s: getattr(self, s) for s in self.__slots__}


def _build_indexes(
    images: List[Dict[str, Any]],
) -> tuple[Dict[str, Dict], Dict[str, Dict], Dict[str, List[Dict[str, Any]]]]:
    by_digest: Dict[str, Dict] = {}
    by_ref:    Dict[str, Dict] = {}
    by_repo:   Dict[str, List[Dict[str, Any]]] = {}
    for img in images:
        digest = img.get("image_digest", "")
        ref    = img.get("image_ref", "")
        if digest:
            by_digest[digest] = img
        if ref:
            by_ref[ref] = img
            repo = _repo_name(ref)
            if repo:
                by_repo.setdefault(repo, []).append(img)
    return by_digest, by_ref, by_repo


def lookup_exposure(
    cluster_id: str,
    image_refs:  List[str],
    image_digests: Optional[List[str]] = None,
) -> List[ImageExposureSummary]:
    """
    cluster_id 의 latest summary 에서 image_refs / image_digests 를 매칭.

    매칭 우선순위:
      1. image_digest (exact)
      2. image_ref   (exact fallback)

    반환: 매칭된 ImageExposureSummary 목록 (순서 보장 안 함).
    """
    summary = get_latest_summary(cluster_id)
    if not summary:
        log.debug("no summary for cluster_id=%s", cluster_id)
        return []

    by_digest, by_ref, by_repo = _build_indexes(summary.get("images", []))
    digests = set(image_digests or [])
    refs    = set(image_refs or [])

    result: List[ImageExposureSummary] = []
    matched_refs: set[str] = set()

    # 1. digest match
    for d in digests:
        if d and d in by_digest:
            row = by_digest[d]
            result.append(ImageExposureSummary(row))
            matched_refs.add(row.get("image_ref", ""))

    # 2. ref fallback
    for ref in refs:
        if ref in matched_refs:
            continue
        if ref in by_ref:
            row = by_ref[ref]
            result.append(ImageExposureSummary(row))
            matched_refs.add(row.get("image_ref", ""))
            continue

        repo = _repo_name(ref)
        if not repo:
            continue

        candidates = by_repo.get(repo, [])
        if not candidates:
            candidates = [
                img
                for indexed_repo, rows in by_repo.items()
                if repo.startswith(indexed_repo) or indexed_repo.startswith(repo)
                for img in rows
            ]
        for row in candidates:
            row_ref = row.get("image_ref", "")
            if row_ref in matched_refs:
                continue
            result.append(ImageExposureSummary(row))
            matched_refs.add(row_ref)
            break

    return result
