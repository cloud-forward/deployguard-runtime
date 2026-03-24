"""
runtime_api/clients/s3_exposure_client.py

S3 latest pointer + summary index 읽기 전담 클라이언트.
쓰기는 하지 않는다.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, Optional

import boto3
from botocore.exceptions import ClientError

log = logging.getLogger(__name__)

_S3_BUCKET  = os.environ.get("S3_BUCKET", "dg-raw-scans")
_S3_REGION  = os.environ.get("S3_REGION", "ap-northeast-2")
_S3_PREFIX  = os.environ.get("S3_PREFIX", "scans")
_S3_TIMEOUT = int(os.environ.get("S3_TIMEOUT", "5"))


def _s3() -> Any:
    return boto3.client(
        "s3",
        region_name=_S3_REGION,
        config=boto3.session.Config(connect_timeout=_S3_TIMEOUT, read_timeout=_S3_TIMEOUT),
    )


def _get_json(key: str) -> Optional[Dict[str, Any]]:
    try:
        resp = _s3().get_object(Bucket=_S3_BUCKET, Key=key)
        return json.loads(resp["Body"].read())
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("NoSuchKey", "404"):
            log.debug("s3 key not found: %s", key)
        else:
            log.warning("s3 get_object error key=%s: %s", key, e)
        return None
    except Exception as e:
        log.warning("s3 read error key=%s: %s", key, e)
        return None


def latest_pointer_key(cluster_id: str) -> str:
    return f"{_S3_PREFIX}/{cluster_id}/image/latest.json"


def get_latest_pointer(cluster_id: str) -> Optional[Dict[str, Any]]:
    """
    scans/{cluster_id}/image/latest.json 조회.
    없으면 None.
    """
    return _get_json(latest_pointer_key(cluster_id))


def get_summary_by_key(summary_key: str) -> Optional[Dict[str, Any]]:
    """
    latest pointer 의 summary_key 로 직접 조회.
    """
    return _get_json(summary_key)


def get_latest_summary(cluster_id: str) -> Optional[Dict[str, Any]]:
    """
    latest pointer → summary index 순서로 조회.
    편의 메서드.
    """
    pointer = get_latest_pointer(cluster_id)
    if not pointer:
        return None
    summary_key = pointer.get("summary_key")
    if not summary_key:
        return None
    return get_summary_by_key(summary_key)
