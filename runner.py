"""
runner.py — DeployGuard Runtime Scanner

파이프라인:
  collect → normalize → enrich → build_evidence_fact → suppress → dispatch

변경 사항:
  - dispatch()를 facts 유무와 관계없이 항상 호출 (empty cycle liveness)
  - FORWARD_MODE / FORWARD_URL 제거 (Engine S3 전용)
  - ENGINE_BASE_URL / ENGINE_API_TOKEN 환경변수 사용
"""

import time
import subprocess
import json
import sys
import os
import logging
import signal
from datetime import datetime, timezone
from pathlib import Path

sys.path.append(str(Path(__file__).parent))

from normalizer.tetragon       import normalize_with_excerpt as tetragon_normalize
from normalizer.audit          import normalize_with_excerpt as audit_normalize
from fact_builder.mapper       import build_evidence_fact
from fact_builder.enricher     import (
    enrich, build_pod_meta_map, build_owner_map,
    get_workload_labels, get_workload_annotations,
)
from forwarder.dispatcher      import dispatch
from config.loader             import get_system_namespaces
from suppression.matcher       import get_matcher, reload_matcher
from suppression.self_identity import get_identity

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger(__name__)

# ── 환경변수 ──────────────────────────────────────────────────────────
CLUSTER_ID       = os.environ.get("CLUSTER_ID", "")
SCANNER_VERSION  = os.environ.get("SCANNER_VERSION", "unknown")
SCAN_INTERVAL    = int(os.environ.get("SCAN_INTERVAL", "300"))
OUTPUT_DIR       = Path(os.environ.get("OUTPUT_DIR", "/tmp/evidence"))
DEBUG            = os.environ.get("DEBUG", "false").lower() == "true"
SAVE_RAW         = os.environ.get("SAVE_RAW", "false").lower() == "true" or DEBUG

TETRAGON_ENABLED   = os.environ.get("TETRAGON_ENABLED", "true").lower() == "true"
TETRAGON_NAMESPACE = os.environ.get("TETRAGON_NAMESPACE", "kube-system")
TETRAGON_SELECTOR  = os.environ.get("TETRAGON_SELECTOR",
                                     "app.kubernetes.io/name=tetragon")
TETRAGON_CONTAINER = os.environ.get("TETRAGON_CONTAINER", "export-stdout")

NODE_NAME = os.environ.get("NODE_NAME", "")

AUDIT_ENABLED    = os.environ.get("AUDIT_ENABLED", "true").lower() == "true"
AUDIT_LOG_PATH   = os.environ.get("AUDIT_LOG_PATH",
                                   "/var/log/kubernetes/audit/audit.log")
AUDIT_TAIL_LINES = int(os.environ.get("AUDIT_TAIL_LINES", "1000"))

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# ── SIGHUP: 정책 핫 리로드 ────────────────────────────────────────────

def _handle_sighup(signum, frame) -> None:
    log.info("SIGHUP 수신 — suppression 정책 리로드")
    reload_matcher()


signal.signal(signal.SIGHUP, _handle_sighup)


# ── 수집 헬퍼 ─────────────────────────────────────────────────────────

def _since_str() -> str:
    return f"{max(1, (SCAN_INTERVAL // 60) + 1)}m"


def _find_tetragon_pods() -> list[str]:
    """
    DaemonSet 전제:
      NODE_NAME 설정 → fieldSelector로 해당 노드 Pod만 반환
      NODE_NAME 미설정 → 전체 Pod 반환 + 경고 (fallback)
    """
    try:
        cmd = [
            "kubectl", "get", "pods",
            "-n", TETRAGON_NAMESPACE,
            "-l", TETRAGON_SELECTOR,
        ]
        if NODE_NAME:
            cmd.append(f"--field-selector=spec.nodeName={NODE_NAME}")
        else:
            log.warning(
                "NODE_NAME 환경변수 미설정 — 모든 Tetragon Pod에서 수집 "
                "(DaemonSet 환경에서는 spec.nodeName fieldRef 주입 필요)"
            )
        cmd += ["-o", "jsonpath={.items[*].metadata.name}"]

        result = subprocess.run(cmd, capture_output=True, text=True)
        pods = [p for p in result.stdout.strip().split() if "operator" not in p]

        if len(pods) > 1:
            log.warning("Tetragon pod가 여러 개 발견됨: %s", pods)

        return pods

    except Exception as e:
        log.error("Tetragon Pod 목록 조회 실패: %s", e)
        return []


def collect_tetragon_events() -> list:
    pod_names = _find_tetragon_pods()
    if not pod_names:
        log.warning("Tetragon Pod 없음 (ns=%s, node=%s)",
                    TETRAGON_NAMESPACE, NODE_NAME or "*")
        return []

    log.debug("Tetragon 수집 대상 Pod: %s", pod_names)
    events: list = []
    for pod_name in pod_names:
        result = subprocess.run(
            ["kubectl", "logs",
             "-n", TETRAGON_NAMESPACE,
             pod_name, "-c", TETRAGON_CONTAINER,
             f"--since={_since_str()}"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            log.warning("Tetragon 로그 조회 실패: pod=%s", pod_name)
            continue
        for line in result.stdout.strip().splitlines():
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return events


def collect_audit_events() -> list:
    if not Path(AUDIT_LOG_PATH).exists():
        return []
    try:
        result = subprocess.run(
            ["tail", "-n", str(AUDIT_TAIL_LINES), AUDIT_LOG_PATH],
            capture_output=True, text=True,
        )
        events: list = []
        for line in result.stdout.strip().splitlines():
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return events
    except Exception as e:
        log.error("Audit 수집 실패: %s", e)
        return []


def get_pod_meta() -> tuple[dict, dict]:
    try:
        result = subprocess.run(
            ["kubectl", "get", "pods", "--all-namespaces", "-o", "json"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            return {}, {}
        data = json.loads(result.stdout)
        return build_pod_meta_map(data), build_owner_map(data)
    except Exception as e:
        log.error("Pod 메타 조회 실패: %s", e)
        return {}, {}


# ── suppression ───────────────────────────────────────────────────────

def _apply_suppression(fact, pod_meta_map: dict) -> bool:
    """True → suppress (outbound 차단, 내부 카운터 유지)"""
    matcher = get_matcher()

    labels = get_workload_labels(
        pod_meta_map, fact.actor.namespace, fact.actor.pod_name,
    )
    annotations = get_workload_annotations(
        pod_meta_map, fact.actor.namespace, fact.actor.pod_name,
    )

    identity = get_identity()
    if identity.is_self(fact.actor.pod_uid, fact.actor.pod_name):
        labels = {**labels, **identity.labels}
        if "deployguard.io/internal-collector" not in labels:
            labels["deployguard.io/internal-collector"] = "true"

    result = matcher.evaluate(fact, labels, annotations)
    if result.suppressed:
        log.debug(
            "[suppressed] rule=%s fact=%s pod=%s reason=%s",
            result.rule_id, fact.fact_type,
            fact.actor.pod_name, result.suppressed_reason,
        )
        return True
    return False


# ── 메인 실행 ─────────────────────────────────────────────────────────

def run() -> None:
    if not CLUSTER_ID:
        log.warning("CLUSTER_ID 미설정")

    system_namespaces = get_system_namespaces()
    pod_meta_map, owner_map = get_pod_meta()

    tetragon_raws = collect_tetragon_events() if TETRAGON_ENABLED else []
    audit_raws    = collect_audit_events()    if AUDIT_ENABLED    else []

    log.info("수집: Tetragon=%d, Audit=%d", len(tetragon_raws), len(audit_raws))

    if SAVE_RAW and (tetragon_raws or audit_raws):
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        try:
            with open(OUTPUT_DIR / f"raw_{ts}.json", "w") as f:
                json.dump(
                    {"tetragon": tetragon_raws, "audit": audit_raws},
                    f, indent=2, ensure_ascii=False,
                )
        except Exception as e:
            log.error("Raw 저장 실패: %s", e)

    facts:      list = []
    suppressed: int  = 0

    # ── Tetragon ──────────────────────────────────────────────────────
    seen_tetragon: set = set()
    for raw in tetragon_raws:
        try:
            result = tetragon_normalize(raw)
            if result is None:
                continue
            event, excerpt = result

            block   = raw.get("process_kprobe") or raw.get("process_exec") or {}
            exec_id = block.get("process", {}).get("exec_id", "")
            func    = raw.get("process_kprobe", {}).get("function_name", "exec")
            dedup_k = f"{exec_id}:{func}"
            if dedup_k in seen_tetragon:
                continue
            seen_tetragon.add(dedup_k)

            if event.actor.namespace in system_namespaces:
                continue

            event = enrich(event, pod_meta_map, owner_map)

            fact = build_evidence_fact(
                event=event, raw_excerpt=excerpt, raw_full=raw,
                cluster_id=CLUSTER_ID, scanner_version=SCANNER_VERSION,
            )
            if not fact:
                continue

            if _apply_suppression(fact, pod_meta_map):
                suppressed += 1
                continue

            facts.append(fact)

        except Exception as e:
            log.error("Tetragon 처리 실패: %s", e)

    # ── Audit ─────────────────────────────────────────────────────────
    seen_audit: set = set()
    for raw in audit_raws:
        try:
            result = audit_normalize(raw)
            if result is None:
                continue

            event, excerpt = result if isinstance(result, tuple) else (result, None)

            audit_id = raw.get("auditID")
            if audit_id:
                if audit_id in seen_audit:
                    continue
                seen_audit.add(audit_id)

            if event.actor.namespace in system_namespaces:
                continue

            event = enrich(event, pod_meta_map, owner_map)

            fact = build_evidence_fact(
                event=event, raw_excerpt=excerpt, raw_full=raw,
                cluster_id=CLUSTER_ID, scanner_version=SCANNER_VERSION,
            )
            if not fact:
                continue

            if _apply_suppression(fact, pod_meta_map):
                suppressed += 1
                continue

            facts.append(fact)

        except Exception as e:
            log.error("Audit 처리 실패: %s", e)

    log.info(
        "EvidenceFact: 생성=%d  통과=%d  suppressed=%d",
        len(facts) + suppressed, len(facts), suppressed,
    )

    for metric in get_matcher().metrics_snapshot():
        if metric["match_count"] > 0:
            log.debug(
                "[suppression-metric] rule=%s count=%d last=%s",
                metric["rule_id"], metric["match_count"], metric["last_matched"],
            )

    # empty cycle이어도 항상 dispatch (liveness 확인)
    dispatch(facts)


if __name__ == "__main__":
    log.info(
        "DeployGuard Scanner 시작 (interval=%ds, cluster=%s, node=%s)",
        SCAN_INTERVAL, CLUSTER_ID or "(미설정)", NODE_NAME or "*",
    )
    while True:
        try:
            run()
        except Exception as e:
            log.error("run() 예외: %s", e)
        time.sleep(SCAN_INTERVAL)
