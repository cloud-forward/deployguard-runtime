"""
runner.py — DeployGuard Runtime Scanner

파이프라인:
  collect → normalize → enrich → dedup
  → build_evidence_fact → [suppress] → forward

suppression 단계:
  - YAML 정책 기반 (코드 if/else 하드코딩 없음)
  - pod_name/service_account 문자열 하드코딩 없음
  - workload_labels / pod_uid / annotation 기반 식별
  - suppressed fact는 drop되지만 내부 카운터/로그는 유지
  - outbound payload만 차단
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

sys.path.append(str(Path(__file__).parent.parent))

from normalizer.tetragon   import normalize_with_excerpt as tetragon_normalize
from normalizer.audit      import normalize_with_excerpt as audit_normalize
from fact_builder.mapper   import build_evidence_fact
from fact_builder.enricher import (
    enrich, build_pod_meta_map, build_owner_map,
    get_workload_labels, get_workload_annotations,
)
from forwarder.forwarder   import forward
from config.loader         import get_system_namespaces
from suppression.matcher   import get_matcher, reload_matcher
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

FORWARD_MODE     = os.environ.get("FORWARD_MODE", "file-jsonl")
FORWARD_URL      = os.environ.get("FORWARD_URL", "")

TETRAGON_ENABLED   = os.environ.get("TETRAGON_ENABLED", "true").lower() == "true"
TETRAGON_NAMESPACE = os.environ.get("TETRAGON_NAMESPACE", "kube-system")
TETRAGON_SELECTOR  = os.environ.get("TETRAGON_SELECTOR",
                                     "app.kubernetes.io/name=tetragon")
TETRAGON_CONTAINER = os.environ.get("TETRAGON_CONTAINER", "export-stdout")

AUDIT_ENABLED    = os.environ.get("AUDIT_ENABLED", "true").lower() == "true"
AUDIT_LOG_PATH   = os.environ.get("AUDIT_LOG_PATH",
                                   "/var/log/kubernetes/audit/audit.log")
AUDIT_TAIL_LINES = int(os.environ.get("AUDIT_TAIL_LINES", "1000"))

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# ── SIGHUP: 정책 핫 리로드 ────────────────────────────────────────────

def _handle_sighup(signum, frame) -> None:
    log.info("SIGHUP 수신 — suppression 정책 및 registry 리로드")
    reload_matcher()


signal.signal(signal.SIGHUP, _handle_sighup)


# ── 수집 헬퍼 ────────────────────────────────────────────────────────

def _since_str() -> str:
    return f"{max(1, (SCAN_INTERVAL // 60) + 1)}m"


def collect_tetragon_events() -> list:
    try:
        pods_result = subprocess.run(
            ["kubectl", "get", "pods",
             "-n", TETRAGON_NAMESPACE, "-l", TETRAGON_SELECTOR,
             "-o", "jsonpath={.items[*].metadata.name}"],
            capture_output=True, text=True,
        )
        pod_names = [p for p in pods_result.stdout.strip().split()
                     if "operator" not in p]
        if not pod_names:
            log.warning(f"Tetragon Pod 없음 (ns={TETRAGON_NAMESPACE})")
            return []

        events: list = []
        for pod_name in pod_names:
            result = subprocess.run(
                ["kubectl", "logs", "-n", TETRAGON_NAMESPACE,
                 pod_name, "-c", TETRAGON_CONTAINER,
                 f"--since={_since_str()}"],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                continue
            for line in result.stdout.strip().splitlines():
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        return events
    except Exception as e:
        log.error(f"Tetragon 수집 실패: {e}")
        return []


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
        log.error(f"Audit 수집 실패: {e}")
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
        log.error(f"Pod 메타 조회 실패: {e}")
        return {}, {}


# ── suppression 적용 ──────────────────────────────────────────────────

def _apply_suppression(fact, pod_meta_map: dict) -> bool:
    """
    True  → suppress (outbound 차단, 로그/카운터 유지)
    False → 통과

    workload_labels / annotations는 pod_meta_map에서 조회.
    pod_uid 기반 self-identity 체크는 matcher 내부 규칙에서 처리.
    """
    matcher = get_matcher()

    labels = get_workload_labels(
        pod_meta_map,
        fact.actor.namespace,
        fact.actor.pod_name,
    )
    annotations = get_workload_annotations(
        pod_meta_map,
        fact.actor.namespace,
        fact.actor.pod_name,
    )

    # scanner 자기 자신이면 labels에 self-identity 라벨을 강제 주입
    # (kubectl 조회가 실패했을 때 env 기반 fallback)
    identity = get_identity()
    if identity.is_self(fact.actor.pod_uid, fact.actor.pod_name):
        labels = {**labels, **identity.labels}
        # deployguard.io/internal-collector 라벨이 없어도 자기 자신이면 주입
        if "deployguard.io/internal-collector" not in labels:
            labels["deployguard.io/internal-collector"] = "true"

    result = matcher.evaluate(fact, labels, annotations)

    if result.suppressed:
        log.debug(
            f"[suppressed] rule={result.rule_id} "
            f"fact={fact.fact_type} pod={fact.actor.pod_name} "
            f"reason={result.suppressed_reason}"
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

    log.info(f"수집: Tetragon={len(tetragon_raws)}, Audit={len(audit_raws)}")

    if SAVE_RAW and (tetragon_raws or audit_raws):
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        try:
            with open(OUTPUT_DIR / f"raw_{ts}.json", "w") as f:
                json.dump({"tetragon": tetragon_raws, "audit": audit_raws},
                          f, indent=2, ensure_ascii=False)
        except Exception as e:
            log.error(f"Raw 저장 실패: {e}")

    facts:      list = []
    suppressed: int  = 0

    # ── Tetragon 처리 ─────────────────────────────────────────────────
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

            # ── suppression 적용 ──────────────────────────────────────
            if _apply_suppression(fact, pod_meta_map):
                suppressed += 1
                continue

            facts.append(fact)

        except Exception as e:
            log.error(f"Tetragon 처리 실패: {e}")

    # ── Audit 처리 ────────────────────────────────────────────────────
    seen_audit: set = set()
    for raw in audit_raws:
        try:
            result = audit_normalize(raw)
            if result is None:
                continue

            if isinstance(result, tuple):
                event, excerpt = result
            else:
                event, excerpt = result, None

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

            # ── suppression 적용 ──────────────────────────────────────
            if _apply_suppression(fact, pod_meta_map):
                suppressed += 1
                continue

            facts.append(fact)

        except Exception as e:
            log.error(f"Audit 처리 실패: {e}")

    log.info(
        f"EvidenceFact: 생성={len(facts) + suppressed}  "
        f"통과={len(facts)}  suppressed={suppressed}"
    )

    # 진단 카운터 로그 (suppress된 규칙별 집계)
    for metric in get_matcher().metrics_snapshot():
        if metric["match_count"] > 0:
            log.debug(
                f"[suppression-metric] rule={metric['rule_id']} "
                f"count={metric['match_count']} "
                f"last={metric['last_matched']}"
            )

    forward(facts)


if __name__ == "__main__":
    log.info(f"DeployGuard Scanner 시작 (interval={SCAN_INTERVAL}s, "
             f"cluster={CLUSTER_ID}, forward={FORWARD_MODE})")
    while True:
        try:
            run()
        except Exception as e:
            log.error(f"run() 예외: {e}")
        time.sleep(SCAN_INTERVAL)
