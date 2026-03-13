"""
runner.py — DeployGuard Runtime Scanner (리팩토링)

파이프라인:
  collect → normalize → enrich → dedup → build_evidence_fact → forward

변경 사항:
  - map_to_evidence() 호출 제거
  - Evidence JSON 직접 저장 제거
  - EvidenceFact 생성 및 forward 구조로 변경
  - CLUSTER_ID / SCANNER_VERSION / FORWARD_MODE / FORWARD_URL env 추가
  - source_native_event_id 기반 dedup
"""

import time
import subprocess
import json
import sys
import os
import logging
from datetime import datetime, timezone
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from normalizer.tetragon import normalize_with_excerpt as tetragon_normalize
from normalizer.audit    import normalize_with_excerpt as audit_normalize
from fact_builder.mapper   import build_evidence_fact
from fact_builder.enricher import enrich, build_pod_meta_map, build_owner_map
from forwarder.forwarder   import forward
from config.loader         import get_system_namespaces

# ── 로깅 설정 ─────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger(__name__)


# ── 환경변수 ──────────────────────────────────────────────────────────

# 공통
CLUSTER_ID       = os.environ.get("CLUSTER_ID", "")             # 필수
SCANNER_VERSION  = os.environ.get("SCANNER_VERSION", "unknown")
SCAN_INTERVAL    = int(os.environ.get("SCAN_INTERVAL", "300"))
OUTPUT_DIR       = Path(os.environ.get("OUTPUT_DIR", "/tmp/evidence"))
DEBUG            = os.environ.get("DEBUG", "false").lower() == "true"
SAVE_RAW         = os.environ.get("SAVE_RAW", "false").lower() == "true" or DEBUG

# Forward
FORWARD_MODE     = os.environ.get("FORWARD_MODE", "file-jsonl")
FORWARD_URL      = os.environ.get("FORWARD_URL", "")

# Tetragon
TETRAGON_ENABLED   = os.environ.get("TETRAGON_ENABLED", "true").lower() == "true"
TETRAGON_NAMESPACE = os.environ.get("TETRAGON_NAMESPACE", "kube-system")
TETRAGON_SELECTOR  = os.environ.get("TETRAGON_SELECTOR",
                                     "app.kubernetes.io/name=tetragon")
TETRAGON_CONTAINER = os.environ.get("TETRAGON_CONTAINER", "export-stdout")

# Audit
AUDIT_ENABLED    = os.environ.get("AUDIT_ENABLED", "true").lower() == "true"
AUDIT_LOG_PATH   = os.environ.get("AUDIT_LOG_PATH",
                                   "/var/log/kubernetes/audit/audit.log")
AUDIT_TAIL_LINES = int(os.environ.get("AUDIT_TAIL_LINES", "1000"))

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# ── 수집 ─────────────────────────────────────────────────────────────

def _since_str() -> str:
    minutes = max(1, (SCAN_INTERVAL // 60) + 1)
    return f"{minutes}m"


def collect_tetragon_events() -> list:
    since = _since_str()
    log.debug(f"Tetragon 수집 범위: --since={since}")
    try:
        pods_result = subprocess.run(
            ["kubectl", "get", "pods",
             "-n", TETRAGON_NAMESPACE,
             "-l", TETRAGON_SELECTOR,
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
                ["kubectl", "logs",
                 "-n", TETRAGON_NAMESPACE,
                 pod_name, "-c", TETRAGON_CONTAINER,
                 f"--since={since}"],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                log.warning(f"Pod 로그 실패: {pod_name}")
                continue
            for line in result.stdout.strip().splitlines():
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        log.debug(f"JSON 파싱 실패(tetragon): {line[:80]}")
        return events
    except Exception as e:
        log.error(f"Tetragon 수집 실패: {e}")
        return []


def collect_audit_events() -> list:
    audit_path = Path(AUDIT_LOG_PATH)
    if not audit_path.exists():
        log.warning(f"Audit 로그 없음: {AUDIT_LOG_PATH}")
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
                    log.debug(f"JSON 파싱 실패(audit): {line[:80]}")
        return events
    except Exception as e:
        log.error(f"Audit 수집 실패: {e}")
        return []


def get_pod_meta() -> tuple[dict, dict]:
    """(pod_meta_map, owner_map) 반환. 실패 시 빈 dict."""
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


# ── 메인 실행 ─────────────────────────────────────────────────────────

def run() -> None:
    if not CLUSTER_ID:
        log.warning("CLUSTER_ID 미설정 — EvidenceFact의 cluster_id가 'unknown'으로 설정됨")

    if not TETRAGON_ENABLED and not AUDIT_ENABLED:
        log.warning("TETRAGON_ENABLED, AUDIT_ENABLED 모두 false")
        return

    system_namespaces = get_system_namespaces()
    pod_meta_map, owner_map = get_pod_meta()

    # 1. 수집
    tetragon_raws = collect_tetragon_events() if TETRAGON_ENABLED else []
    audit_raws    = collect_audit_events()    if AUDIT_ENABLED    else []

    log.info(f"수집: Tetragon={len(tetragon_raws)}, Audit={len(audit_raws)}")

    # 2. raw 저장 (DEBUG/SAVE_RAW 모드)
    if SAVE_RAW and (tetragon_raws or audit_raws):
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        raw_path = OUTPUT_DIR / f"raw_{ts}.json"
        try:
            with open(raw_path, "w") as f:
                json.dump({"tetragon": tetragon_raws, "audit": audit_raws},
                          f, indent=2, ensure_ascii=False)
            log.debug(f"Raw 저장: {raw_path}")
        except Exception as e:
            log.error(f"Raw 저장 실패: {e}")

    facts: list = []

    # 3. Tetragon 처리
    seen_tetragon: set = set()
    for raw in tetragon_raws:
        try:
            result = tetragon_normalize(raw)
            if result is None:
                continue
            event, excerpt = result

            # dedup: source_native_event_id (exec_id) + func 기반
            block    = raw.get("process_kprobe") or raw.get("process_exec") or {}
            exec_id  = block.get("process", {}).get("exec_id", "")
            func     = raw.get("process_kprobe", {}).get("function_name", "exec")
            dedup_k  = f"{exec_id}:{func}"
            if dedup_k in seen_tetragon:
                continue
            seen_tetragon.add(dedup_k)

            if event.actor.namespace in system_namespaces:
                continue

            # 4. enrich
            event = enrich(event, pod_meta_map, owner_map)

            # 5. build_evidence_fact
            fact = build_evidence_fact(
                event=event,
                raw_excerpt=excerpt,
                raw_full=raw,
                cluster_id=CLUSTER_ID,
                scanner_version=SCANNER_VERSION,
            )
            if fact:
                facts.append(fact)

        except Exception as e:
            log.error(f"Tetragon 처리 실패: {e}")

    # 3. Audit 처리
    seen_audit: set = set()
    for raw in audit_raws:
        try:
            result = audit_normalize(raw)
            if result is None:
                continue

            # audit_normalize가 (event, excerpt) 또는 event 단독 반환 처리
            if isinstance(result, tuple):
                event, excerpt = result
            else:
                event, excerpt = result, None

            # dedup: auditID
            audit_id = raw.get("auditID")
            if audit_id:
                if audit_id in seen_audit:
                    continue
                seen_audit.add(audit_id)

            if event.actor.namespace in system_namespaces:
                continue

            # 4. enrich
            event = enrich(event, pod_meta_map, owner_map)

            # 5. build_evidence_fact
            fact = build_evidence_fact(
                event=event,
                raw_excerpt=excerpt,
                raw_full=raw,
                cluster_id=CLUSTER_ID,
                scanner_version=SCANNER_VERSION,
            )
            if fact:
                facts.append(fact)

        except Exception as e:
            log.error(f"Audit 처리 실패: {e}")

    log.info(f"EvidenceFact 생성: {len(facts)}건")
    for f in facts:
        log.info(
            f"  → {f.fact_type:<35} "
            f"pod={f.actor.pod_name}  ns={f.actor.namespace}  "
            f"severity={f.severity_hint}"
        )

    # 6. forward (stdout / file-jsonl / http-post)
    forward(facts)


if __name__ == "__main__":
    log.info(f"DeployGuard Scanner 시작 (interval={SCAN_INTERVAL}s, "
             f"cluster={CLUSTER_ID}, mode={FORWARD_MODE})")
    while True:
        try:
            run()
        except Exception as e:
            log.error(f"run() 예외: {e}")
        time.sleep(SCAN_INTERVAL)
