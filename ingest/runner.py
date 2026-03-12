import time
import subprocess
import json
import sys
import time
import os
from datetime import datetime, timezone
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from normalizer.tetragon import normalize as tetragon_normalize
from normalizer.audit import normalize as audit_normalize
from evidence_mapper.mapper import map_to_evidence
from config.loader import get_system_namespaces

# ── 환경변수 설정 ────────────────────────────────────────────
SCAN_INTERVAL       = int(os.environ.get("SCAN_INTERVAL", "300"))
OUTPUT_DIR          = Path(os.environ.get("OUTPUT_DIR", "/tmp/evidence"))
DEBUG               = os.environ.get("DEBUG", "false").lower() == "true"
SAVE_RAW            = os.environ.get("SAVE_RAW", "false").lower() == "true" or DEBUG

TETRAGON_ENABLED    = os.environ.get("TETRAGON_ENABLED", "true").lower() == "true"
TETRAGON_NAMESPACE  = os.environ.get("TETRAGON_NAMESPACE", "kube-system")
TETRAGON_SELECTOR   = os.environ.get("TETRAGON_SELECTOR", "app.kubernetes.io/name=tetragon")
TETRAGON_CONTAINER  = os.environ.get("TETRAGON_CONTAINER", "export-stdout")

AUDIT_ENABLED       = os.environ.get("AUDIT_ENABLED", "true").lower() == "true"
AUDIT_LOG_PATH      = os.environ.get("AUDIT_LOG_PATH", "/var/log/kubernetes/audit/audit.log")
AUDIT_TAIL_LINES    = int(os.environ.get("AUDIT_TAIL_LINES", "100"))
# ─────────────────────────────────────────────────────────────

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def log(level: str, message: str):
    ts = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    print(f"[{ts}] [{level}] {message}", flush=True)


def debug(message: str):
    if DEBUG:
        log("DEBUG", message)


def collect_tetragon_events(since: str = "2m") -> list:
    """모든 Tetragon Pod에서 로그 수집 (노드별로 각각 뽑음)"""
    try:
        pods_result = subprocess.run(
            [
                "kubectl", "get", "pods",
                "-n", TETRAGON_NAMESPACE,
                "-l", TETRAGON_SELECTOR,
                "-o", "jsonpath={.items[*].metadata.name}",
            ],
            capture_output=True,
            text=True,
        )

        pod_names = [
            p for p in pods_result.stdout.strip().split()
            if "operator" not in p
        ]

        if not pod_names:
            log("WARN", f"Tetragon Pod를 찾을 수 없음 (namespace={TETRAGON_NAMESPACE}, selector={TETRAGON_SELECTOR})")
            return []

        debug(f"Tetragon Pods 발견: {pod_names}")

        events = []
        for pod_name in pod_names:
            try:
                result = subprocess.run(
                    [
                        "kubectl", "logs",
                        "-n", TETRAGON_NAMESPACE,
                        pod_name,
                        "-c", TETRAGON_CONTAINER,
                        f"--since={since}",
                    ],
                    capture_output=True,
                    text=True,
                )
                if result.returncode != 0:
                    log("WARN", f"Pod 로그 수집 실패: {pod_name} → {result.stderr.strip()}")
                    continue

                parsed = 0
                for line in result.stdout.strip().split("\n"):
                    if not line:
                        continue
                    try:
                        events.append(json.loads(line))
                        parsed += 1
                    except json.JSONDecodeError:
                        debug(f"JSON 파싱 실패 (tetragon): {line[:80]}")
                        continue

                debug(f"Pod {pod_name}: {parsed}개 이벤트 수집")

            except Exception as e:
                log("ERROR", f"Pod {pod_name} 로그 수집 중 예외: {e}")
                continue

        return events

    except Exception as e:
        log("ERROR", f"Tetragon 수집 실패: {e}")
        return []


def collect_audit_events() -> list:
    """Audit 로그에서 raw JSON 이벤트 수집"""
    audit_path = Path(AUDIT_LOG_PATH)
    if not audit_path.exists():
        log("WARN", f"Audit 로그 파일 없음: {AUDIT_LOG_PATH}")
        return []

    try:
        result = subprocess.run(
            ["tail", "-n", str(AUDIT_TAIL_LINES), AUDIT_LOG_PATH],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            log("WARN", f"Audit 로그 읽기 실패: {result.stderr.strip()}")
            return []

        events = []
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                debug(f"JSON 파싱 실패 (audit): {line[:80]}")
                continue

        debug(f"Audit 이벤트 수집: {len(events)}개")
        return events

    except Exception as e:
        log("ERROR", f"Audit 수집 실패: {e}")
        return []


def get_pod_sa_map() -> dict:
    """pod_name → service_account 매핑 테이블"""
    try:
        result = subprocess.run(
            [
                "kubectl", "get", "pods",
                "--all-namespaces",
                "-o", "json",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            log("WARN", f"Pod SA 매핑 조회 실패: {result.stderr.strip()}")
            return {}

        data = json.loads(result.stdout)
        mapping = {}
        for item in data.get("items", []):
            ns   = item["metadata"]["namespace"]
            name = item["metadata"]["name"]
            sa   = item["spec"].get("serviceAccountName", "")
            if sa:
                mapping[f"{ns}/{name}"] = sa

        debug(f"Pod SA 매핑 테이블 크기: {len(mapping)}")
        return mapping

    except Exception as e:
        log("ERROR", f"Pod SA 매핑 실패: {e}")
        return {}


def run():
    log("INFO", "스캐너 실행 시작")
    debug(f"설정: interval={SCAN_INTERVAL}s, output={OUTPUT_DIR}, tetragon={TETRAGON_ENABLED}, audit={AUDIT_ENABLED}")

    if not TETRAGON_ENABLED and not AUDIT_ENABLED:
        log("WARN", "TETRAGON_ENABLED, AUDIT_ENABLED 모두 false — 수집할 소스 없음, 스킵")
        return

    try:
        system_namespaces = get_system_namespaces()
    except Exception as e:
        log("ERROR", f"시스템 네임스페이스 로드 실패: {e}")
        system_namespaces = set()

    try:
        pod_sa_map = get_pod_sa_map()
    except Exception as e:
        log("ERROR", f"Pod SA 맵 로드 실패: {e}")
        pod_sa_map = {}

    # 1. 수집
    tetragon_events = collect_tetragon_events(since="2m") if TETRAGON_ENABLED else []
    audit_events    = collect_audit_events()               if AUDIT_ENABLED    else []

    log("INFO", f"Tetragon 이벤트: {len(tetragon_events)}개 | Audit 이벤트: {len(audit_events)}개")

    # 2. raw JSON 저장 (DEBUG 모드 또는 SAVE_RAW=true)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")

    if SAVE_RAW and (tetragon_events or audit_events):
        try:
            raw_path = OUTPUT_DIR / f"raw_{timestamp}.json"
            with open(raw_path, "w") as f:
                json.dump(
                    {"tetragon": tetragon_events, "audit": audit_events},
                    f, indent=2, ensure_ascii=False,
                )
            log("DEBUG", f"Raw 저장: {raw_path}")
        except Exception as e:
            log("ERROR", f"Raw 저장 실패: {e}")

    # 3. Evidence 변환
    evidences = []

    # Tetragon
    seen_tetragon_keys = set()
    for raw in tetragon_events:
        try:
            kprobe     = raw.get("process_kprobe")
            exec_event = raw.get("process_exec")
            block      = kprobe or exec_event
            if block:
                exec_id   = block.get("process", {}).get("exec_id", "")
                func      = raw.get("process_kprobe", {}).get("function_name", "exec")
                dedup_key = f"{exec_id}_{func}"
                if dedup_key in seen_tetragon_keys:
                    continue
                seen_tetragon_keys.add(dedup_key)

            event = tetragon_normalize(raw)
            if not event:
                continue
            if event.actor.namespace in system_namespaces:
                continue
            evidence = map_to_evidence(event)
            if not evidence:
                continue
            evidences.append(evidence)
        except Exception as e:
            log("ERROR", f"Tetragon 이벤트 처리 실패: {e}")
            continue

    # Audit
    seen_audit_ids = set()
    for raw in audit_events:
        try:
            audit_id = raw.get("auditID")
            if audit_id:
                if audit_id in seen_audit_ids:
                    continue
                seen_audit_ids.add(audit_id)

            event = audit_normalize(raw)
            if not event:
                continue
            if event.actor.namespace in system_namespaces:
                continue
            evidence = map_to_evidence(event)
            if not evidence:
                continue
            evidences.append(evidence)
        except Exception as e:
            log("ERROR", f"Audit 이벤트 처리 실패: {e}")
            continue

    # 4. service_account null 채우기
    for e in evidences:
        if e.service_account is None and e.pod_name and e.namespace:
            key = f"{e.namespace}/{e.pod_name}"
            e.service_account = pod_sa_map.get(key)

    log("INFO", f"Evidence 생성: {len(evidences)}개")

    # 5. Evidence JSON 저장
    if evidences:
        try:
            output_path = OUTPUT_DIR / f"evidence_{timestamp}.json"
            output = [
                {
                    "evidence_id":   e.evidence_id,
                    "evidence_type": e.evidence_type.value,
                    "timestamp":     e.timestamp.isoformat(),
                    "namespace":     e.namespace,
                    "pod_name":      e.pod_name,
                    "service_account": e.service_account,
                    "node_name":     e.node_name,
                    "source":        e.source,
                    "detail":        e.detail,
                }
                for e in evidences
            ]

            with open(output_path, "w") as f:
                json.dump(output, f, indent=2, ensure_ascii=False)

            log("INFO", f"Evidence 저장: {output_path}")
            for e in output:
                log("INFO", f"  → {e['evidence_type']} | {e['pod_name']} | {e['namespace']}")

        except Exception as e:
            log("ERROR", f"Evidence 저장 실패: {e}")
    else:
        log("INFO", "Evidence 없음 — 저장 스킵")





if __name__ == "__main__":
    log("INFO", f"DeployGuard Scanner 시작 (interval={SCAN_INTERVAL}s)")
    while True:
        try:
            run()
        except Exception as e:
            log("ERROR", f"run() 예외 발생: {e}")
        time.sleep(SCAN_INTERVAL)
