import time
import subprocess
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from normalizer.tetragon import normalize as tetragon_normalize
from normalizer.audit import normalize as audit_normalize
from evidence_mapper.mapper import map_to_evidence
from config.loader import get_system_namespaces

OUTPUT_DIR = Path(__file__).parent.parent / "output"
OUTPUT_DIR.mkdir(exist_ok=True)


def collect_tetragon_events(since: str = "2m") -> list:
    """모든 Tetragon Pod에서 로그 수집 (노드별로 각각 뽑음)"""
    try:
        pods_result = subprocess.run(
            [
                "kubectl", "get", "pods",
                "-n", "kube-system",
                "-l", "app.kubernetes.io/name=tetragon",
                "-o", "jsonpath={.items[*].metadata.name}",
            ],
            capture_output=True,
            text=True,
        )
        pod_names = [
            p for p in pods_result.stdout.strip().split()
            if "operator" not in p
        ]

        events = []
        for pod_name in pod_names:
            result = subprocess.run(
                [
                    "kubectl", "logs",
                    "-n", "kube-system",
                    pod_name,
                    "-c", "export-stdout",
                    f"--since={since}",
                ],
                capture_output=True,
                text=True,
            )
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        return events

    except Exception as e:
        print(f"[ERROR] Tetragon 수집 실패: {e}")
        return []


def collect_audit_events(log_path: str = "/var/log/kubernetes/audit/audit.log") -> list:
    """Audit 로그에서 raw JSON 이벤트 수집"""
    try:
        result = subprocess.run(
            ["tail", "-n", "100", log_path],
            capture_output=True,
            text=True,
        )
        events = []
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return events
    except Exception as e:
        print(f"[ERROR] Audit 수집 실패: {e}")
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
        data = json.loads(result.stdout)
        mapping = {}
        for item in data.get("items", []):
            ns = item["metadata"]["namespace"]
            name = item["metadata"]["name"]
            sa = item["spec"].get("serviceAccountName", "")
            if sa:
                mapping[f"{ns}/{name}"] = sa
        return mapping
    except Exception as e:
        print(f"[ERROR] Pod SA 매핑 실패: {e}")
        return {}


def run():
    print(f"[{datetime.now()}] 스캐너 시작")
    system_namespaces = get_system_namespaces()
    pod_sa_map = get_pod_sa_map()

    # 1. 수집
    tetragon_events = collect_tetragon_events(since="2m")
    audit_events = collect_audit_events()

    print(f"[INFO] Tetragon 이벤트: {len(tetragon_events)}개")
    print(f"[INFO] Audit 이벤트: {len(audit_events)}개")

    # 2. raw JSON 저장 (엔진단 협의용)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    raw_path = OUTPUT_DIR / f"raw_{timestamp}.json"
    with open(raw_path, "w") as f:
        json.dump(
            {"tetragon": tetragon_events, "audit": audit_events},
            f, indent=2, ensure_ascii=False
        )
    print(f"[RAW] {raw_path}")

    # 3. Evidence 변환
    evidences = []

    # Tetragon 중복 제거용 set
    seen_tetragon_keys = set()

    for raw in tetragon_events:
        kprobe = raw.get("process_kprobe")
        exec_event = raw.get("process_exec")
        block = kprobe or exec_event
        if block:
            exec_id = block.get("process", {}).get("exec_id", "")
            func = raw.get("process_kprobe", {}).get("function_name", "exec")
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

    # Audit 중복 제거용 set
    seen_audit_ids = set()

    for raw in audit_events:
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

    # 4. service_account null 채우기
    for e in evidences:
        if e.service_account is None and e.pod_name and e.namespace:
            key = f"{e.namespace}/{e.pod_name}"
            e.service_account = pod_sa_map.get(key)

    print(f"[INFO] Evidence 생성: {len(evidences)}개")

    # 5. Evidence JSON 저장
    if evidences:
        output_path = OUTPUT_DIR / f"evidence_{timestamp}.json"

        output = [
            {
                "evidence_id": e.evidence_id,
                "evidence_type": e.evidence_type.value,
                "timestamp": e.timestamp.isoformat(),
                "namespace": e.namespace,
                "pod_name": e.pod_name,
                "service_account": e.service_account,
                "node_name": e.node_name,
                "source": e.source,
                "detail": e.detail,
            }
            for e in evidences
        ]

        with open(output_path, "w") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)

        print(f"[OUTPUT] {output_path}")
        for e in output:
            print(f"  → {e['evidence_type']} | {e['pod_name']} | {e['namespace']}")
    else:
        print("[INFO] Evidence 없음")





if __name__ == "__main__":
    while True:
        run()
        time.sleep(120)
