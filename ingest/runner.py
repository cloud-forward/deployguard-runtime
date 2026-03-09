import subprocess
import json
import sys
import os
from datetime import datetime, timezone
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from normalizer.tetragon import normalize as tetragon_normalize
from normalizer.audit import normalize as audit_normalize
from evidence_mapper.mapper import map_to_evidence

OUTPUT_DIR = Path(__file__).parent.parent / "output"
OUTPUT_DIR.mkdir(exist_ok=True)


def collect_tetragon_events(since: str = "1m") -> list:
    """Tetragon 로그에서 raw JSON 이벤트 수집"""
    try:
        result = subprocess.run(
            [
                "kubectl", "logs",
                "-n", "kube-system",
                "-l", "app.kubernetes.io/name=tetragon",
                "-c", "export-stdout",
                f"--since={since}",
            ],
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


def run():
    print(f"[{datetime.now()}] 스캐너 시작")

    # 1. 수집
    tetragon_events = collect_tetragon_events(since="2m")
    audit_events = collect_audit_events()

    print(f"[INFO] Tetragon 이벤트: {len(tetragon_events)}개")
    print(f"[INFO] Audit 이벤트: {len(audit_events)}개")

    # 2. Evidence 변환
    evidences = []

    for raw in tetragon_events:
        event = tetragon_normalize(raw)
        if not event:
            continue
        evidence = map_to_evidence(event)
        if not evidence:
            continue
        evidences.append(evidence)

    for raw in audit_events:
        event = audit_normalize(raw)
        if not event:
            continue
        evidence = map_to_evidence(event)
        if not evidence:
            continue
        evidences.append(evidence)

    print(f"[INFO] Evidence 생성: {len(evidences)}개")

    # 3. JSON 파일로 저장
    if evidences:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
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
    run()