import json
import pytest
from pathlib import Path
from datetime import datetime, timezone

from normalizer.tetragon import normalize as tetragon_normalize
from normalizer.audit import normalize as audit_normalize
from evidence_mapper.mapper import map_to_evidence
from verdict.verdict import determine_verdict
from schemas.evidence import EvidenceType, PathVerdict


# ── 샘플 데이터 로드 ──────────────────────────────────────────────────────

SAMPLES_DIR = Path(__file__).parent.parent / "samples"

def load_tetragon_samples():
    with open(SAMPLES_DIR / "tetragon" / "sample_events.json") as f:
        return json.load(f)

def load_audit_samples():
    with open(SAMPLES_DIR / "audit" / "sample_events.json") as f:
        return json.load(f)


# ── Normalizer 테스트 ─────────────────────────────────────────────────────

class TestTetragonNormalizer:
    def test_normalize_file_event(self):
        raw = load_tetragon_samples()[0]  # SA token 접근
        event = tetragon_normalize(raw)
        assert event is not None
        assert event.action == "open"
        assert "token" in event.target

    def test_normalize_network_event(self):
        raw = load_tetragon_samples()[1]  # kube-api 접근
        event = tetragon_normalize(raw)
        assert event is not None
        assert event.action == "connect"
        assert event.target == "10.96.0.1"

    def test_normalize_imds_event(self):
        raw = load_tetragon_samples()[2]  # IMDS 접근
        event = tetragon_normalize(raw)
        assert event is not None
        assert event.target == "169.254.169.254"


class TestAuditNormalizer:
    def test_normalize_secret_get(self):
        raw = load_audit_samples()[0]  # READ_SECRET
        event = audit_normalize(raw)
        assert event is not None
        assert event.action == "get"
        assert event.target_resource == "secrets"

    def test_normalize_cronjob_create(self):
        raw = load_audit_samples()[2]  # CREATED_CRONJOB
        event = audit_normalize(raw)
        assert event is not None
        assert event.action == "create"
        assert event.target_resource == "cronjobs"


# ── Evidence Mapper 테스트 ────────────────────────────────────────────────

class TestEvidenceMapper:
    def test_map_sa_token(self):
        raw = load_tetragon_samples()[0]
        event = tetragon_normalize(raw)
        evidence = map_to_evidence(event)
        assert evidence is not None
        assert evidence.evidence_type == EvidenceType.ACCESSED_SA_TOKEN

    def test_map_kube_api_access(self):
        raw = load_tetragon_samples()[1]
        event = tetragon_normalize(raw)
        evidence = map_to_evidence(event)
        assert evidence is not None
        assert evidence.evidence_type == EvidenceType.KUBE_API_ACCESS

    def test_map_imds(self):
        raw = load_tetragon_samples()[2]
        event = tetragon_normalize(raw)
        evidence = map_to_evidence(event)
        assert evidence is not None
        assert evidence.evidence_type == EvidenceType.ACCESSED_IMDS

    def test_map_host_sensitive_path(self):
        raw = load_tetragon_samples()[3]
        event = tetragon_normalize(raw)
        evidence = map_to_evidence(event)
        assert evidence is not None
        assert evidence.evidence_type == EvidenceType.ACCESSED_HOST_SENSITIVE_PATH

    def test_map_read_secret(self):
        raw = load_audit_samples()[0]
        event = audit_normalize(raw)
        evidence = map_to_evidence(event)
        assert evidence is not None
        assert evidence.evidence_type == EvidenceType.READ_SECRET

    def test_map_created_cronjob(self):
        raw = load_audit_samples()[2]
        event = audit_normalize(raw)
        evidence = map_to_evidence(event)
        assert evidence is not None
        assert evidence.evidence_type == EvidenceType.CREATED_CRONJOB


# ── Verdict 테스트 (시나리오별 end-to-end) ────────────────────────────────

class TestVerdict:

    def _collect_evidences(self, tetragon_indices=[], audit_indices=[]):
        evidences = []
        tetragon_samples = load_tetragon_samples()
        audit_samples = load_audit_samples()

        for i in tetragon_indices:
            event = tetragon_normalize(tetragon_samples[i])
            evidence = map_to_evidence(event)
            if evidence:
                evidences.append(evidence)

        for i in audit_indices:
            event = audit_normalize(audit_samples[i])
            evidence = map_to_evidence(event)
            if evidence:
                evidences.append(evidence)

        return evidences

    def test_scenario1_path_possible(self):
        """evidence 없으면 PATH_POSSIBLE"""
        state = determine_verdict("path-001", "scenario_1_external_exposure_aws", [])
        assert state.verdict == PathVerdict.PATH_POSSIBLE

    def test_scenario1_path_observed(self):
        """SUSPICIOUS_EXECUTION + ACCESSED_SA_TOKEN → PATH_OBSERVED"""
        evidences = self._collect_evidences(tetragon_indices=[0])  # SA token
        state = determine_verdict("path-001", "scenario_1_external_exposure_aws", evidences)
        assert state.verdict == PathVerdict.PATH_OBSERVED

    def test_scenario1_expansion_attempt(self):
        """ACCESSED_IMDS → EXPANSION_ATTEMPT_OBSERVED"""
        evidences = self._collect_evidences(tetragon_indices=[2])  # IMDS
        state = determine_verdict("path-001", "scenario_1_external_exposure_aws", evidences)
        assert state.verdict == PathVerdict.EXPANSION_ATTEMPT_OBSERVED

    def test_scenario2_path_partially_confirmed(self):
        """READ_SECRET → PATH_PARTIALLY_CONFIRMED"""
        evidences = self._collect_evidences(audit_indices=[0])  # READ_SECRET
        state = determine_verdict("path-002", "scenario_2_supply_chain_data_exfil", evidences)
        assert state.verdict == PathVerdict.PATH_PARTIALLY_CONFIRMED

    def test_scenario3_expansion_attempt(self):
        """CREATED_DAEMONSET → EXPANSION_ATTEMPT_OBSERVED"""
        evidences = self._collect_evidences(audit_indices=[3])  # CREATED_DAEMONSET
        state = determine_verdict("path-003", "scenario_3_neglected_resource_expansion", evidences)
        assert state.verdict == PathVerdict.EXPANSION_ATTEMPT_OBSERVED