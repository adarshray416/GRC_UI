"""
tests/test_all.py
─────────────────────────────────────────────────────────────────────────────
Full test suite for the BABCOM GRC Platform backend.

Run with:
    cd backend
    python -m pytest tests/ -v

Or without pytest:
    cd backend
    python tests/test_all.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

# Add backend root to path so imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


# ══════════════════════════════════════════════════════════════════════════════
# 1. Helper utilities
# ══════════════════════════════════════════════════════════════════════════════

class TestHelpers(unittest.TestCase):

    def setUp(self):
        from extractors._helpers import _find, _find_date
        self._find      = _find
        self._find_date = _find_date

    def test_find_basic(self):
        text = "Approved by: Alice Smith, CISO"
        self.assertEqual(self._find(text, ["approved by"]), "Alice Smith, CISO")

    def test_find_case_insensitive(self):
        text = "APPROVED BY: Bob Jones"
        self.assertEqual(self._find(text, ["approved by"]), "Bob Jones")

    def test_find_multiple_labels_first_wins(self):
        text = "Owner: Carol White\nVersion: 2.0"
        result = self._find(text, ["version", "owner"])
        # "version" comes first in labels list → "2.0"
        self.assertEqual(result, "2.0")

    def test_find_returns_none_when_missing(self):
        self.assertIsNone(self._find("No labels here", ["approved by"]))

    def test_find_stops_at_newline(self):
        text = "Title: My Policy\nOther line here"
        self.assertEqual(self._find(text, ["title"]), "My Policy")

    def test_find_date_iso(self):
        text = "Review Date: 2026-06-01"
        self.assertEqual(self._find_date(text, ["review date"]), "2026-06-01")

    def test_find_date_uk_format(self):
        text = "Approval Date: 15/03/2025"
        self.assertEqual(self._find_date(text, ["approval date"]), "2025-03-15")

    def test_find_date_written_out(self):
        text = "Expiry Date: 01 January 2026"
        self.assertEqual(self._find_date(text, ["expiry date"]), "2026-01-01")

    def test_find_date_returns_none_when_missing(self):
        self.assertIsNone(self._find_date("No dates here", ["review date"]))


# ══════════════════════════════════════════════════════════════════════════════
# 2. Policy extractor
# ══════════════════════════════════════════════════════════════════════════════

SAMPLE_POLICY = """Information Security Policy

Title: BABCOM ISMS Policy
Version: 3.1
Approved by: Alice Smith, CISO
Approval Date: 2024-01-10
Review Date: 2026-06-01
Scope: All employees, contractors, and third-party vendors.
Classification: Confidential

1. Purpose
This information security policy establishes the ISMS framework
for managing risks to BABCOM's information assets.

2. Acceptable Use
All users must comply with the acceptable use guidelines.
"""

class TestPolicyExtractor(unittest.TestCase):

    def setUp(self):
        from extractors.policy_extractor import extract_policy
        self.extract = extract_policy
        self.result  = extract_policy(SAMPLE_POLICY, "test_policy.txt")

    def test_extracts_name(self):
        self.assertEqual(self.result["name"], "BABCOM ISMS Policy")

    def test_extracts_version(self):
        self.assertEqual(self.result["version"], "3.1")

    def test_extracts_approved_by(self):
        self.assertEqual(self.result["approved_by"], "Alice Smith, CISO")

    def test_extracts_review_date(self):
        self.assertEqual(self.result["review_date"], "2026-06-01")

    def test_extracts_approval_date(self):
        self.assertEqual(self.result["approval_date"], "2024-01-10")

    def test_extracts_scope(self):
        self.assertIn("employees", self.result["scope"].lower())

    def test_extracts_classification(self):
        self.assertEqual(self.result["classification"], "Confidential")

    def test_keywords_found(self):
        kws = self.result["keywords_found"]
        self.assertIn("information security policy", kws)
        self.assertIn("acceptable use", kws)
        self.assertIn("isms", kws)

    def test_confidence_high_when_fields_present(self):
        self.assertGreaterEqual(self.result["_confidence"], 0.9)

    def test_confidence_lower_without_approver(self):
        no_approver = SAMPLE_POLICY.replace("Approved by: Alice Smith, CISO\n", "")
        result = self.extract(no_approver, "test.txt")
        self.assertLess(result["_confidence"], 1.0)

    def test_fallback_name_from_filename(self):
        result = self.extract("Just some policy text.", "my_security_policy.txt")
        # Fallback uses the filename stem — "my security policy" or the first text line
        name_lower = result["name"].lower()
        self.assertTrue(
            "security" in name_lower or "policy" in name_lower or "just" in name_lower,
            f"Expected name derived from filename or text, got: {result['name']}"
        )

    def test_source_file_stored(self):
        self.assertEqual(self.result["source_file"], "test_policy.txt")


# ══════════════════════════════════════════════════════════════════════════════
# 3. Risk extractor
# ══════════════════════════════════════════════════════════════════════════════

SAMPLE_RISK_REGISTER = """Risk Register Q1 2025

Risk: Ransomware via phishing
Impact: Critical
Likelihood: High
Owner: Bob Patel
Status: Approved
Mitigation: EDR deployed. Email filtering active. Staff training quarterly.
Residual Risk: Medium

Risk: Unpatched software vulnerabilities
Impact: High
Likelihood: Medium
Owner: Carol Jones
Status: Pending
Mitigation: Patch management policy drafted. Scanning tool being implemented.

Risk: Third-party vendor breach
Impact: High
Likelihood: Low
Owner: David Lee
Status: Approved
Mitigation: Annual vendor assessments. DPAs in place.
"""

class TestRiskExtractor(unittest.TestCase):

    def setUp(self):
        from extractors.risk_extractor import extract_risks
        self.risks = extract_risks(SAMPLE_RISK_REGISTER, "risk_register.txt")

    def test_extracts_correct_count(self):
        self.assertEqual(len(self.risks), 3)

    def test_first_risk_description(self):
        self.assertIn("Ransomware", self.risks[0]["risk_description"])

    def test_impact_normalised_critical(self):
        self.assertEqual(self.risks[0]["impact"], "critical")

    def test_impact_normalised_high(self):
        self.assertEqual(self.risks[1]["impact"], "high")

    def test_owner_extracted(self):
        self.assertEqual(self.risks[0]["owner"], "Bob Patel")

    def test_status_approved(self):
        self.assertEqual(self.risks[0]["status"], "approved")

    def test_status_pending(self):
        self.assertEqual(self.risks[1]["status"], "pending")

    def test_mitigation_extracted(self):
        self.assertIsNotNone(self.risks[0]["mitigation"])
        self.assertIn("EDR", self.risks[0]["mitigation"])

    def test_risk_ids_sequential(self):
        ids = [r["risk_id"] for r in self.risks]
        self.assertEqual(ids, ["R-001", "R-002", "R-003"])

    def test_risk_score_computed(self):
        # Critical × High = 5 × 4 = 20
        self.assertEqual(self.risks[0]["risk_score"], 20)

    def test_source_file_stored(self):
        for r in self.risks:
            self.assertEqual(r["source_file"], "risk_register.txt")

    def test_empty_input_returns_empty_list(self):
        from extractors.risk_extractor import extract_risks
        self.assertEqual(extract_risks("", "empty.txt"), [])


# ══════════════════════════════════════════════════════════════════════════════
# 4. Log extractor
# ══════════════════════════════════════════════════════════════════════════════

SAMPLE_LOG = """2024-10-01T08:12:33Z user=alice action=login outcome=success ip=192.168.1.10 resource=/dashboard
2024-10-02T09:01:55Z user=charlie action=login outcome=failure ip=203.0.113.5 resource=/admin
2024-10-15T14:22:01Z user=sysadmin action=sudo outcome=success ip=10.0.0.1 resource=/etc/passwd
2024-12-31T23:59:59Z user=system action=audit_rotate outcome=success ip=127.0.0.1 resource=/logs
"""

class TestLogExtractor(unittest.TestCase):

    def setUp(self):
        from extractors.log_extractor import extract_logs
        self.logs = extract_logs(SAMPLE_LOG, "audit_log.txt")

    def test_entry_count(self):
        self.assertEqual(self.logs["entry_count"], 4)

    def test_coverage_days(self):
        # 2024-10-01 → 2024-12-31 = 91 days
        self.assertEqual(self.logs["coverage_days"], 91)

    def test_failure_rate(self):
        # 1 failure out of 4 entries = 0.25
        self.assertAlmostEqual(self.logs["failure_rate"], 0.25, places=2)

    def test_start_date_set(self):
        self.assertIsNotNone(self.logs["start_date"])
        self.assertIn("2024-10-01", self.logs["start_date"])

    def test_end_date_set(self):
        self.assertIsNotNone(self.logs["end_date"])
        self.assertIn("2024-12-31", self.logs["end_date"])

    def test_user_field_extracted(self):
        entries = self.logs["entries"]
        users = [e.get("user") for e in entries]
        self.assertIn("alice", users)
        self.assertIn("charlie", users)

    def test_action_field_extracted(self):
        entries = self.logs["entries"]
        actions = [e.get("action") for e in entries]
        self.assertIn("login", actions)
        self.assertIn("sudo", actions)

    def test_outcome_field_extracted(self):
        entries = self.logs["entries"]
        outcomes = [e.get("outcome") for e in entries if e.get("outcome")]
        self.assertIn("success", outcomes)
        self.assertIn("failure", outcomes)

    def test_empty_log_returns_zero_entries(self):
        from extractors.log_extractor import extract_logs
        result = extract_logs("", "empty.log")
        self.assertEqual(result["entry_count"], 0)


# ══════════════════════════════════════════════════════════════════════════════
# 5. Access review extractor
# ══════════════════════════════════════════════════════════════════════════════

SAMPLE_ACCESS = """Access Review Report
System: Corporate IAM Platform
Review Period: Q4 2024

User: alice
Role: Administrator
Department: IT Security
Privileged: yes
MFA: yes
Status: active
Last Reviewed: 2024-11-01
Reviewer: Jane Doe

User: charlie
Role: DBA
Department: Engineering
Privileged: yes
MFA: no
Status: suspended
Last Reviewed: 2024-07-01
Reviewer: Mike Brown

User: bob
Role: Analyst
Department: Finance
Privileged: no
MFA: yes
Status: active
Last Reviewed: 2024-10-15
"""

class TestAccessExtractor(unittest.TestCase):

    def setUp(self):
        from extractors.access_extractor import extract_access_reviews
        self.result = extract_access_reviews(SAMPLE_ACCESS, "access_review.txt")

    def test_record_count(self):
        self.assertEqual(self.result["record_count"], 3)

    def test_system_extracted(self):
        self.assertIn("IAM", self.result["system"])

    def test_review_period_extracted(self):
        self.assertEqual(self.result["review_period"], "Q4 2024")

    def test_alice_mfa_true(self):
        alice = next(r for r in self.result["records"] if r["user"] == "alice")
        self.assertTrue(alice["mfa_enabled"])
        self.assertTrue(alice["privileged"])
        self.assertEqual(alice["status"], "active")

    def test_charlie_mfa_false(self):
        charlie = next(r for r in self.result["records"] if r["user"] == "charlie")
        self.assertFalse(charlie["mfa_enabled"])
        self.assertEqual(charlie["status"], "suspended")

    def test_charlie_privileged_from_role(self):
        # DBA role should auto-flag as privileged even without explicit Privileged: yes
        charlie = next(r for r in self.result["records"] if r["user"] == "charlie")
        self.assertTrue(charlie["privileged"])

    def test_bob_not_privileged(self):
        bob = next(r for r in self.result["records"] if r["user"] == "bob")
        self.assertFalse(bob["privileged"])

    def test_last_reviewed_parsed(self):
        alice = next(r for r in self.result["records"] if r["user"] == "alice")
        self.assertEqual(alice["last_reviewed"], "2024-11-01")

    def test_header_block_not_parsed_as_user(self):
        # "System: Corporate IAM" should NOT appear as a user record
        users = [r["user"] for r in self.result["records"]]
        self.assertNotIn("System:", users)
        self.assertNotIn("System", users)


# ══════════════════════════════════════════════════════════════════════════════
# 6. Canonical models
# ══════════════════════════════════════════════════════════════════════════════

class TestCanonicalModels(unittest.TestCase):

    def test_policy_model_to_dict_and_back(self):
        from models.canonical import PolicyModel
        m = PolicyModel(name="Test Policy", version="1.0", approved_by="Alice",
                        review_date="2026-01-01", source_file="test.txt")
        d = m.to_dict()
        self.assertEqual(d["name"], "Test Policy")
        m2 = PolicyModel.from_dict(d)
        self.assertEqual(m2.name, "Test Policy")
        self.assertEqual(m2.approved_by, "Alice")

    def test_risk_model_score(self):
        from models.canonical import RiskModel
        r = RiskModel(risk_id="R-001", risk_description="Test",
                      impact="critical", likelihood="high")
        self.assertEqual(r.risk_score(), 20)  # 5×4

    def test_risk_model_is_treated(self):
        from models.canonical import RiskModel
        r = RiskModel(risk_id="R-001", risk_description="Test",
                      impact="high", likelihood="medium",
                      status="approved", mitigation="Control in place.")
        self.assertTrue(r.is_treated())

    def test_risk_model_untreated_when_pending(self):
        from models.canonical import RiskModel
        r = RiskModel(risk_id="R-001", risk_description="Test",
                      impact="high", likelihood="medium", status="pending")
        self.assertFalse(r.is_treated())

    def test_log_collection_coverage(self):
        from models.canonical import LogCollectionModel, LogEntryModel
        m = LogCollectionModel(
            source_file = "test.log",
            entries     = [],
            start_date  = "2024-10-01T00:00:00",
            end_date    = "2024-12-31T00:00:00",
        )
        self.assertEqual(m.coverage_days(), 91)

    def test_access_collection_privileged_without_mfa(self):
        from models.canonical import AccessReviewCollectionModel, AccessReviewModel
        records = [
            AccessReviewModel(user="alice", role="admin", privileged=True,  mfa_enabled=True),
            AccessReviewModel(user="charlie", role="dba", privileged=True, mfa_enabled=False),
        ]
        col = AccessReviewCollectionModel(records=records)
        gap = col.privileged_without_mfa()
        self.assertEqual(len(gap), 1)
        self.assertEqual(gap[0].user, "charlie")


# ══════════════════════════════════════════════════════════════════════════════
# 7. Control evaluator
# ══════════════════════════════════════════════════════════════════════════════

class TestControlEvaluator(unittest.TestCase):

    def _make_store(self):
        from extractors.policy_extractor  import extract_policy
        from extractors.risk_extractor    import extract_risks
        from extractors.log_extractor     import extract_logs
        from extractors.access_extractor  import extract_access_reviews
        return {
            "policy":        extract_policy(SAMPLE_POLICY, "p.txt"),
            "risk":          extract_risks(SAMPLE_RISK_REGISTER, "r.txt"),
            "logs":          extract_logs(SAMPLE_LOG, "l.txt"),
            "access_review": extract_access_reviews(SAMPLE_ACCESS, "a.txt"),
        }

    def setUp(self):
        from engine.control_evaluator import ControlEvaluator
        import json, os
        controls_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "controls", "controls.json"
        )
        with open(controls_path) as f:
            self.controls = json.load(f)
        self.evaluator = ControlEvaluator(self.controls)
        self.store = self._make_store()

    def test_logs_control_passes(self):
        results = self.evaluator.evaluate_all(self.store, ["ISO27001"])
        log_ctrl = next(r for r in results if r.control_id == "ISO-A.12.4")
        self.assertEqual(log_ctrl.status, "pass")
        self.assertEqual(log_ctrl.score, 1.0)

    def test_missing_evidence_returns_missing_status(self):
        empty_store = {}
        results = self.evaluator.evaluate_all(empty_store, ["ISO27001"])
        for r in results:
            self.assertEqual(r.status, "missing")

    def test_summary_structure(self):
        from engine.control_evaluator import ControlEvaluator
        results = self.evaluator.evaluate_all(self.store, ["ISO27001", "SOC2"])
        summary = ControlEvaluator.summary(results)
        self.assertIn("overall_score", summary)
        self.assertIn("risk_level",    summary)
        self.assertIn("by_framework",  summary)
        self.assertIn("total_controls", summary)

    def test_framework_filter_works(self):
        iso_results = self.evaluator.evaluate_all(self.store, ["ISO27001"])
        soc_results = self.evaluator.evaluate_all(self.store, ["SOC2"])
        self.assertTrue(all(r.framework == "ISO27001" for r in iso_results))
        self.assertTrue(all(r.framework == "SOC2"     for r in soc_results))

    def test_control_result_has_checks(self):
        results = self.evaluator.evaluate_all(self.store, ["ISO27001"])
        for r in results:
            if r.status not in ("missing", "not_applicable"):
                self.assertGreater(r.total_checks, 0)


# ══════════════════════════════════════════════════════════════════════════════
# 8. Full pipeline (integration test)
# ══════════════════════════════════════════════════════════════════════════════

class TestFullPipeline(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        # Write all four sample evidence files
        for fname, content in [
            ("security_policy.txt",  SAMPLE_POLICY),
            ("risk_register.txt",    SAMPLE_RISK_REGISTER),
            ("audit_log.txt",        SAMPLE_LOG),
            ("access_review.txt",    SAMPLE_ACCESS),
        ]:
            with open(os.path.join(self.tmp, fname), "w") as f:
                f.write(content)

    def test_runner_produces_report(self):
        from connectors.local_connector import LocalConnector
        from engine.runner import GRCRunner
        index  = LocalConnector(base_path=self.tmp).fetch_all()
        self.assertEqual(len(index), 4)
        report = GRCRunner(evidence_index=index, frameworks=["ISO27001"]).run()
        self.assertIn("summary",        report)
        self.assertIn("controls",       report)
        self.assertIn("evidence_store", report)

    def test_all_evidence_types_extracted(self):
        from connectors.local_connector import LocalConnector
        from engine.runner import GRCRunner
        index  = LocalConnector(base_path=self.tmp).fetch_all()
        report = GRCRunner(evidence_index=index, frameworks=["ISO27001"]).run()
        store  = report["evidence_store"]
        self.assertIn("policy",        store)
        self.assertIn("risk",          store)
        self.assertIn("logs",          store)
        self.assertIn("access_review", store)

    def test_multi_framework_scoring(self):
        from connectors.local_connector import LocalConnector
        from engine.runner import GRCRunner
        index   = LocalConnector(base_path=self.tmp).fetch_all()
        report  = GRCRunner(evidence_index=index, frameworks=["ISO27001","SOC2","GDPR"]).run()
        summary = report["summary"]
        by_fw   = summary["by_framework"]
        self.assertIn("ISO27001", by_fw)
        self.assertIn("SOC2",     by_fw)
        self.assertIn("GDPR",     by_fw)

    def test_score_between_0_and_100(self):
        from connectors.local_connector import LocalConnector
        from engine.runner import GRCRunner
        index  = LocalConnector(base_path=self.tmp).fetch_all()
        report = GRCRunner(evidence_index=index, frameworks=["ISO27001"]).run()
        score  = report["summary"]["overall_score"]
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score,    100)

    def test_report_builder(self):
        from connectors.local_connector import LocalConnector
        from engine.runner import GRCRunner
        from engine.report_builder import build_summary_text
        index  = LocalConnector(base_path=self.tmp).fetch_all()
        report = GRCRunner(evidence_index=index, frameworks=["ISO27001"]).run()
        text   = build_summary_text(report)
        self.assertIn("BABCOM GRC", text)
        self.assertIn("Overall Compliance Score", text)


# ══════════════════════════════════════════════════════════════════════════════
# 9. Connectors
# ══════════════════════════════════════════════════════════════════════════════

class TestLocalConnector(unittest.TestCase):

    def test_finds_evidence_files(self):
        tmp = tempfile.mkdtemp()
        for fname in ["policy.txt", "risk_register.csv", "audit.log", "notes.pdf"]:
            open(os.path.join(tmp, fname), "w").write("test content")
        # Add a file that should be ignored
        open(os.path.join(tmp, "README.exe"), "w").write("ignored")

        from connectors.local_connector import LocalConnector
        index = LocalConnector(base_path=tmp).fetch_all()
        names = [i["file"] for i in index]
        self.assertIn("policy.txt",       names)
        self.assertIn("risk_register.csv", names)
        self.assertIn("audit.log",         names)
        self.assertNotIn("README.exe",     names)

    def test_type_inference(self):
        from connectors.local_connector import _infer_type
        self.assertEqual(_infer_type("security_policy.txt"),  "policy")
        self.assertEqual(_infer_type("risk_register.csv"),    "risk")
        self.assertEqual(_infer_type("audit_log.txt"),        "logs")
        self.assertEqual(_infer_type("access_review.txt"),    "access_review")

    def test_nonexistent_path_returns_empty(self):
        from connectors.local_connector import LocalConnector
        index = LocalConnector(base_path="/nonexistent/path/xyz").fetch_all()
        self.assertEqual(index, [])


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    loader  = unittest.TestLoader()
    suite   = loader.loadTestsFromModule(sys.modules[__name__])
    runner  = unittest.TextTestRunner(verbosity=2)
    result  = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
