"""
engine/control_evaluator.py

Model-based control evaluator.
Replaces keyword matching with typed field validation against canonical models.

Pipeline:
  canonical JSON dict → model object → typed checks → ControlResult
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Dict, List, Optional

from models.policy_model import PolicyModel
from models.risk_model import RiskModel
from models.log_model import LogCollectionModel, LogEntryModel
from models.access_model import AccessReviewCollectionModel, AccessReviewModel


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    check_id:    str
    description: str
    passed:      bool
    actual:      Any    = None
    expected:    Any    = None
    detail:      str    = ""

@dataclass
class ControlResult:
    control_id:     str
    control_name:   str
    status:         str          # pass / fail / partial / missing / not_applicable
    score:          float        # 0.0 – 1.0
    checks:         List[CheckResult] = field(default_factory=list)
    evidence_files: List[str]         = field(default_factory=list)
    recommendation: str               = ""
    framework_ref:  str               = ""

    @property
    def passed_checks(self) -> int:
        return sum(1 for c in self.checks if c.passed)

    @property
    def total_checks(self) -> int:
        return len(self.checks)

    def to_dict(self) -> dict:
        return {
            "control_id":     self.control_id,
            "control_name":   self.control_name,
            "status":         self.status,
            "score":          round(self.score * 100, 1),
            "passed_checks":  sum(1 for c in self.checks if c.passed),
            "total_checks":   len(self.checks),
            "evidence_files": self.evidence_files,
            "recommendation": self.recommendation,
            "framework_ref":  self.framework_ref,
            "checks": [
                {
                    "check_id":    c.check_id,
                    "description": c.description,
                    "passed":      c.passed,
                    "actual":      str(c.actual) if c.actual is not None else None,
                    "expected":    str(c.expected) if c.expected is not None else None,
                    "detail":      c.detail,
                }
                for c in self.checks
            ],
        }


# ── Individual check functions ────────────────────────────────────────────────

def _check_policy_approved(m: PolicyModel) -> CheckResult:
    passed = bool(m.approved_by and m.approved_by.strip())
    return CheckResult("policy.approved_by", "Policy has a named approver",
                       passed, m.approved_by, "non-empty name",
                       "" if passed else "No approver recorded in document.")

def _check_policy_current(m: PolicyModel, max_age_days: int = 365) -> CheckResult:
    today = date.today()
    if not m.review_date:
        return CheckResult("policy.review_date",
                           f"Policy reviewed within {max_age_days} days",
                           False, None, f"date ≥ {today}", "No review date found.")
    try:
        rd = date.fromisoformat(m.review_date)
    except Exception:
        return CheckResult("policy.review_date", f"Policy reviewed within {max_age_days} days",
                           False, m.review_date, f"date ≥ {today}", "Could not parse review date.")
    passed = rd >= today
    days   = (rd - today).days
    return CheckResult("policy.review_date", f"Policy reviewed within {max_age_days} days",
                       passed, str(rd), f"≥ {today}",
                       f"Valid for {days} more days." if passed else f"Expired {abs(days)} days ago.")

def _check_policy_version(m: PolicyModel) -> CheckResult:
    passed = bool(m.version)
    return CheckResult("policy.version", "Policy has a version number",
                       passed, m.version, "any version string",
                       "" if passed else "No version number found.")

def _check_logs_not_empty(m: LogCollectionModel) -> CheckResult:
    passed = len(m.entries) > 0
    return CheckResult("logs.not_empty", "Log file contains entries",
                       passed, f"{len(m.entries)} entries", "> 0 entries",
                       "" if passed else "Log parsed but contained no entries.")

def _check_logs_coverage(m: LogCollectionModel, min_days: int = 90) -> CheckResult:
    days   = m.coverage_days()
    passed = days is not None and days >= min_days
    return CheckResult("logs.coverage_days", f"Logs cover ≥ {min_days} days",
                       passed, f"{days} days" if days is not None else "unknown",
                       f"≥ {min_days} days",
                       f"Only {days} days found." if (days is not None and not passed) else "")

def _check_logs_timestamps(m: LogCollectionModel) -> CheckResult:
    if not m.entries:
        return CheckResult("logs.timestamps", "All entries have timestamps",
                           False, "0 entries", "> 0 timestamped entries")
    missing = sum(1 for e in m.entries if e.timestamp is None)
    passed  = missing == 0
    return CheckResult("logs.timestamps", "All log entries have timestamps",
                       passed, f"{missing} missing timestamps", "0 missing",
                       f"{missing} entries lacked a timestamp." if not passed else "")

def _check_access_mfa(m: AccessReviewCollectionModel) -> CheckResult:
    priv_no_mfa = m.privileged_without_mfa()
    passed = len(priv_no_mfa) == 0
    return CheckResult("access.mfa_privileged", "All privileged accounts have MFA",
                       passed, f"{len(priv_no_mfa)} without MFA", "0 accounts",
                       f"Users: {[r.user for r in priv_no_mfa]}" if not passed else "")

def _check_access_cadence(m: AccessReviewCollectionModel, max_days: int = 90) -> CheckResult:
    overdue = m.overdue_reviews(max_days)
    passed  = len(overdue) == 0
    return CheckResult("access.review_cadence", f"All reviews done within {max_days} days",
                       passed, f"{len(overdue)} overdue", "0 overdue",
                       f"Overdue: {[r.user for r in overdue[:5]]}" if not passed else "")

def _check_access_revocation(m: AccessReviewCollectionModel) -> CheckResult:
    suspended = [r for r in m.records if r.status == "suspended"]
    passed    = len(suspended) == 0
    return CheckResult("access.revocation", "No suspended accounts hold active access",
                       passed, f"{len(suspended)} suspended", "0 suspended",
                       f"Accounts: {[r.user for r in suspended[:5]]}" if not passed else "")

def _check_risk_owner(m: RiskModel) -> CheckResult:
    passed = bool(m.owner and m.owner.strip())
    return CheckResult("risk.owner", "Risk has a named owner",
                       passed, m.owner, "non-empty name",
                       f"Risk '{m.risk_description[:60]}' has no owner." if not passed else "")

def _check_risk_treatment(m: RiskModel) -> CheckResult:
    passed = m.is_treated()
    return CheckResult("risk.treatment", "Risk has approved mitigation",
                       passed,
                       f"status={m.status}, mitigation={'yes' if m.mitigation else 'no'}",
                       "status=approved AND mitigation present",
                       "" if passed else "Risk untreated or awaiting approval.")


# ── Control runner ────────────────────────────────────────────────────────────

class ControlEvaluator:
    """
    Loads control definitions from controls.json.
    Evaluates each control against the canonical store.
    """

    EVIDENCE_TYPE_CHECKS = {
        "policy": [
            (_check_policy_approved, {}),
            (_check_policy_current,  {"max_age_days": 365}),
            (_check_policy_version,  {}),
        ],
        "logs": [
            (_check_logs_not_empty,   {}),
            (_check_logs_coverage,    {"min_days": 90}),
            (_check_logs_timestamps,  {}),
        ],
        "access_review": [
            (_check_access_mfa,        {}),
            (_check_access_cadence,    {"max_days": 90}),
            (_check_access_revocation, {}),
        ],
        "risk": [
            (_check_risk_owner,     {}),
            (_check_risk_treatment, {}),
        ],
    }

    def __init__(self, controls_path: str = "controls/controls.json"):
        with open(controls_path, "r") as f:
            raw = json.load(f)
        self.controls = raw if isinstance(raw, list) else raw.get("controls", [])

    def _load_canonical(self, evidence_type: str, canonical_store: dict) -> Optional[Any]:
        """Reconstruct a model object from canonical store data."""
        data = canonical_store.get(evidence_type)
        if not data:
            return None
        try:
            if evidence_type == "policy":
                return PolicyModel.from_dict(data)
            if evidence_type == "risk":
                if isinstance(data, list):
                    return [RiskModel.from_dict(r) for r in data]
                return RiskModel.from_dict(data)
            if evidence_type == "logs":
                return LogCollectionModel.from_dict(data)
            if evidence_type == "access_review":
                return AccessReviewCollectionModel.from_dict(data)
        except Exception as e:
            return None
        return None

    def evaluate_control(self, control: dict, canonical_store: dict) -> ControlResult:
        cid   = control.get("control_id", "?")
        cname = control.get("name", "Unknown")
        etype = control.get("evidence_type", "")
        fref  = control.get("framework_ref", "")
        rec   = control.get("recommendation", "")

        model = self._load_canonical(etype, canonical_store)

        if model is None:
            return ControlResult(cid, cname, "missing", 0.0,
                                 recommendation=f"No {etype} evidence found. {rec}",
                                 framework_ref=fref)

        check_defs = self.EVIDENCE_TYPE_CHECKS.get(etype, [])
        checks: List[CheckResult] = []

        # Handle list of models (e.g. multiple risk entries)
        models = model if isinstance(model, list) else [model]

        for m in models:
            for fn, kwargs in check_defs:
                try:
                    checks.append(fn(m, **kwargs))
                except Exception as e:
                    checks.append(CheckResult(fn.__name__, "Execution error",
                                              False, None, None, str(e)))

        if not checks:
            return ControlResult(cid, cname, "not_applicable", 1.0, framework_ref=fref)

        passed = sum(1 for c in checks if c.passed)
        score  = passed / len(checks)
        status = "pass" if score == 1.0 else "fail" if score == 0.0 else "partial"

        return ControlResult(
            control_id     = cid,
            control_name   = cname,
            status         = status,
            score          = score,
            checks         = checks,
            evidence_files = list(canonical_store.get("_files", {}).get(etype, [])),
            recommendation = rec if status != "pass" else "",
            framework_ref  = fref,
        )

    def evaluate_all(self, canonical_store: dict) -> List[ControlResult]:
        return [self.evaluate_control(c, canonical_store) for c in self.controls]

    @staticmethod
    def summary(results: List[ControlResult]) -> dict:
        total  = len(results)
        counts = {"pass": 0, "partial": 0, "fail": 0, "missing": 0, "not_applicable": 0}
        for r in results:
            counts[r.status] = counts.get(r.status, 0) + 1

        scored = [r for r in results if r.status not in ("missing", "not_applicable")]
        overall = sum(r.score for r in scored) / len(scored) if scored else 0.0

        return {
            "total_controls": total,
            **counts,
            "overall_score": round(overall * 100, 1),
            "risk_level": (
                "Critical" if overall < 0.5 else
                "High"     if overall < 0.7 else
                "Medium"   if overall < 0.9 else
                "Low"
            ),
        }
