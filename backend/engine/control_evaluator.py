"""engine/control_evaluator.py — model-based, multi-framework"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import date
from typing import Any, List, Optional
from models.canonical import PolicyModel, RiskModel, LogCollectionModel, AccessReviewCollectionModel, AccessReviewModel

@dataclass
class CheckResult:
    check_id: str; description: str; passed: bool
    actual: Any = None; expected: Any = None; detail: str = ""

@dataclass
class ControlResult:
    control_id: str; control_name: str; framework: str
    status: str; score: float
    checks: List[CheckResult] = field(default_factory=list)
    evidence_files: List[str] = field(default_factory=list)
    recommendation: str = ""; framework_ref: str = ""

    @property
    def passed_checks(self): return sum(1 for c in self.checks if c.passed)
    @property
    def total_checks(self): return len(self.checks)

    def to_dict(self):
        return {
            "control_id": self.control_id, "control_name": self.control_name,
            "framework": self.framework, "status": self.status,
            "score": round(self.score * 100, 1),
            "passed_checks": self.passed_checks, "total_checks": self.total_checks,
            "evidence_files": self.evidence_files,
            "recommendation": self.recommendation, "framework_ref": self.framework_ref,
            "checks": [{"check_id":c.check_id,"description":c.description,"passed":c.passed,
                        "actual":str(c.actual) if c.actual is not None else None,
                        "expected":str(c.expected) if c.expected is not None else None,
                        "detail":c.detail} for c in self.checks],
        }

# ── Check functions ───────────────────────────────────────────────────────────
def _chk_policy_approved(m: PolicyModel) -> CheckResult:
    ok = bool(m.approved_by and m.approved_by.strip())
    return CheckResult("policy.approved_by","Policy has named approver",ok,m.approved_by,"non-empty",
                       "" if ok else "No approver found.")

def _chk_policy_current(m: PolicyModel) -> CheckResult:
    today = date.today()
    if not m.review_date:
        return CheckResult("policy.review_date","Policy review date present",False,None,f"≥{today}","No review date.")
    try:
        rd = date.fromisoformat(m.review_date)
        ok = rd >= today
        days = (rd - today).days
        return CheckResult("policy.review_date",f"Policy not expired",ok,str(rd),f"≥{today}",
                           f"Valid {days} more days." if ok else f"Expired {abs(days)} days ago.")
    except:
        return CheckResult("policy.review_date","Policy not expired",False,m.review_date,f"≥{today}","Parse error.")

def _chk_policy_version(m: PolicyModel) -> CheckResult:
    ok = bool(m.version)
    return CheckResult("policy.version","Policy has version number",ok,m.version,"any version","" if ok else "No version.")

def _chk_logs_not_empty(m: LogCollectionModel) -> CheckResult:
    ok = len(m.entries) > 0
    return CheckResult("logs.not_empty","Log file has entries",ok,f"{len(m.entries)} entries",">0","" if ok else "Empty log.")

def _chk_logs_coverage(m: LogCollectionModel, min_days: int = 90) -> CheckResult:
    days = m.coverage_days()
    ok   = days is not None and days >= min_days
    return CheckResult("logs.coverage",f"Logs cover ≥{min_days} days",ok,
                       f"{days}d" if days else "?",f"≥{min_days}d",f"Only {days}d." if (days and not ok) else "")

def _chk_logs_timestamps(m: LogCollectionModel) -> CheckResult:
    if not m.entries:
        return CheckResult("logs.timestamps","All entries have timestamps",False,"0 entries",">0 entries")
    miss = sum(1 for e in m.entries if not e.timestamp)
    ok   = miss == 0
    return CheckResult("logs.timestamps","All entries timestamped",ok,f"{miss} missing","0 missing",
                       f"{miss} entries lack timestamps." if not ok else "")

def _chk_access_mfa(m: AccessReviewCollectionModel) -> CheckResult:
    bad = m.privileged_without_mfa()
    ok  = len(bad) == 0
    return CheckResult("access.mfa","All privileged accounts have MFA",ok,
                       f"{len(bad)} without MFA","0",f"Users: {[r.user for r in bad]}" if not ok else "")

def _chk_access_cadence(m: AccessReviewCollectionModel, max_days: int = 90) -> CheckResult:
    od = m.overdue_reviews(max_days)
    ok = len(od) == 0
    return CheckResult("access.cadence",f"Reviews within {max_days}d",ok,
                       f"{len(od)} overdue","0",f"Overdue: {[r.user for r in od[:5]]}" if not ok else "")

def _chk_access_revoke(m: AccessReviewCollectionModel) -> CheckResult:
    sus = [r for r in m.records if r.status == "suspended"]
    ok  = len(sus) == 0
    return CheckResult("access.revocation","No suspended accounts active",ok,
                       f"{len(sus)} suspended","0",f"Accounts: {[r.user for r in sus[:5]]}" if not ok else "")

def _chk_risk_owner(m: RiskModel) -> CheckResult:
    ok = bool(m.owner and m.owner.strip())
    return CheckResult("risk.owner","Risk has named owner",ok,m.owner,"non-empty",
                       f"'{m.risk_description[:50]}' has no owner." if not ok else "")

def _chk_risk_treatment(m: RiskModel) -> CheckResult:
    ok = m.is_treated()
    return CheckResult("risk.treatment","Risk has approved mitigation",ok,
                       f"status={m.status},mit={'y' if m.mitigation else 'n'}","approved+mitigation",
                       "" if ok else "Untreated or pending approval.")

# ── Check registry ────────────────────────────────────────────────────────────
CHECKS = {
    "policy":        [(_chk_policy_approved,{}),(_chk_policy_current,{}),(_chk_policy_version,{})],
    "logs":          [(_chk_logs_not_empty,{}),(_chk_logs_coverage,{"min_days":90}),(_chk_logs_timestamps,{})],
    "access_review": [(_chk_access_mfa,{}),(_chk_access_cadence,{"max_days":90}),(_chk_access_revoke,{})],
    "risk":          [(_chk_risk_owner,{}),(_chk_risk_treatment,{})],
}

# ── Evaluator ─────────────────────────────────────────────────────────────────
class ControlEvaluator:
    def __init__(self, controls: list):
        self.controls = controls

    def _load(self, etype: str, store: dict):
        d = store.get(etype)
        if not d: return None
        try:
            if etype == "policy":        return PolicyModel.from_dict(d)
            if etype == "logs":          return LogCollectionModel.from_dict(d)
            if etype == "access_review": return AccessReviewCollectionModel.from_dict(d)
            if etype == "risk":
                return [RiskModel.from_dict(r) for r in (d if isinstance(d, list) else [d])]
        except: return None

    def evaluate_control(self, ctrl: dict, store: dict) -> ControlResult:
        cid   = ctrl["control_id"]; cname = ctrl["name"]
        fw    = ctrl.get("framework",""); etype = ctrl.get("evidence_type","")
        fref  = ctrl.get("framework_ref",""); rec = ctrl.get("recommendation","")
        model = self._load(etype, store)
        if model is None:
            return ControlResult(cid, cname, fw, "missing", 0.0,
                                 recommendation=f"No {etype} evidence. {rec}", framework_ref=fref)
        check_defs = CHECKS.get(etype, [])
        checks: List[CheckResult] = []
        models = model if isinstance(model, list) else [model]
        for m in models:
            for fn, kwargs in check_defs:
                try: checks.append(fn(m, **kwargs))
                except Exception as e: checks.append(CheckResult(fn.__name__,"Error",False,None,None,str(e)))
        if not checks:
            return ControlResult(cid, cname, fw, "not_applicable", 1.0, framework_ref=fref)
        passed = sum(1 for c in checks if c.passed)
        score  = passed / len(checks)
        status = "pass" if score == 1.0 else "fail" if score == 0.0 else "partial"
        return ControlResult(cid, cname, fw, status, score, checks,
                             list(store.get("_files",{}).get(etype,[])),
                             rec if status != "pass" else "", fref)

    def evaluate_all(self, store: dict, frameworks: list = None) -> List[ControlResult]:
        targets = [c for c in self.controls
                   if not frameworks or c.get("framework","").upper() in [f.upper() for f in frameworks]]
        return [self.evaluate_control(c, store) for c in targets]

    @staticmethod
    def summary(results: List[ControlResult]) -> dict:
        total  = len(results)
        counts = {"pass":0,"partial":0,"fail":0,"missing":0,"not_applicable":0}
        by_fw: dict = {}
        for r in results:
            counts[r.status] = counts.get(r.status,0) + 1
            fw = r.framework
            if fw not in by_fw:
                by_fw[fw] = {"pass":0,"partial":0,"fail":0,"missing":0,"total":0}
            by_fw[fw][r.status] = by_fw[fw].get(r.status,0) + 1
            by_fw[fw]["total"] += 1
        scored = [r for r in results if r.status not in ("missing","not_applicable")]
        overall = sum(r.score for r in scored)/len(scored) if scored else 0.0
        # Per-framework scores
        for fw, d in by_fw.items():
            fw_scored = [r for r in results if r.framework == fw and r.status not in ("missing","not_applicable")]
            d["score"] = round(sum(r.score for r in fw_scored)/len(fw_scored)*100,1) if fw_scored else 0.0
        return {
            "total_controls": total, **counts,
            "overall_score": round(overall*100,1),
            "risk_level": "Critical" if overall<0.5 else "High" if overall<0.7 else "Medium" if overall<0.9 else "Low",
            "by_framework": by_fw,
        }
