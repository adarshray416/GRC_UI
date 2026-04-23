"""models/canonical.py — all canonical dataclasses"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import date, datetime
from typing import List, Optional

# ── Policy ────────────────────────────────────────────────────────────────────
@dataclass
class PolicyModel:
    name: str
    version: Optional[str] = None
    approved_by: Optional[str] = None
    approval_date: Optional[str] = None
    review_date: Optional[str] = None
    scope: Optional[str] = None
    classification: Optional[str] = None
    keywords_found: List[str] = field(default_factory=list)
    source_file: Optional[str] = None

    def to_dict(self): return asdict(self)

    @classmethod
    def from_dict(cls, d: dict):
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

# ── Risk ──────────────────────────────────────────────────────────────────────
@dataclass
class RiskModel:
    risk_id: str
    risk_description: str
    impact: str
    likelihood: str
    owner: Optional[str] = None
    status: str = "pending"
    mitigation: Optional[str] = None
    residual_risk: Optional[str] = None
    source_file: Optional[str] = None

    def risk_score(self):
        s = {"critical":5,"high":4,"medium":3,"low":2,"info":1}
        return s.get(self.impact,3) * s.get(self.likelihood,3)

    def is_treated(self):
        return self.status == "approved" and self.mitigation is not None

    def to_dict(self):
        d = asdict(self); d["risk_score"] = self.risk_score(); return d

    @classmethod
    def from_dict(cls, d: dict):
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

# ── Log ───────────────────────────────────────────────────────────────────────
@dataclass
class LogEntryModel:
    event: str
    timestamp: Optional[str] = None
    user: Optional[str] = None
    source_ip: Optional[str] = None
    action: Optional[str] = None
    outcome: Optional[str] = None
    resource: Optional[str] = None

    def to_dict(self): return asdict(self)

@dataclass
class LogCollectionModel:
    source_file: str
    entries: List[LogEntryModel] = field(default_factory=list)
    start_date: Optional[str] = None
    end_date: Optional[str] = None

    def coverage_days(self):
        if self.start_date and self.end_date:
            try:
                s = datetime.fromisoformat(self.start_date.replace("Z",""))
                e = datetime.fromisoformat(self.end_date.replace("Z",""))
                return (e - s).days
            except: pass
        return None

    def failure_rate(self):
        if not self.entries: return 0.0
        f = sum(1 for e in self.entries if (e.outcome or "").lower() in ("failure","failed","denied"))
        return f / len(self.entries)

    def to_dict(self):
        return {
            "source_file": self.source_file,
            "entry_count": len(self.entries),
            "start_date":  self.start_date,
            "end_date":    self.end_date,
            "coverage_days": self.coverage_days(),
            "failure_rate":  round(self.failure_rate(), 3),
            "entries": [e.to_dict() for e in self.entries[:200]],  # cap for API
        }

    @classmethod
    def from_dict(cls, d: dict):
        entries = [LogEntryModel(**{k: v for k,v in e.items() if k in LogEntryModel.__dataclass_fields__})
                   for e in d.get("entries", [])]
        return cls(source_file=d.get("source_file",""), entries=entries,
                   start_date=d.get("start_date"), end_date=d.get("end_date"))

# ── Access Review ─────────────────────────────────────────────────────────────
@dataclass
class AccessReviewModel:
    user: str
    role: str
    department: Optional[str] = None
    access_level: Optional[str] = None
    last_reviewed: Optional[str] = None
    reviewer: Optional[str] = None
    status: str = "active"
    mfa_enabled: Optional[bool] = None
    privileged: bool = False
    source_file: Optional[str] = None

    def is_overdue(self, max_days: int = 90) -> bool:
        if not self.last_reviewed: return True
        try:
            d = date.fromisoformat(self.last_reviewed)
            return (date.today() - d).days > max_days
        except: return True

    def to_dict(self): return asdict(self)

    @classmethod
    def from_dict(cls, d: dict):
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

@dataclass
class AccessReviewCollectionModel:
    system: Optional[str] = None
    review_period: Optional[str] = None
    records: List[AccessReviewModel] = field(default_factory=list)
    source_file: Optional[str] = None

    def privileged_without_mfa(self):
        return [r for r in self.records if r.privileged and not r.mfa_enabled]

    def overdue_reviews(self, max_days: int = 90):
        return [r for r in self.records if r.is_overdue(max_days)]

    def to_dict(self):
        return {
            "system": self.system, "review_period": self.review_period,
            "source_file": self.source_file, "record_count": len(self.records),
            "records": [r.to_dict() for r in self.records],
        }

    @classmethod
    def from_dict(cls, d: dict):
        records = [AccessReviewModel.from_dict(r) for r in d.get("records", [])]
        return cls(system=d.get("system"), review_period=d.get("review_period"),
                   records=records, source_file=d.get("source_file"))
