"""models/access_model.py"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import List, Optional
from datetime import date, datetime

@dataclass
class AccessReviewModel:
    user:          str
    role:          str
    department:    Optional[str]  = None
    access_level:  Optional[str]  = None
    last_reviewed: Optional[date] = None
    reviewer:      Optional[str]  = None
    status:        str            = "active"   # active / revoked / suspended / under_review
    mfa_enabled:   Optional[bool] = None
    privileged:    bool           = False
    source_file:   Optional[str]  = None

    def is_review_overdue(self, max_days: int = 90) -> bool:
        if self.last_reviewed is None:
            return True
        today = date.today()
        return (today - self.last_reviewed).days > max_days

    def to_dict(self) -> dict:
        d = asdict(self)
        d["last_reviewed"] = str(self.last_reviewed) if self.last_reviewed else None
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "AccessReviewModel":
        fields = {k: v for k, v in d.items() if k in cls.__dataclass_fields__}
        if fields.get("last_reviewed"):
            try:
                fields["last_reviewed"] = date.fromisoformat(fields["last_reviewed"])
            except Exception:
                fields["last_reviewed"] = None
        return cls(**fields)

@dataclass
class AccessReviewCollectionModel:
    system:        Optional[str]              = None
    review_period: Optional[str]              = None
    records:       List[AccessReviewModel]    = field(default_factory=list)
    source_file:   Optional[str]              = None

    def privileged_without_mfa(self) -> List[AccessReviewModel]:
        return [r for r in self.records if r.privileged and not r.mfa_enabled]

    def overdue_reviews(self, max_days: int = 90) -> List[AccessReviewModel]:
        return [r for r in self.records if r.is_review_overdue(max_days)]

    def to_dict(self) -> dict:
        return {
            "system":        self.system,
            "review_period": self.review_period,
            "source_file":   self.source_file,
            "record_count":  len(self.records),
            "records":       [r.to_dict() for r in self.records],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AccessReviewCollectionModel":
        records = [AccessReviewModel.from_dict(r) for r in d.get("records", [])]
        return cls(
            system        = d.get("system"),
            review_period = d.get("review_period"),
            records       = records,
            source_file   = d.get("source_file"),
        )
