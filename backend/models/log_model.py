"""models/log_model.py"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import List, Optional
from datetime import datetime

@dataclass
class LogEntryModel:
    event:     str
    timestamp: Optional[datetime] = None
    user:      Optional[str]      = None
    source_ip: Optional[str]      = None
    action:    Optional[str]      = None
    outcome:   Optional[str]      = None
    resource:  Optional[str]      = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat() if self.timestamp else None
        return d

@dataclass
class LogCollectionModel:
    source_file: str
    entries:     List[LogEntryModel] = field(default_factory=list)
    start_date:  Optional[datetime]  = None
    end_date:    Optional[datetime]  = None

    def coverage_days(self) -> Optional[int]:
        if self.start_date and self.end_date:
            return (self.end_date - self.start_date).days
        return None

    def has_continuous_coverage(self, min_days: int = 90) -> bool:
        d = self.coverage_days()
        return d is not None and d >= min_days

    def failure_rate(self) -> float:
        if not self.entries:
            return 0.0
        failures = sum(1 for e in self.entries if (e.outcome or "").lower() in ("failure", "failed", "denied"))
        return failures / len(self.entries)

    def to_dict(self) -> dict:
        return {
            "source_file":   self.source_file,
            "entry_count":   len(self.entries),
            "start_date":    self.start_date.isoformat() if self.start_date else None,
            "end_date":      self.end_date.isoformat() if self.end_date else None,
            "coverage_days": self.coverage_days(),
            "failure_rate":  round(self.failure_rate(), 3),
            "entries":       [e.to_dict() for e in self.entries],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "LogCollectionModel":
        entries = [LogEntryModel(**{k: v for k, v in e.items() if k in LogEntryModel.__dataclass_fields__})
                   for e in d.get("entries", [])]
        return cls(
            source_file = d.get("source_file", ""),
            entries     = entries,
            start_date  = datetime.fromisoformat(d["start_date"]) if d.get("start_date") else None,
            end_date    = datetime.fromisoformat(d["end_date"])   if d.get("end_date")   else None,
        )
