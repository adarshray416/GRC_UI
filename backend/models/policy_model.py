"""models/policy_model.py"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import List, Optional

@dataclass
class PolicyModel:
    name:           str
    version:        Optional[str]   = None
    approved_by:    Optional[str]   = None
    approval_date:  Optional[str]   = None   # stored as ISO string
    review_date:    Optional[str]   = None
    scope:          Optional[str]   = None
    classification: Optional[str]   = None
    keywords_found: List[str]       = field(default_factory=list)
    source_file:    Optional[str]   = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "PolicyModel":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})
