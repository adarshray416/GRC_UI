"""models/risk_model.py"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Optional

@dataclass
class RiskModel:
    risk_id:           str
    risk_description:  str
    impact:            str   # critical / high / medium / low / info
    likelihood:        str
    owner:             Optional[str] = None
    status:            str           = "pending"  # approved / pending / rejected
    mitigation:        Optional[str] = None
    residual_risk:     Optional[str] = None
    source_file:       Optional[str] = None

    def risk_score(self) -> int:
        scale = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        return scale.get(self.impact, 3) * scale.get(self.likelihood, 3)

    def is_treated(self) -> bool:
        return self.status == "approved" and self.mitigation is not None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["risk_score"] = self.risk_score()
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "RiskModel":
        fields = {k: v for k, v in d.items() if k in cls.__dataclass_fields__}
        return cls(**fields)
