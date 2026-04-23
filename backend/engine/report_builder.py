"""
engine/report_builder.py
─────────────────────────────────────────────────────────────────────────────
Assembles the final JSON compliance report from control results + summary.

Separated from runner.py so it can be called independently (e.g. to
rebuild a report from a cached canonical store without re-running the
full pipeline).

Output structure
────────────────
{
  "generated_at":   "2025-10-01T08:00:00Z",
  "summary": {
    "overall_score":  75.0,
    "risk_level":     "Medium",
    "total_controls": 9,
    "pass": 3, "partial": 4, "fail": 1, "missing": 1,
    "by_framework": { "ISO27001": {...}, "SOC2": {...} }
  },
  "controls":       [ ControlResult.to_dict(), ... ],
  "evidence_store": { "policy": {...}, "risk": [...], ... },
  "sources":        [ {"file": "...", "type": "...", "source": "..."}, ... ]
}
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List


def build_report(
    results: list,
    summary: dict,
    canonical_store: dict,
    sources: list = None,
) -> dict:
    """
    Build the full compliance report dict.

    Args:
        results:         List of ControlResult objects.
        summary:         Output of ControlEvaluator.summary(results).
        canonical_store: The evidence store built by GRCRunner.
        sources:         List of evidence index entries (file metadata).

    Returns:
        Complete report dict ready to be JSON-serialised.
    """
    return {
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "summary":        summary,
        "controls":       [r.to_dict() for r in results],
        # Strip internal keys (prefixed with _) before exposing
        "evidence_store": {
            k: v for k, v in canonical_store.items()
            if not k.startswith("_")
        },
        "sources": sources or [],
    }


def build_summary_text(report: dict) -> str:
    """
    Build a plain-text executive summary from a report dict.
    Used as the opening section of the PDF export.
    """
    s = report.get("summary", {})
    lines = [
        "BABCOM GRC COMPLIANCE REPORT",
        f"Generated: {report.get('generated_at', 'Unknown')}",
        "",
        f"Overall Compliance Score : {s.get('overall_score', 0)}%",
        f"Risk Level               : {s.get('risk_level', 'Unknown')}",
        f"Total Controls Evaluated : {s.get('total_controls', 0)}",
        f"  Passed                 : {s.get('pass', 0)}",
        f"  Partial                : {s.get('partial', 0)}",
        f"  Failed                 : {s.get('fail', 0)}",
        f"  Missing Evidence       : {s.get('missing', 0)}",
        "",
        "FRAMEWORK BREAKDOWN",
        "───────────────────",
    ]
    for fw, d in s.get("by_framework", {}).items():
        lines.append(
            f"  {fw:<12} {d.get('score', 0):5.1f}%  "
            f"pass={d.get('pass',0)}  partial={d.get('partial',0)}  "
            f"fail={d.get('fail',0)}  missing={d.get('missing',0)}"
        )
    lines += ["", "CONTROL DETAILS", "───────────────"]
    for ctrl in report.get("controls", []):
        lines.append(
            f"  [{ctrl['status'].upper():<12}]  {ctrl['control_id']:<16}  "
            f"{ctrl['control_name']}  ({ctrl['score']}%)"
        )
        if ctrl.get("recommendation"):
            lines.append(f"    → {ctrl['recommendation']}")
    return "\n".join(lines)
