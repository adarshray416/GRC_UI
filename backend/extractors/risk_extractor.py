"""
extractors/risk_extractor.py
─────────────────────────────────────────────────────────────────────────────
Converts raw risk register text → list of RiskModel dicts (canonical JSON).

Supported input formats
───────────────────────
1. Block format (blank line between entries) — most common for .txt registers:

        Risk: Ransomware attack
        Impact: Critical
        Likelihood: High
        Owner: Bob Patel
        Status: Approved
        Mitigation: EDR deployed on all endpoints.

2. Line-by-line format (one risk per line, compact):

        Ransomware attack | Critical | High | Bob Patel | Approved

3. CSV / delimited — the CSV parser in parsers.py converts each row into
   "key: value  key: value" text before reaching this extractor, so it
   arrives here as format 1 above.

How field extraction works
──────────────────────────
Each block is passed to _parse_risk_block() which calls _find() from
_helpers.py for every field.  _find() searches for the field label
(e.g. "Impact:") and returns the value that follows it on the same line.

Impact / likelihood normalisation
──────────────────────────────────
Raw values like "Very High", "CRITICAL", "4/5" are normalised to the
canonical set: critical / high / medium / low / info via _IMPACT_MAP.

Output
──────
Returns a LIST of dicts (one per risk entry), not a single dict, because
a risk register file contains multiple rows.  The runner accumulates
these across files into store["risk"] = [r1, r2, …].
"""
from __future__ import annotations

import re
from typing import List, Optional

from models.canonical import RiskModel
from extractors._helpers import _find, _find_date


# ── Level normalisation map ───────────────────────────────────────────────────
# Maps whatever the document says → canonical level string
_IMPACT_MAP = {
    "critical":   "critical",
    "very high":  "critical",
    "5":          "critical",
    "high":       "high",
    "4":          "high",
    "medium":     "medium",
    "moderate":   "medium",
    "3":          "medium",
    "low":        "low",
    "2":          "low",
    "info":       "info",
    "informational": "info",
    "1":          "info",
    "negligible": "info",
}

# Maps treatment/status values → canonical status
_STATUS_MAP = {
    "approved":    "approved",
    "accepted":    "approved",
    "closed":      "approved",
    "treated":     "approved",
    "mitigated":   "approved",
    "pending":     "pending",
    "open":        "pending",
    "active":      "pending",
    "in progress": "pending",
    "rejected":    "rejected",
    "transferred": "approved",
}


def _normalise_level(raw: str) -> str:
    """Map a raw impact/likelihood string to a canonical level."""
    return _IMPACT_MAP.get(raw.strip().lower(), "medium")


# Keywords that must appear in a block for it to be treated as a risk entry
_RISK_SIGNAL_LABELS = re.compile(
    r"^(impact|likelihood|risk|severity|owner|status|mitigation|treatment)\s*[:\-]",
    re.IGNORECASE | re.MULTILINE
)

def _parse_risk_block(block: str, index: int) -> Optional[dict]:
    """
    Parse one risk entry (a block of text) into a RiskModel dict.
    Returns None if the block looks like a header or has no risk-related labels.
    """
    if len(block.strip()) < 10:
        return None

    # Skip header/title blocks that contain no risk field labels
    if not _RISK_SIGNAL_LABELS.search(block):
        return None

    # ── Risk description ──────────────────────────────────────────────────────
    description = (
        _find(block, ["risk", "description", "risk description", "issue", "threat"])
        or block.strip().splitlines()[0][:200]
    )

    # ── Impact / likelihood ───────────────────────────────────────────────────
    impact_raw     = _find(block, ["impact", "severity", "consequence", "rating"], max_len=20) or "medium"
    likelihood_raw = _find(block, ["likelihood", "probability", "frequency", "chance"], max_len=20) or "medium"

    # ── Owner ─────────────────────────────────────────────────────────────────
    owner = _find(block, ["owner", "risk owner", "responsible", "assigned to", "accountable"])

    # ── Treatment status ──────────────────────────────────────────────────────
    raw_status = _find(block, ["status", "treatment status", "treatment", "state"], max_len=20) or "pending"
    status     = _STATUS_MAP.get(raw_status.strip().lower(), "pending")

    # ── Mitigation ────────────────────────────────────────────────────────────
    mitigation = _find(block, [
        "mitigation", "treatment", "control", "action", "countermeasure",
        "remediation", "response",
    ], max_len=400)

    # ── Residual risk ─────────────────────────────────────────────────────────
    residual_raw = _find(block, ["residual", "residual risk", "residual level", "remaining risk"], max_len=20)

    # ── Review date ───────────────────────────────────────────────────────────
    review_date = _find_date(block, ["review date", "next review", "due date", "review by"])

    return RiskModel(
        risk_id          = f"R-{index + 1:03d}",
        risk_description = description,
        impact           = _normalise_level(impact_raw),
        likelihood       = _normalise_level(likelihood_raw),
        owner            = owner,
        status           = status,
        mitigation       = mitigation,
        residual_risk    = _normalise_level(residual_raw) if residual_raw else None,
        source_file      = None,   # set by caller after splitting
    ).to_dict()


def extract_risks(raw_text: str, file_path: str) -> List[dict]:
    """
    Extract all risk entries from a raw risk register document.

    Strategy:
      1. Split on double newlines (blank-line-separated blocks).
      2. If only 1 block found (compact format), treat each non-empty line
         as its own risk entry.
      3. Parse each block with _parse_risk_block().
      4. Attach source_file to every entry for traceability.

    Args:
        raw_text:  Full text of the risk register file.
        file_path: Source file path (stored in each risk entry).

    Returns:
        List of RiskModel dicts.  Empty list if nothing parseable found.
    """
    # Split on blank lines — each chunk should be one risk
    blocks = [b for b in re.split(r"\n{2,}", raw_text) if b.strip()]

    # If the whole file came back as one block (no blank lines),
    # fall back to treating each non-trivial line as one entry.
    if len(blocks) <= 1:
        blocks = [line for line in raw_text.splitlines() if len(line.strip()) > 15]

    results = []
    entry_index = 0   # only incremented for actual risk entries, not skipped headers
    for block in blocks:
        parsed = _parse_risk_block(block, entry_index)
        if parsed:
            parsed["source_file"] = file_path
            results.append(parsed)
            entry_index += 1

    return results
