"""
extractors/policy_extractor.py
─────────────────────────────────────────────────────────────────────────────
Converts raw document text → PolicyModel (canonical dict).

What it searches for
────────────────────
Given ANY text file or PDF that contains a policy document, this extractor
tries to pull out these fields:

  Field            What it looks for in the text
  ───────────────  ──────────────────────────────────────────────────────────
  name             "Title:", "Policy Name:", "Document Name:", or the first
                   non-empty line of the document
  version          "Version:", "Ver.", "Revision:", "Rev."
  approved_by      "Approved by:", "Authorised by:", "Signed by:",
                   "Document Owner:", "Owner:"
  approval_date    "Approval Date:", "Approved on:", "Date Approved:",
                   "Effective Date:"
  review_date      "Review Date:", "Next Review:", "Expiry Date:",
                   "Valid Until:", "Review By:"
  scope            "Scope:", "Applies to:", "Coverage:"
  classification   "Classification:", "Sensitivity:"
  keywords_found   Scans the full text for known policy topic keywords

How it decides a file IS a policy
──────────────────────────────────
The POLICY_KEYWORDS list contains phrases that appear in real policy
documents.  If any match, the file is confidently treated as a policy.
The file-naming hint ("*policy*", "*isms*", etc.) from the connector is
a first-pass filter; this extractor does the deeper scan.

Confidence scoring
──────────────────
  - Starts at 1.0
  - -0.15 if no approver found    (control A.5.1 will fail)
  - -0.10 if no review date found (policy may appear expired)
  - -0.05 if no version found
  Minimum is 0.3 so we never discard a file entirely.

Output
──────
Returns a dict matching PolicyModel fields, ready to be stored in
canonical_store/policy.json and consumed by the control evaluator.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from models.canonical import PolicyModel
from extractors._helpers import _find, _find_date


# ── Keywords that confirm a document is policy-related ───────────────────────
# If ANY of these phrases appear in the document body the file is tagged as
# policy evidence.  The list covers ISO 27001 / SOC 2 / GDPR vocabulary.
POLICY_KEYWORDS = [
    # Generic policy terms
    "information security policy",
    "security policy",
    "acceptable use policy",
    "acceptable use",
    # Data / privacy
    "data protection",
    "data classification",
    "privacy policy",
    "gdpr",
    "personal data",
    # Access and identity
    "access control policy",
    "identity management",
    "privileged access",
    # Incident and change
    "incident response policy",
    "incident management",
    "change management policy",
    "change management",
    # Governance terms
    "information security management",
    "isms",
    "iso 27001",
    "soc 2",
    "governance",
    # Document metadata markers
    "document owner",
    "policy owner",
    "review cycle",
    "annual review",
    "approved by",
]


def extract_policy(raw_text: str, file_path: str) -> dict:
    """
    Extract structured fields from a raw policy document.

    Args:
        raw_text:  Full text content of the file (from pdf_parser or txt_parser).
        file_path: Original file path — used as fallback for the policy name
                   and stored in source_file for traceability.

    Returns:
        A dict matching PolicyModel fields.  All fields are optional except
        'name' — a fallback name is always produced from the file path.
    """
    confidence = 1.0
    warnings   = []

    # ── Step 1: Extract the policy name ──────────────────────────────────────
    # Priority: explicit label → first heading → filename stem
    name = (
        _find(raw_text, [
            "title",
            "policy name",
            "document name",
            "document title",
            "policy:",
        ])
        or _first_heading(raw_text)
        or Path(file_path).stem.replace("_", " ").replace("-", " ").title()
    )

    # ── Step 2: Extract approver ──────────────────────────────────────────────
    approved_by = _find(raw_text, [
        "approved by",
        "authorised by",
        "authorized by",
        "signed by",
        "document owner",
        "policy owner",
        "owner",
    ])
    if not approved_by:
        warnings.append("No approver found — control A.5.1 check 'approved_by' will fail")
        confidence -= 0.15

    # ── Step 3: Extract dates ─────────────────────────────────────────────────
    approval_date = _find_date(raw_text, [
        "approval date",
        "approved on",
        "date approved",
        "effective date",
        "date effective",
        "issued on",
        "issue date",
    ])

    review_date = _find_date(raw_text, [
        "review date",
        "next review",
        "next review date",
        "expiry date",
        "valid until",
        "review by",
        "scheduled review",
        "due for review",
    ])
    if not review_date:
        warnings.append("No review date found — policy may be flagged as expired")
        confidence -= 0.10

    # ── Step 4: Extract version ───────────────────────────────────────────────
    version = _find(raw_text, [
        "version",
        "ver.",
        "revision",
        "rev.",
        "document version",
    ], max_len=20)
    if not version:
        confidence -= 0.05

    # ── Step 5: Extract scope and classification ──────────────────────────────
    scope = _find(raw_text, [
        "scope",
        "applies to",
        "application",
        "coverage",
        "this policy applies",
    ], max_len=400)

    classification = _find(raw_text, [
        "classification",
        "sensitivity",
        "document classification",
        "information classification",
    ], max_len=40)

    # ── Step 6: Keyword scan ──────────────────────────────────────────────────
    # Scan the full lowercased text for known policy vocabulary.
    lower_text     = raw_text.lower()
    keywords_found = [kw for kw in POLICY_KEYWORDS if kw in lower_text]

    # ── Step 7: Build canonical model ────────────────────────────────────────
    model = PolicyModel(
        name           = name,
        version        = version,
        approved_by    = approved_by,
        approval_date  = approval_date,
        review_date    = review_date,
        scope          = scope,
        classification = classification,
        keywords_found = keywords_found,
        source_file    = file_path,
    )

    result = model.to_dict()
    result["_confidence"] = round(max(0.3, confidence), 2)
    result["_warnings"]   = warnings

    # LLM fallback: fill gaps when regex confidence is low
    if result["_confidence"] < 0.75:
        try:
            from extractors.llm_extractor import llm_extract_policy
            result = llm_extract_policy(raw_text, result)
        except Exception:
            pass  # LLM unavailable - continue with regex result
    return result


def _first_heading(text: str) -> Optional[str]:
    """
    Find the first line that looks like a document heading.
    Skips blank lines, very short lines, and lines ending in ':'.
    Limits to the first 30 lines so we don't pick up body text.
    """
    for line in text.splitlines()[:30]:
        line = line.strip()
        if 6 < len(line) < 120 and not line.endswith(":") and not line.startswith("#"):
            return line
    return None
