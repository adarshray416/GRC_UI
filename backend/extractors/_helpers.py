"""
extractors/_helpers.py
─────────────────────────────────────────────────────────────────────────────
Shared utility functions used by ALL extractors.

Two core jobs:
  1. _find(text, labels)       — find a short text value after a label keyword
  2. _find_date(text, labels)  — find and parse a date after a label keyword

How label matching works
────────────────────────
Given a label like "approved by" and a document line like:
    Approved by: Alice Smith, CISO

The regex pattern becomes:
    approved by\s*[:\-=]?\s*(.{1,120})

That matches "Alice Smith, CISO" as group 1.

We then take only the first line of the match (split on \n) and strip
whitespace, so multi-line documents don't bleed into each other.

Date parsing
────────────
_find_date tries every format in _DATE_FMTS in order.  If a date like
"01/03/2025" is found it tries DD/MM/YYYY first, then MM/DD/YYYY.
Returns the date as an ISO 8601 string ("2025-03-01") or None.
"""
from __future__ import annotations

import re
from datetime import date, datetime
from typing import List, Optional


# ── Date format priority list ─────────────────────────────────────────────────
# Tried in order — first match wins.
_DATE_FMTS = [
    "%Y-%m-%d",     # 2025-03-01          (ISO — most reliable, try first)
    "%d/%m/%Y",     # 01/03/2025          (UK/India format)
    "%m/%d/%Y",     # 03/01/2025          (US format)
    "%d %B %Y",     # 01 March 2025
    "%B %d, %Y",    # March 01, 2025
    "%d-%b-%Y",     # 01-Mar-2025
    "%d-%m-%Y",     # 01-03-2025
    "%b %d %Y",     # Mar 01 2025
]


def _parse_date(raw: str) -> Optional[date]:
    """Try every known date format. Return a date object or None."""
    raw = raw.strip()
    for fmt in _DATE_FMTS:
        try:
            return datetime.strptime(raw, fmt).date()
        except ValueError:
            pass
    return None


def _find_date(text: str, labels: List[str]) -> Optional[str]:
    """
    Search for a date that follows any of the given label phrases.

    Example:
        text   = "Review Date: 01/06/2026"
        labels = ["review date", "next review"]
        returns "2026-06-01"

    Returns ISO string "YYYY-MM-DD" or None if not found.
    """
    for label in labels:
        pattern = rf"{re.escape(label)}\s*[:\-]?\s*([0-9A-Za-z ,/\-]{{6,20}})"
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            parsed = _parse_date(match.group(1).strip())
            if parsed:
                return str(parsed)
    return None


def _find(text: str, labels: List[str], max_len: int = 120) -> Optional[str]:
    """
    Search for a short text value that follows any of the given label phrases.

    Example:
        text   = "Approved by: Alice Smith, CISO\\nVersion: 2.1"
        labels = ["approved by", "authorised by"]
        returns "Alice Smith, CISO"

    max_len caps how far after the colon we read (avoids grabbing entire
    paragraphs when the document has no line breaks).
    """
    for label in labels:
        pattern = rf"{re.escape(label)}\s*[:\-=]?\s*(.{{1,{max_len}}})"
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            # Take only the first line so we don't bleed into the next field
            value = match.group(1).strip().split("\n")[0].strip()
            # Reject single-character noise
            if len(value) > 1:
                return value
    return None
