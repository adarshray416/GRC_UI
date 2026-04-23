"""
extractors/access_extractor.py
─────────────────────────────────────────────────────────────────────────────
Converts raw access review text → AccessReviewCollectionModel (canonical dict).

Supported input formats
───────────────────────
1. Block format (blank line between users) — most common:

        User: alice
        Role: Administrator
        Privileged: yes
        MFA: yes
        Status: active
        Last Reviewed: 2024-11-01

2. Compact line format (one user per line):

        alice | Administrator | active | MFA=yes | privileged

3. CSV / spreadsheet — the CSV parser converts each row to
   "key: value  key: value" text before this extractor sees it.

How each user block is parsed
──────────────────────────────
Each blank-line-separated block is passed to _parse_access_block():

  1. Find "User:" or "Username:" for the account name.
     If no label, take the first token on the first line.

  2. Find "Role:", "Position:", or "Job Title:" for the role.
     If the role contains "admin", "root", "dba", or "superuser",
     the user is automatically flagged as privileged.

  3. Find "MFA:", "2FA:", "Two-Factor:" → bool (yes/no/true/false).

  4. Find "Privileged:", "Admin:", "Elevated:" → bool.

  5. Find "Status:" → maps to active / revoked / suspended / under_review.

  6. Find "Last Reviewed:", "Reviewed On:", "Review Date:" → date string.

Privileged escalation detection
────────────────────────────────
Even if "Privileged: no" is written, if the Role field contains any of
("admin", "root", "superuser", "dba"), privileged is set True.
This catches misclassified accounts in poorly maintained registers.

MFA gap detection
─────────────────
If mfa_enabled is None (field missing) AND the user is privileged,
the control evaluator treats this as MFA-unknown and may flag it.
Only an explicit "MFA: yes" / "MFA: true" counts as confirmed.

Output
──────
Returns an AccessReviewCollectionModel dict containing:
  - system, review_period  (document-level metadata)
  - record_count           number of accounts parsed
  - records[]              list of AccessReviewModel dicts
"""
from __future__ import annotations

import re
from typing import List, Optional

from models.canonical import AccessReviewModel, AccessReviewCollectionModel
from extractors._helpers import _find, _find_date


# ── Status normalisation ──────────────────────────────────────────────────────
_STATUS_MAP = {
    "active":       "active",
    "enabled":      "active",
    "revoked":      "revoked",
    "disabled":     "revoked",
    "removed":      "revoked",
    "terminated":   "revoked",
    "offboarded":   "revoked",
    "suspended":    "suspended",
    "locked":       "suspended",
    "on leave":     "suspended",
    "under review": "under_review",
    "pending":      "under_review",
    "review":       "under_review",
}

# Role keywords that automatically flag an account as privileged
_PRIVILEGED_ROLE_KEYWORDS = (
    "admin", "administrator", "root", "superuser",
    "dba", "database administrator", "sysadmin",
    "system administrator", "devops", "security engineer",
    "ciso", "it manager",
)


def _parse_bool_field(raw: Optional[str]) -> Optional[bool]:
    """Convert 'yes'/'no'/'true'/'false'/'1'/'0' to a Python bool or None."""
    if raw is None:
        return None
    return raw.strip().lower() in ("yes", "true", "enabled", "1", "y")


def _parse_access_block(block: str) -> Optional[dict]:
    """
    Parse one access review block (one user record) into a dict.
    Returns None if the block is a metadata header or has no username.
    """
    if len(block.strip()) < 5:
        return None

    # Skip document-level header blocks (System:, Review Period:, etc.)
    lower_block = block.strip().lower()
    _META_LABELS = ("system:", "review period:", "period:", "application:",
                    "platform:", "service:", "report date:", "prepared by:")
    if any(lower_block.startswith(lbl) for lbl in _META_LABELS):
        return None

    # ── Username ──────────────────────────────────────────────────────────────
    user = _find(block, [
        "user", "username", "employee", "name",
        "account", "login", "samaccountname",
    ])
    # Fallback: only use first token as username if block has access-review content
    if not user:
        _ACCESS_SIGNALS = re.compile(
            r"^(role|status|mfa|privileged|department|last.reviewed|reviewer)\s*[:\-]",
            re.IGNORECASE | re.MULTILINE
        )
        if _ACCESS_SIGNALS.search(block):
            first_line = block.strip().splitlines()[0]
            candidate  = first_line.split()[0] if first_line else None
            _skip = {"system","period","application","platform","service",
                     "report","prepared","date","quarter","review","access"}
            if candidate and candidate.rstrip(":").lower() not in _skip:
                user = candidate.rstrip(":")
    if not user:
        return None

    # ── Role ──────────────────────────────────────────────────────────────────
    role = _find(block, [
        "role", "position", "job title", "access role",
        "privilege level", "title",
    ]) or "unknown"

    # ── Department ───────────────────────────────────────────────────────────
    department = _find(block, ["department", "dept", "team", "division", "business unit"])

    # ── Access level ─────────────────────────────────────────────────────────
    access_level = _find(block, ["access level", "level", "permission", "access type"], max_len=30)

    # ── MFA ───────────────────────────────────────────────────────────────────
    mfa_raw    = _find(block, ["mfa", "2fa", "two-factor", "multi-factor", "multifactor"], max_len=10)
    mfa_enabled = _parse_bool_field(mfa_raw)

    # ── Privileged flag ───────────────────────────────────────────────────────
    priv_raw  = _find(block, ["privileged", "admin", "elevated", "root", "superuser"], max_len=10)
    privileged = _parse_bool_field(priv_raw) or False

    # Auto-detect from role name even if the "privileged" field says no
    if not privileged and role:
        privileged = any(kw in role.lower() for kw in _PRIVILEGED_ROLE_KEYWORDS)

    # ── Status ────────────────────────────────────────────────────────────────
    status_raw = _find(block, ["status", "account status", "user status", "access status"], max_len=30) or "active"
    status     = _STATUS_MAP.get(status_raw.strip().lower(), "active")

    # ── Last reviewed date ────────────────────────────────────────────────────
    last_reviewed = _find_date(block, [
        "last reviewed", "reviewed on", "review date",
        "date reviewed", "last review", "reviewed",
    ])

    # ── Reviewer ─────────────────────────────────────────────────────────────
    reviewer = _find(block, ["reviewer", "reviewed by", "approved by", "certifier"])

    return AccessReviewModel(
        user          = user,
        role          = role,
        department    = department,
        access_level  = access_level,
        last_reviewed = last_reviewed,
        reviewer      = reviewer,
        status        = status,
        mfa_enabled   = mfa_enabled,
        privileged    = privileged,
    ).to_dict()


def extract_access_reviews(raw_text: str, file_path: str) -> dict:
    """
    Extract all user access records from a raw access review document.

    Strategy:
      1. Try to extract document-level metadata (system name, review period).
      2. Split on blank lines → one block per user.
      3. If only one block (compact format), treat each non-trivial line
         as its own user record.
      4. Parse each block with _parse_access_block().

    Args:
        raw_text:  Full text of the access review file.
        file_path: Source path for traceability.

    Returns:
        AccessReviewCollectionModel dict.
    """
    # ── Document-level metadata ───────────────────────────────────────────────
    system        = _find(raw_text, ["system", "application", "platform", "service", "environment"])
    review_period = _find(raw_text, ["review period", "period", "quarter", "reporting period", "cycle"])

    # ── Split into per-user blocks ────────────────────────────────────────────
    blocks = [b for b in re.split(r"\n{2,}", raw_text) if b.strip()]

    # Compact format fallback (no blank lines between users)
    if len(blocks) <= 1:
        blocks = [line for line in raw_text.splitlines() if len(line.strip()) > 5]

    # ── Parse each block ──────────────────────────────────────────────────────
    records: List[AccessReviewModel] = []
    for block in blocks:
        parsed = _parse_access_block(block)
        if parsed:
            # Attach source_file before converting to model
            parsed["source_file"] = file_path
            records.append(AccessReviewModel.from_dict(parsed))

    return AccessReviewCollectionModel(
        system        = system,
        review_period = review_period,
        records       = records,
        source_file   = file_path,
    ).to_dict()
