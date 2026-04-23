"""
extractors/log_extractor.py
─────────────────────────────────────────────────────────────────────────────
Converts raw audit log text → LogCollectionModel (canonical dict).

Supported log formats
─────────────────────
1. ISO 8601 structured   2024-10-01T08:12:33Z user=alice action=login outcome=success
2. Syslog                Oct  1 08:12:33 hostname sshd[123]: Accepted publickey for alice
3. W3C / IIS             2024-10-01 08:12:33 GET /api/health 200
4. CSV-converted         timestamp: 2024-10-01  user: alice  action: login
5. AWS CloudTrail JSON   (pre-converted to text by parsers.py)
6. Key=value pairs       ts=2024-10-01T08:12:33 user=alice action=login ip=10.0.0.1

How timestamp detection works
──────────────────────────────
_TS_RE is a compiled regex that matches the most common timestamp formats:
  • ISO 8601:   2024-10-01T08:12:33Z  or  2024-10-01 08:12:33
  • UK/US date: 01/10/2024 08:12:33
  • Syslog:     Oct  1 08:12:33

If a timestamp is found, everything after it on the same line becomes
the "event" field.  If no timestamp is found the whole line is the event.

Field extraction via key=value scanning
────────────────────────────────────────
After timestamp detection, _kv() scans for common field names:
  user=, username=, usr=       → user field
  ip=, src_ip=, source_ip=     → source_ip field
  action=, event=, operation=  → action field
  status=, result=, outcome=   → outcome field
  resource=, target=, file=    → resource field

Security event detection
────────────────────────
If no explicit action= field is found, the line is scanned against
SEC_ACTIONS (login, delete, sudo, etc.) to auto-tag the action type.

Output
──────
Returns a LogCollectionModel dict containing:
  - entry_count   number of parsed log lines
  - start_date    earliest timestamp found
  - end_date      latest timestamp found
  - coverage_days (end_date - start_date).days
  - failure_rate  fraction of entries with outcome=failure/failed/denied
  - entries[]     list of LogEntryModel dicts (capped at 200 for the API)
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import List, Optional

from models.canonical import LogEntryModel, LogCollectionModel


# ── Timestamp regex ───────────────────────────────────────────────────────────
# Matches the three most common log timestamp formats.
# Order matters — more specific patterns first.
_TS_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?"  # ISO 8601
    r"|\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}"                                      # DD/MM/YYYY HH:MM:SS
    r"|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"                                      # Syslog: Oct  1 08:12:33
)

_TS_FMTS = [
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
    "%b %d %H:%M:%S",
    "%b  %d %H:%M:%S",   # syslog double-space for single-digit days
]

# Actions that indicate a security-relevant log event
SEC_ACTIONS = {
    "login", "logout", "signin", "sign_in",
    "delete", "remove",
    "export", "download",
    "sudo", "privilege", "escalation",
    "password_change", "password change", "reset_password",
    "failed", "failure", "denied", "blocked",
    "unauthorised", "unauthorized",
    "create_user", "delete_user", "modify_user",
}


def _parse_timestamp(raw: str) -> Optional[str]:
    """Parse a raw timestamp string into an ISO 8601 string, or None."""
    raw = raw.strip()
    for fmt in _TS_FMTS:
        try:
            return datetime.strptime(raw, fmt).isoformat()
        except ValueError:
            pass
    # Try Python's built-in ISO parser for timezone-aware strings
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).isoformat()
    except Exception:
        return None


def _kv(line: str, keys: List[str]) -> Optional[str]:
    """
    Extract a value from key=value or key: value pairs.

    Example:
        line = "user=alice action=login ip=10.0.0.1"
        _kv(line, ["user", "username"])  → "alice"
    """
    for key in keys:
        match = re.search(rf"\b{key}[=:\s]+([^\s,;|\]]+)", line, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return None


def _parse_log_line(line: str) -> Optional[LogEntryModel]:
    """
    Parse one log line into a LogEntryModel.
    Returns None if the line is empty or too short to be meaningful.
    """
    line = line.strip()
    if not line or len(line) < 10:
        return None

    # ── Timestamp ─────────────────────────────────────────────────────────────
    ts_match   = _TS_RE.search(line)
    ts_str     = _parse_timestamp(ts_match.group()) if ts_match else None

    # Everything after the timestamp is the raw event text
    after_ts   = line[ts_match.end():].strip() if ts_match else line

    # ── Fields via key=value ──────────────────────────────────────────────────
    user      = _kv(line, ["user", "username", "usr", "uid", "account", "principal"])
    source_ip = _kv(line, ["ip", "src_ip", "source_ip", "srcip", "from", "client"])
    action    = _kv(line, ["action", "event", "type", "operation", "cmd", "method"])
    outcome   = _kv(line, ["status", "result", "outcome", "response"])
    resource  = _kv(line, ["resource", "target", "file", "path", "object", "uri", "url"])

    # ── Auto-detect action from known security verbs ──────────────────────────
    if not action:
        lower_line = line.lower()
        for verb in SEC_ACTIONS:
            if verb in lower_line:
                action = verb
                break

    return LogEntryModel(
        event     = after_ts[:200],
        timestamp = ts_str,
        user      = user,
        source_ip = source_ip,
        action    = action,
        outcome   = outcome,
        resource  = resource,
    )


def extract_logs(raw_text: str, file_path: str) -> dict:
    """
    Parse all lines in a log file into a LogCollectionModel.

    Args:
        raw_text:  Full text content of the log file.
        file_path: Source path for traceability.

    Returns:
        LogCollectionModel dict with entry_count, coverage_days,
        failure_rate, and up to 200 entries.
    """
    entries: List[LogEntryModel] = []

    for line in raw_text.splitlines():
        entry = _parse_log_line(line)
        if entry:
            entries.append(entry)

    # Find the date range from timestamped entries
    dated      = [e for e in entries if e.timestamp]
    start_date = min((e.timestamp for e in dated), default=None)
    end_date   = max((e.timestamp for e in dated), default=None)

    return LogCollectionModel(
        source_file = file_path,
        entries     = entries,
        start_date  = start_date,
        end_date    = end_date,
    ).to_dict()
