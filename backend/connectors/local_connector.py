"""
connectors/local_connector.py
Scans a local directory for evidence files.
Default path: D:\\Babcom\\GRC  (Windows) or ~/GRC (Linux/Mac fallback).
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import List

log = logging.getLogger(__name__)

EVIDENCE_EXTENSIONS = {".txt", ".pdf", ".csv", ".log", ".json", ".md"}

EVIDENCE_TYPE_HINTS = {
    "policy":        ["policy", "isms", "acceptable", "security", "governance", "procedure"],
    "risk":          ["risk", "register", "threat", "vulnerability", "assessment"],
    "logs":          ["log", "audit", "event", "access_log", "syslog", "trail"],
    "access_review": ["access", "review", "iam", "user", "permission", "role", "account"],
}

def _infer_type(filename: str) -> str:
    name = filename.lower()
    for etype, hints in EVIDENCE_TYPE_HINTS.items():
        if any(h in name for h in hints):
            return etype
    return "policy"


class LocalConnector:
    def __init__(self, base_path: str = r"D:\files\backend\evidence_store\evidence"):
        self.base_path = Path(base_path)

    def fetch_all(self) -> List[dict]:
        """
        Recursively scan base_path for evidence files.
        Returns evidence_index entries (no download needed — already local).
        """
        if not self.base_path.exists():
            log.warning(f"Local path not found: {self.base_path}")
            return []

        index = []
        for file_path in self.base_path.rglob("*"):
            if not file_path.is_file():
                continue
            if file_path.suffix.lower() not in EVIDENCE_EXTENSIONS:
                continue
            # Skip hidden files and system files
            if file_path.name.startswith(".") or file_path.name.startswith("~"):
                continue

            entry = {
                "file":   file_path.name,
                "path":   str(file_path),
                "type":   _infer_type(file_path.name),
                "source": f"local:{file_path}",
                "sha":    "",
            }
            index.append(entry)
            log.info(f"  Local ← {file_path.name} [{entry['type']}]")

        log.info(f"Local connector: {len(index)} file(s) from {self.base_path}")
        return index
