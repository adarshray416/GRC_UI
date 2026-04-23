"""
connectors/github_connector.py
Scrapes a GitHub repo for evidence files (txt, pdf, csv, log, json).
Uses the GitHub API — no token needed for public repos (60 req/hr).
With a token: 5000 req/hr.
"""
from __future__ import annotations

import base64
import os
import tempfile
import time
import logging
from pathlib import Path
from typing import List, Optional

import requests

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


class GitHubConnector:
    BASE = "https://api.github.com"

    def __init__(self, repo: str, token: Optional[str] = None, branch: str = "main"):
        self.repo   = repo       # "owner/repo"
        self.branch = branch
        self.headers = {"Accept": "application/vnd.github.v3+json"}
        if token:
            self.headers["Authorization"] = f"Bearer {token}"
        # Try GITHUB_TOKEN env var as fallback
        env_token = os.getenv("GITHUB_TOKEN")
        if env_token and not token:
            self.headers["Authorization"] = f"Bearer {env_token}"

    def _get(self, url: str) -> dict | list:
        r = requests.get(url, headers=self.headers, timeout=15)
        if r.status_code == 404:
            raise FileNotFoundError(f"GitHub 404: {url}")
        r.raise_for_status()
        return r.json()

    def _list_files(self, path: str = "") -> List[dict]:
        """Recursively list all files in the repo."""
        url = f"{self.BASE}/repos/{self.repo}/contents/{path}"
        try:
            items = self._get(url)
        except Exception as e:
            log.warning(f"GitHub list error at {path}: {e}")
            return []

        files = []
        if isinstance(items, dict):
            items = [items]

        for item in items:
            if item["type"] == "file":
                files.append(item)
            elif item["type"] == "dir":
                # Recurse — rate-limit friendly
                time.sleep(0.05)
                files.extend(self._list_files(item["path"]))

        return files

    def _download_file(self, item: dict, tmp_dir: str) -> Optional[str]:
        """Download file content and save to tmp_dir. Returns local path."""
        try:
            detail = self._get(item["url"])
            content_b64 = detail.get("content", "")
            content_b64 = content_b64.replace("\n", "")
            content = base64.b64decode(content_b64)

            safe_name = item["path"].replace("/", "_").replace("\\", "_")
            local_path = os.path.join(tmp_dir, safe_name)
            with open(local_path, "wb") as f:
                f.write(content)
            return local_path
        except Exception as e:
            log.warning(f"Failed to download {item['path']}: {e}")
            return None

    def fetch_all(self) -> List[dict]:
        """
        Returns evidence_index entries for all compatible files in the repo.
        Files are downloaded to a temp directory.
        """
        log.info(f"Scanning GitHub repo: {self.repo}")
        all_files = self._list_files()

        # Filter to evidence-compatible extensions
        evidence_files = [
            f for f in all_files
            if Path(f["name"]).suffix.lower() in EVIDENCE_EXTENSIONS
        ]

        if not evidence_files:
            log.warning(f"No evidence files found in {self.repo}")
            return []

        tmp_dir = tempfile.mkdtemp(prefix="grc_github_")
        index = []

        for item in evidence_files:
            local_path = self._download_file(item, tmp_dir)
            if local_path:
                index.append({
                    "file":   item["name"],
                    "path":   local_path,
                    "type":   _infer_type(item["name"]),
                    "source": f"github:{self.repo}/{item['path']}",
                    "sha":    item.get("sha", ""),
                })
                log.info(f"  GitHub ← {item['path']} [{_infer_type(item['name'])}]")

        return index
