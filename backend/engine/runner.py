"""engine/runner.py — full pipeline orchestrator"""
from __future__ import annotations
import json, logging, os, sys
from pathlib import Path
from typing import Callable, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from parsers.parsers import parse_file
from extractors.all_extractors import extract_policy, extract_risks, extract_logs, extract_access_reviews
from engine.control_evaluator import ControlEvaluator
from datetime import datetime

log = logging.getLogger(__name__)

EXTRACTOR_MAP = {
    "policy":        extract_policy,
    "risk":          extract_risks,
    "logs":          extract_logs,
    "access_review": extract_access_reviews,
}

CONTROLS_PATH = Path(__file__).parent.parent / "controls" / "controls.json"

class GRCRunner:
    def __init__(
        self,
        evidence_index: List[dict] = None,
        frameworks: List[str] = None,
        controls_path: str = None,
    ):
        self.evidence_index = evidence_index or []
        self.frameworks     = frameworks or ["ISO27001","SOC2","GDPR"]
        cp = controls_path or str(CONTROLS_PATH)
        with open(cp) as f:
            self.controls = json.load(f)

    def _progress(self, cb: Optional[Callable], msg: str):
        log.info(msg)
        if cb: cb(msg)

    def build_store(self, cb=None) -> dict:
        store: dict = {"_files": {}}
        for item in self.evidence_index:
            fpath = item.get("path","")
            etype = item.get("type","")
            fname = item.get("file", Path(fpath).name)
            source = item.get("source","local")

            if not os.path.exists(fpath):
                self._progress(cb, f"  Skip (not found): {fname}")
                continue

            try:
                raw = parse_file(fpath)
            except Exception as e:
                self._progress(cb, f"  Parse error [{fname}]: {e}")
                continue

            if not raw or not raw.strip():
                self._progress(cb, f"  Empty content: {fname}")
                continue

            extractor = EXTRACTOR_MAP.get(etype)
            if not extractor:
                self._progress(cb, f"  No extractor for type '{etype}': {fname}")
                continue

            try:
                canonical = extractor(raw, fpath)
            except Exception as e:
                self._progress(cb, f"  Extractor error [{fname}]: {e}")
                continue

            if etype == "risk":
                store["risk"] = store.get("risk",[]) + (canonical if isinstance(canonical,list) else [canonical])
            else:
                store[etype] = canonical

            store["_files"].setdefault(etype,[]).append(f"{source}:{fname}")
            self._progress(cb, f"  Extracted [{etype}] ← {fname}")

        return store

    def run(self, progress_cb=None) -> dict:
        self._progress(progress_cb, f"Building evidence store from {len(self.evidence_index)} file(s)…")
        store    = self.build_store(progress_cb)
        evaluator = ControlEvaluator(self.controls)
        self._progress(progress_cb, f"Evaluating {len(self.controls)} controls across {self.frameworks}…")
        results  = evaluator.evaluate_all(store, self.frameworks)
        summary  = ControlEvaluator.summary(results)
        return {
            "generated_at":   datetime.utcnow().isoformat()+"Z",
            "summary":        summary,
            "controls":       [r.to_dict() for r in results],
            "evidence_store": {k:v for k,v in store.items() if not k.startswith("_")},
            "sources":        self.evidence_index,
        }
