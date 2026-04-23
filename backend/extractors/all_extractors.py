"""extractors/all_extractors.py — policy, risk, log, access"""
from __future__ import annotations
import re
from datetime import datetime, date
from typing import List, Optional

from models.canonical import (
    PolicyModel, RiskModel, LogEntryModel, LogCollectionModel,
    AccessReviewModel, AccessReviewCollectionModel
)

# ── Date helpers ──────────────────────────────────────────────────────────────
_DATE_FMTS = ["%Y-%m-%d","%d/%m/%Y","%m/%d/%Y","%d %B %Y","%B %d, %Y","%d-%b-%Y","%d-%m-%Y"]
def _parse_date(s: str) -> Optional[date]:
    for f in _DATE_FMTS:
        try: return datetime.strptime(s.strip(), f).date()
        except: pass
    return None

def _find_date(text: str, labels: List[str]) -> Optional[str]:
    for label in labels:
        m = re.search(rf"{re.escape(label)}\s*[:\-]?\s*([0-9A-Za-z ,/\-]{{6,20}})", text, re.IGNORECASE)
        if m:
            d = _parse_date(m.group(1).strip())
            if d: return str(d)
    return None

def _find(text: str, labels: List[str], max_len: int = 120) -> Optional[str]:
    for label in labels:
        m = re.search(rf"{re.escape(label)}\s*[:\-=]?\s*(.{{1,{max_len}}})", text, re.IGNORECASE)
        if m:
            val = m.group(1).strip().split("\n")[0].strip()
            if val: return val
    return None

# ── Policy extractor ──────────────────────────────────────────────────────────
POLICY_KW = ["information security","security policy","acceptable use","data protection",
             "privacy policy","access control","incident response","change management"]

def extract_policy(raw: str, path: str) -> dict:
    name = (_find(raw, ["title","policy name","document name","policy:"]) or
            next((l.strip() for l in raw.splitlines()[:20] if 5 < len(l.strip()) < 120), None) or
            Path(path).stem.replace("_"," "))
    return PolicyModel(
        name           = name,
        version        = _find(raw, ["version","ver.","revision","rev."], 20),
        approved_by    = _find(raw, ["approved by","authorised by","authorized by","signed by","document owner","owner"]),
        approval_date  = _find_date(raw, ["approval date","approved on","date approved","effective date"]),
        review_date    = _find_date(raw, ["review date","next review","expiry date","valid until","review by"]),
        scope          = _find(raw, ["scope","applies to","coverage"], 300),
        classification = _find(raw, ["classification","sensitivity"], 40),
        keywords_found = [k for k in POLICY_KW if k in raw.lower()],
        source_file    = path,
    ).to_dict()

# ── Risk extractor ────────────────────────────────────────────────────────────
_IMPACT_MAP = {"critical":"critical","very high":"critical","high":"high",
               "medium":"medium","moderate":"medium","low":"low","info":"info"}
_STATUS_MAP = {"approved":"approved","accepted":"approved","closed":"approved",
               "pending":"pending","open":"pending","active":"pending","rejected":"rejected"}

def _norm_level(t: str) -> str: return _IMPACT_MAP.get(t.strip().lower(), "medium")

def _parse_risk_block(block: str, idx: int) -> Optional[dict]:
    if len(block.strip()) < 10: return None
    desc = _find(block, ["risk","description","issue"]) or block.strip().splitlines()[0][:200]
    raw_status = _find(block, ["status","treatment status"], 20) or "pending"
    return RiskModel(
        risk_id          = f"R-{idx+1:03d}",
        risk_description = desc,
        impact           = _norm_level(_find(block, ["impact","severity","consequence"], 20) or "medium"),
        likelihood       = _norm_level(_find(block, ["likelihood","probability"], 20) or "medium"),
        owner            = _find(block, ["owner","responsible","assigned to","risk owner"]),
        status           = _STATUS_MAP.get(raw_status.strip().lower(), "pending"),
        mitigation       = _find(block, ["mitigation","treatment","control","action"], 300),
        residual_risk    = _norm_level(_find(block, ["residual","residual risk"], 20) or "medium"),
    ).to_dict()

def extract_risks(raw: str, path: str) -> List[dict]:
    blocks = [b for b in re.split(r"\n{2,}", raw) if b.strip()]
    if len(blocks) <= 1:
        blocks = [l for l in raw.splitlines() if len(l.strip()) > 15]
    results = []
    for i, b in enumerate(blocks):
        p = _parse_risk_block(b, i)
        if p: results.append(p)
    return results

# ── Log extractor ─────────────────────────────────────────────────────────────
_TS_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?|"
    r"\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}|"
    r"\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
)
_TS_FMTS = ["%Y-%m-%dT%H:%M:%S","%Y-%m-%d %H:%M:%S","%d/%m/%Y %H:%M:%S","%b %d %H:%M:%S"]
SEC_ACTIONS = {"login","logout","delete","export","sudo","privilege","password_change","failed","denied"}

def _parse_ts_str(raw: str) -> Optional[str]:
    raw = raw.strip()
    for f in _TS_FMTS:
        try: return datetime.strptime(raw, f).isoformat()
        except: pass
    try: return datetime.fromisoformat(raw.replace("Z","+00:00")).isoformat()
    except: return None

def _kv(line: str, keys: List[str]) -> Optional[str]:
    for k in keys:
        m = re.search(rf"{k}[=:\s]+([^\s,;|]+)", line, re.IGNORECASE)
        if m: return m.group(1).strip()
    return None

def _parse_log_line(line: str) -> Optional[LogEntryModel]:
    line = line.strip()
    if not line or len(line) < 10: return None
    ts_m   = _TS_RE.search(line)
    ts_str = _parse_ts_str(ts_m.group()) if ts_m else None
    after  = line[ts_m.end():].strip() if ts_m else line
    action = _kv(line, ["action","event","type","operation"]) or next(
        (a for a in SEC_ACTIONS if a in line.lower()), None)
    return LogEntryModel(
        event     = after[:200],
        timestamp = ts_str,
        user      = _kv(line, ["user","username","usr","uid","account"]),
        source_ip = _kv(line, ["ip","src_ip","source_ip","from","host"]),
        action    = action,
        outcome   = _kv(line, ["status","result","outcome"]),
        resource  = _kv(line, ["resource","target","file","path","object"]),
    )

def extract_logs(raw: str, path: str) -> dict:
    entries = [e for l in raw.splitlines() if (e := _parse_log_line(l))]
    dated   = [e for e in entries if e.timestamp]
    return LogCollectionModel(
        source_file = path,
        entries     = entries,
        start_date  = min((e.timestamp for e in dated), default=None),
        end_date    = max((e.timestamp for e in dated), default=None),
    ).to_dict()

# ── Access extractor ──────────────────────────────────────────────────────────
_ASTATUS_MAP = {"active":"active","enabled":"active","revoked":"revoked","disabled":"revoked",
                "terminated":"revoked","suspended":"suspended","locked":"suspended",
                "under review":"under_review","pending":"under_review"}

def _parse_access_block(block: str) -> Optional[dict]:
    if len(block.strip()) < 5: return None
    user = _find(block, ["user","username","employee","name","account"])
    if not user:
        first = block.strip().splitlines()[0]
        user  = first.split()[0] if first else None
    if not user: return None
    role     = _find(block, ["role","position","job title","access role","privilege"]) or "unknown"
    mfa_raw  = _find(block, ["mfa","2fa","two-factor","multi-factor"], 10)
    priv_raw = _find(block, ["privileged","admin","elevated","root"], 10)
    status_r = _find(block, ["status","account status"], 20) or "active"
    mfa = mfa_raw.strip().lower() in ("yes","true","enabled","1") if mfa_raw else None
    priv = bool(priv_raw and priv_raw.strip().lower() in ("yes","true","admin","root","elevated"))
    if not priv and role:
        priv = any(k in role.lower() for k in ("admin","root","superuser","dba"))
    lr = _find_date(block, ["last reviewed","reviewed on","review date","date reviewed"])
    return AccessReviewModel(
        user=user, role=role,
        department=_find(block,["department","dept","team","division"]),
        access_level=_find(block,["access level","level","permission"],30),
        last_reviewed=lr, reviewer=_find(block,["reviewer","reviewed by","approved by"]),
        status=_ASTATUS_MAP.get(status_r.strip().lower(),"active"),
        mfa_enabled=mfa, privileged=priv,
    ).to_dict()

def extract_access_reviews(raw: str, path: str) -> dict:
    system = _find(raw, ["system","application","platform","service"])
    period = _find(raw, ["review period","period","quarter","reporting period"])
    blocks = [b for b in re.split(r"\n{2,}", raw) if b.strip()]
    if len(blocks) <= 1:
        blocks = [l for l in raw.splitlines() if len(l.strip()) > 5]
    records = []
    for b in blocks:
        p = _parse_access_block(b)
        if p:
            records.append(AccessReviewModel.from_dict(p))
    return AccessReviewCollectionModel(
        system=system, review_period=period, records=records, source_file=path
    ).to_dict()

# Need Path for policy extractor
from pathlib import Path
