# BABCOM GRC Platform v2

**FastAPI backend + React frontend + GitHub scraper + Local path watcher**

Evidence pushed to `adarshray416/GRC` or dropped in `D:\Babcom\GRC` is automatically scraped, parsed, and evaluated against ISO 27001, SOC 2, and GDPR controls.

---

## Architecture

```
GitHub Repo (adarshray416/GRC)       D:\Babcom\GRC (local)
         │                                    │
         └──────── GitHubConnector ───────────┘
                          │
                   LocalConnector
                          │
                    Parser (PDF/TXT/CSV)
                          │
                   Extractor (policy/risk/logs/access)
                          │
                   Canonical Model (typed)
                          │
                  Control Evaluator (ISO27001 + SOC2 + GDPR)
                          │
                    FastAPI REST API   ←──── React Frontend
                    /api/report              (index.html)
                    /api/run
                    /api/status
```

---

## Quick Start

### 1. Clone and install
```bash
git clone https://github.com/adarshray416/GRC.git
cd GRC
bash setup.sh
```

### 2. Open the frontend
Open `frontend/index.html` in your browser (no build step needed).

### 3. Run an assessment
- Set your GitHub repo: `adarshray416/GRC`
- Set local path: `D:\Babcom\GRC`
- Select frameworks: ISO27001, SOC2, GDPR
- Click **Run Assessment**

The backend will scrape both sources and return results via the API.

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/run` | Start an assessment |
| `GET`  | `/api/status` | Poll run progress |
| `GET`  | `/api/report` | Full compliance report |
| `GET`  | `/api/report/summary` | Score + risk level |
| `GET`  | `/api/report/controls` | All control results |
| `GET`  | `/api/report/controls/{id}` | Single control |
| `GET`  | `/api/report/evidence` | Canonical evidence store |
| `GET`  | `/api/report/risks` | Risk register entries |
| `GET`  | `/api/sources` | Files loaded this run |
| `GET`  | `/api/frameworks` | Available frameworks |
| `GET`  | `/api/health` | Health check |

Interactive docs: http://localhost:8000/docs

---

## Pushing Evidence to GitHub

Push any of these file types and the GitHub connector will scrape them automatically:

| File naming | Auto-detected as |
|-------------|-----------------|
| `*policy*`, `*isms*`, `*security*` | `policy` |
| `*risk*`, `*register*`, `*assessment*` | `risk` |
| `*log*`, `*audit*`, `*event*` | `logs` |
| `*access*`, `*review*`, `*iam*` | `access_review` |

Supported formats: `.txt`, `.pdf`, `.csv`, `.log`, `.json`, `.md`

### Example push:
```bash
cp my_security_policy.pdf evidence/
cp risk_register.csv evidence/
cp audit_log.txt evidence/
git add evidence/
git commit -m "Add Q4 evidence"
git push
```
Then click **Run Assessment** — the backend fetches the latest files.

---

## Local Evidence (D:\Babcom\GRC)

Drop files anywhere in `D:\Babcom\GRC` (or subdirectories). The local connector scans recursively and picks up all `.txt`, `.pdf`, `.csv`, `.log` files.

---

## Auto-scan on Push (GitHub Actions)

Every push to the repo triggers `.github/workflows/grc_scan.yml`, which:
1. Scans all evidence files in the repo
2. Runs the GRC engine
3. Saves `grc_report.json` as a workflow artifact

No server needed for CI — the engine runs in GitHub Actions.

---

## Adding Controls

Edit `backend/controls/controls.json`:
```json
{
  "control_id": "ISO-A.5.2",
  "name": "Information Security Roles",
  "framework": "ISO27001",
  "evidence_type": "policy",
  "framework_ref": "ISO 27001:2022 A.5.2",
  "recommendation": "Define and assign security roles."
}
```

No code changes needed.

---

## Project Structure

```
grc_platform/
├── backend/
│   ├── main.py                   ← FastAPI app
│   ├── connectors/
│   │   ├── github_connector.py   ← GitHub API scraper
│   │   └── local_connector.py    ← D:\Babcom\GRC scanner
│   ├── parsers/parsers.py        ← PDF/TXT/CSV/JSON
│   ├── extractors/all_extractors.py
│   ├── models/canonical.py
│   ├── engine/
│   │   ├── control_evaluator.py  ← ISO27001 + SOC2 + GDPR
│   │   └── runner.py
│   ├── controls/controls.json    ← 9 controls across 3 frameworks
│   └── requirements.txt
├── frontend/
│   └── index.html                ← React SPA (no build needed)
├── .github/workflows/
│   └── grc_scan.yml              ← Auto-scan on push
├── setup.sh
└── README.md
```
