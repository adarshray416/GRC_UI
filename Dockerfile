# ============================================================
# BABCOM GRC Platform — Dockerfile
# Single container: FastAPI backend + static frontend served together
#
# Build:  docker build -t babcom-grc .
# Run:    docker run -p 8000:8000 -e GITHUB_TOKEN=ghp_xxx babcom-grc
# ============================================================

FROM python:3.11-slim

# System deps for pdfplumber (uses pdfminer which needs no extra libs)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── Python deps ──────────────────────────────────────────────────────────────
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install optional deps for PDF export and scheduling
RUN pip install --no-cache-dir reportlab apscheduler

# ── Application code ─────────────────────────────────────────────────────────
COPY backend/ ./

# ── Frontend (served as static files by FastAPI) ─────────────────────────────
COPY Frontend/ ./frontend/

# ── Evidence + controls ───────────────────────────────────────────────────────
COPY backend/evidence_store/evidence/ ./evidence/

# ── Expose port ───────────────────────────────────────────────────────────────
EXPOSE 8000

# ── Environment defaults (override at runtime) ─────────────────────────────────
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# ── Health check ──────────────────────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')"

# ── Start ────────────────────────────────────────────────────────────────────
# CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
CMD uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1
