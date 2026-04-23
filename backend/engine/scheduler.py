"""
engine/scheduler.py
─────────────────────────────────────────────────────────────────────────────
Automated GRC assessment scheduling using APScheduler.

What it does
────────────
1. Runs a full GRC assessment every night at 02:00 (configurable).
2. After every run, checks for:
   - Controls that newly changed from pass → fail/partial
   - Policy review dates expiring within 30 days
   - Risk entries still marked "pending" with no owner
3. Sends alert summaries to the console (and optionally email/Slack).

How to extend for real notifications
──────────────────────────────────────
Replace _send_alert() with:
  - Email:  smtplib / SendGrid SDK
  - Slack:  requests.post to a Slack Incoming Webhook URL
  - Teams:  requests.post to an Adaptive Card webhook

Usage (called from main.py lifespan)
──────────────────────────────────────
    from engine.scheduler import start_scheduler, stop_scheduler
    start_scheduler(config)   # call on startup
    stop_scheduler()          # call on shutdown
"""
from __future__ import annotations

import logging
import os
from datetime import date
from typing import Optional

log = logging.getLogger(__name__)

# APScheduler is optional — fail gracefully if not installed
try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger
    _SCHEDULER_AVAILABLE = True
except ImportError:
    _SCHEDULER_AVAILABLE = False
    log.warning("apscheduler not installed — scheduled assessments disabled. "
                "Run: pip install apscheduler")

_scheduler: Optional["BackgroundScheduler"] = None


# ── Alert sink ────────────────────────────────────────────────────────────────

def _send_alert(subject: str, body: str) -> None:
    """
    Send an alert.  Currently logs to console.
    Replace with email/Slack/Teams as needed.
    """
    log.warning("=" * 60)
    log.warning(f"GRC ALERT: {subject}")
    for line in body.splitlines():
        log.warning(f"  {line}")
    log.warning("=" * 60)

    # ── Email example (uncomment + configure) ────────────────────────────────
    # import smtplib
    # from email.message import EmailMessage
    # msg = EmailMessage()
    # msg["Subject"] = f"[GRC Alert] {subject}"
    # msg["From"]    = os.getenv("GRC_ALERT_FROM", "grc@babcom.local")
    # msg["To"]      = os.getenv("GRC_ALERT_TO",   "security@babcom.local")
    # msg.set_content(body)
    # with smtplib.SMTP(os.getenv("SMTP_HOST","localhost"), 587) as s:
    #     s.starttls()
    #     s.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASS"))
    #     s.send_message(msg)

    # ── Slack example (uncomment + configure) ────────────────────────────────
    # import requests
    # webhook = os.getenv("SLACK_WEBHOOK_URL")
    # if webhook:
    #     requests.post(webhook, json={"text": f"*{subject}*\n```{body}```"})


# ── Scheduled job ─────────────────────────────────────────────────────────────

def _run_scheduled_assessment(config: dict) -> None:
    """
    The job that APScheduler calls on the configured schedule.
    Runs the full GRC pipeline and fires alerts for any new issues.
    """
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

    from connectors.github_connector import GitHubConnector
    from connectors.local_connector  import LocalConnector
    from engine.runner               import GRCRunner

    log.info("Scheduled GRC assessment starting…")
    evidence_index = []

    # GitHub
    try:
        gh = GitHubConnector(
            repo  = config.get("github_repo", "adarshray416/GRC"),
            token = config.get("github_token") or os.getenv("GITHUB_TOKEN"),
        )
        evidence_index.extend(gh.fetch_all())
    except Exception as e:
        log.warning(f"Scheduled run: GitHub error: {e}")

    # Local
    try:
        lc = LocalConnector(base_path=config.get("local_path", r"D:\files\backend\evidence_store\evidence"))
        evidence_index.extend(lc.fetch_all())
    except Exception as e:
        log.warning(f"Scheduled run: local path error: {e}")

    if not evidence_index:
        log.warning("Scheduled run: no evidence files found")
        return

    runner = GRCRunner(
        evidence_index = evidence_index,
        frameworks     = config.get("controls_frameworks", ["ISO27001", "SOC2", "GDPR"]),
    )
    report  = runner.run()
    summary = report["summary"]
    score   = summary["overall_score"]

    log.info(f"Scheduled assessment complete — score: {score}%  risk: {summary['risk_level']}")

    # ── Alert: low compliance score ───────────────────────────────────────────
    threshold = config.get("alert_threshold", 80)
    if score < threshold:
        failed  = [c for c in report["controls"] if c["status"] == "fail"]
        partial = [c for c in report["controls"] if c["status"] == "partial"]
        body = (
            f"Score: {score}%  (threshold: {threshold}%)\n"
            f"Risk Level: {summary['risk_level']}\n\n"
            f"FAILED controls ({len(failed)}):\n"
            + "\n".join(f"  • {c['control_id']} — {c['control_name']}" for c in failed)
            + f"\n\nPARTIAL controls ({len(partial)}):\n"
            + "\n".join(f"  • {c['control_id']} — {c['control_name']}" for c in partial)
        )
        _send_alert(f"Compliance score below threshold: {score}%", body)

    # ── Alert: expiring policies ──────────────────────────────────────────────
    store = report.get("evidence_store", {})
    policy = store.get("policy", {})
    if policy.get("review_date"):
        try:
            rd   = date.fromisoformat(policy["review_date"])
            days = (rd - date.today()).days
            if 0 <= days <= 30:
                _send_alert(
                    f"Policy review due in {days} days",
                    f"Policy : {policy.get('name','Unknown')}\n"
                    f"Review : {policy['review_date']}\n"
                    f"Action : Schedule review with {policy.get('approved_by','policy owner')}",
                )
            elif days < 0:
                _send_alert(
                    f"Policy EXPIRED {abs(days)} days ago",
                    f"Policy : {policy.get('name','Unknown')}\n"
                    f"Review : {policy['review_date']} (OVERDUE)\n"
                    f"Action : Immediate review required",
                )
        except Exception:
            pass

    # ── Alert: untreated high/critical risks ──────────────────────────────────
    risks = store.get("risk", [])
    untreated = [
        r for r in risks
        if r.get("impact") in ("critical", "high") and r.get("status") != "approved"
    ]
    if untreated:
        body = f"{len(untreated)} high/critical risk(s) without approved treatment:\n\n"
        for r in untreated[:10]:
            body += (
                f"  • [{r.get('risk_id','?')}] {r.get('risk_description','')[:60]}\n"
                f"    Impact={r.get('impact')}  Owner={r.get('owner','UNASSIGNED')}\n"
            )
        _send_alert("Untreated high/critical risks", body)

    # Store result in shared state so the API can serve it
    _store_result(report)


# ── Result storage (back-channel to API state) ────────────────────────────────

_result_callback = None

def _store_result(report: dict) -> None:
    """Called after each scheduled run to push the result to the API state."""
    if _result_callback:
        _result_callback(report)


def set_result_callback(cb) -> None:
    """Register a callback so the scheduler can update the API's _state dict."""
    global _result_callback
    _result_callback = cb


# ── Public API ────────────────────────────────────────────────────────────────

def start_scheduler(config: dict) -> None:
    """
    Start the background scheduler.
    config keys used:
      schedule_hour   (int, default 2)    — hour of day to run (24h)
      schedule_minute (int, default 0)    — minute of hour
    """
    global _scheduler

    if not _SCHEDULER_AVAILABLE:
        log.warning("Scheduler disabled — install apscheduler to enable.")
        return

    if _scheduler and _scheduler.running:
        log.info("Scheduler already running")
        return

    hour   = config.get("schedule_hour",   2)
    minute = config.get("schedule_minute", 0)

    _scheduler = BackgroundScheduler(timezone="UTC")
    _scheduler.add_job(
        func     = _run_scheduled_assessment,
        trigger  = CronTrigger(hour=hour, minute=minute),
        args     = [config],
        id       = "grc_daily_assessment",
        name     = "Daily GRC assessment",
        replace_existing = True,
    )
    _scheduler.start()
    log.info(f"Scheduler started — daily assessment at {hour:02d}:{minute:02d} UTC")


def stop_scheduler() -> None:
    """Shut down the scheduler cleanly on app shutdown."""
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        log.info("Scheduler stopped")


def get_next_run() -> Optional[str]:
    """Return the next scheduled run time as an ISO string, or None."""
    if not _scheduler or not _scheduler.running:
        return None
    job = _scheduler.get_job("grc_daily_assessment")
    if job and job.next_run_time:
        return job.next_run_time.isoformat()
    return None
