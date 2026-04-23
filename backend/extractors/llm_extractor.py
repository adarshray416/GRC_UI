"""
extractors/llm_extractor.py
─────────────────────────────────────────────────────────────────────────────
LLM-assisted field extraction using the Anthropic API.

When to use
───────────
The regex extractors in policy_extractor.py / risk_extractor.py work well
for structured documents (e.g. "Approved by: Alice Smith").  They struggle
with:
  - Prose-format policies with no explicit labels
  - PDFs with garbled text after extraction
  - Non-English documents
  - Documents where fields are buried in paragraphs

This module is a FALLBACK.  It is called by the extractor only when the
regex confidence score drops below a threshold (default 0.6).

To enable
─────────
1. pip install anthropic
2. Set the ANTHROPIC_API_KEY environment variable
3. Set ENABLE_LLM_EXTRACTION=true in your environment

Cost note
─────────
Each LLM call processes up to 3000 characters of document text.
~1000 input tokens + ~200 output tokens per call ≈ very cheap.
Only fires when regex confidence < 0.6, so it won't run on clean docs.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Optional

log = logging.getLogger(__name__)

_ENABLED = os.getenv("ENABLE_LLM_EXTRACTION", "false").lower() == "true"
_LLM_CONFIDENCE_THRESHOLD = 0.6   # only call LLM if regex score < this


# ── Prompts ────────────────────────────────────────────────────────────────────

_POLICY_PROMPT = """\
You are a GRC (Governance, Risk, Compliance) data extractor.
Extract the following fields from the policy document below.

Return ONLY a valid JSON object with exactly these keys:
  name          (string — policy title)
  version       (string or null — e.g. "2.1")
  approved_by   (string or null — person who approved the policy)
  approval_date (string or null — ISO format YYYY-MM-DD)
  review_date   (string or null — ISO format YYYY-MM-DD, when next review is due)
  scope         (string or null — who/what the policy applies to, max 200 chars)
  classification (string or null — e.g. "Confidential", "Internal")

Use null for any field you cannot find. Do NOT include any explanation or
markdown — return only the JSON object.

Document:
{text}
"""

_RISK_PROMPT = """\
You are a GRC data extractor. Extract risk register entries from the text below.

Return ONLY a valid JSON array where each element has these keys:
  risk_description (string — what the risk is)
  impact           (string — one of: critical, high, medium, low, info)
  likelihood       (string — one of: critical, high, medium, low, info)
  owner            (string or null — person responsible)
  status           (string — one of: approved, pending, rejected)
  mitigation       (string or null — how the risk is being treated)

Return at least one entry. Do NOT include any explanation — only the JSON array.

Document:
{text}
"""


# ── Core LLM call ──────────────────────────────────────────────────────────────

def _call_claude(prompt: str) -> Optional[str]:
    """Call the Anthropic API and return the text response."""
    try:
        import anthropic
    except ImportError:
        log.warning("anthropic package not installed. Run: pip install anthropic")
        return None

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        log.warning("ANTHROPIC_API_KEY not set — LLM extraction skipped")
        return None

    try:
        client = anthropic.Anthropic(api_key=api_key)
        message = client.messages.create(
            model      = "claude-sonnet-4-6",
            max_tokens = 500,
            messages   = [{"role": "user", "content": prompt}],
        )
        return message.content[0].text
    except Exception as e:
        log.warning(f"LLM extraction failed: {e}")
        return None


def _safe_json(text: str) -> Optional[dict | list]:
    """Parse JSON, stripping markdown fences if present."""
    if not text:
        return None
    text = text.strip()
    # Strip ```json … ``` fences
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError as e:
        log.warning(f"LLM returned invalid JSON: {e}")
        return None


# ── Public functions ───────────────────────────────────────────────────────────

def llm_extract_policy(raw_text: str, existing: dict) -> dict:
    """
    Use Claude to fill missing fields in a partially-extracted policy.

    Args:
        raw_text: Full document text (truncated to 3000 chars for cost control).
        existing: Dict from regex extraction (may have None values).

    Returns:
        Merged dict — LLM values fill in where regex returned None.
        Original regex values are kept if they exist (regex is cheaper + faster).
    """
    if not _ENABLED:
        return existing

    # Only call if we're missing critical fields
    missing_critical = not existing.get("approved_by") or not existing.get("review_date")
    if not missing_critical:
        return existing

    log.info("LLM fallback: extracting policy fields…")
    prompt = _POLICY_PROMPT.format(text=raw_text[:3000])
    raw_response = _call_claude(prompt)
    llm_data = _safe_json(raw_response)

    if not isinstance(llm_data, dict):
        return existing

    # Merge: keep regex values where they exist, fill gaps with LLM values
    for key, llm_value in llm_data.items():
        if key in existing and existing[key] is None and llm_value:
            existing[key] = llm_value
            log.info(f"  LLM filled: {key} = {str(llm_value)[:60]}")

    return existing


def llm_extract_risks(raw_text: str, existing_risks: list) -> list:
    """
    Use Claude to extract risk entries when regex found nothing useful.

    Args:
        raw_text:       Full document text.
        existing_risks: List from regex extraction (may be empty or sparse).

    Returns:
        List of risk dicts — LLM results if regex found < 2 entries.
    """
    if not _ENABLED:
        return existing_risks

    # Only use LLM if regex found very few risks
    if len(existing_risks) >= 2:
        return existing_risks

    log.info("LLM fallback: extracting risk entries…")
    prompt = _RISK_PROMPT.format(text=raw_text[:3000])
    raw_response = _call_claude(prompt)
    llm_data = _safe_json(raw_response)

    if not isinstance(llm_data, list):
        return existing_risks

    # Add sequential IDs
    result = []
    for i, r in enumerate(llm_data):
        if isinstance(r, dict) and r.get("risk_description"):
            r.setdefault("risk_id", f"R-{i+1:03d}")
            r.setdefault("status", "pending")
            result.append(r)

    log.info(f"  LLM extracted {len(result)} risk entries")
    return result if result else existing_risks
