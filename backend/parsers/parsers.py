"""parsers/parsers.py"""
from __future__ import annotations
import csv, io, json
from pathlib import Path

def parse_txt(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()

def parse_pdf(path: str) -> str:
    try:
        import pdfplumber
        parts = []
        with pdfplumber.open(path) as pdf:
            for page in pdf.pages:
                t = page.extract_text()
                if t: parts.append(t)
        return "\n".join(parts)
    except ImportError:
        return f"[pdfplumber not installed — cannot parse {path}]"

def parse_csv(path: str) -> str:
    """Convert CSV to readable text so existing extractors can process it."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        lines = []
        for row in reader:
            lines.append("  ".join(f"{k}: {v}" for k, v in row.items()))
        return "\n\n".join(lines)

def parse_json(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)
    return json.dumps(data, indent=2)

def parse_md(path: str) -> str:
    return parse_txt(path)

PARSER_MAP = {
    ".txt": parse_txt,
    ".pdf": parse_pdf,
    ".csv": parse_csv,
    ".log": parse_txt,
    ".json": parse_json,
    ".md": parse_md,
}

def parse_file(path: str) -> str:
    ext = Path(path).suffix.lower()
    parser = PARSER_MAP.get(ext)
    if not parser:
        raise ValueError(f"No parser for extension: {ext}")
    return parser(path)
