"""Core prompt-injection scanner engine.

Regex-based detection with configurable rules and weighted risk scoring.
Pure stdlib; no network or model required.

Rules are loaded from ``ai/scanner/payloads/rules.json`` by default and can be
tuned without editing code. If the file is missing or invalid, built-in
defaults are used (best effort, never crashes).
"""

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple

from ..scoring.levels import score_level

DEFAULT_KEYWORD_PATTERNS: List[Tuple[str, float]] = [
    (r"\bignore (all )?(previous|above|prior|earlier) (instructions|prompts|context|chat|messages|input)\b", 0.9),
    (r"\bdisregard (all )?(previous|above|prior|earlier) (instructions|prompts|context)\b", 0.9),
    (r"\bforget (all )?(previous|above|prior) (instructions|prompts|context|rules)\b", 0.85),
    (r"\byour (system )?prompt\b", 0.5),
    (r"\bnot subject to (any )?(rules|restrictions|guidelines)\b", 0.8),
    (r"\byou are now\b", 0.6),
    (r"\byou will now act as\b", 0.7),
    (r"\bact as (a |an |an )?omniscient\b", 0.7),
    (r"\bbut (you )?(don'?t|do not) (have to|need to) (follow|obey) (the )?(rules|guidelines)\b", 0.85),
    (r"\btell me (your|the) (system )?(prompt|instructions)\b", 0.8),
    (r"\breveal\b.*\b(instructions|prompt|system)\b", 0.7),
    (r"\bdev\s*mode\b", 0.7),
    (r"\bdan\b(\s|\W|$)", 0.6),
    (r"\bjailbreak\b", 0.9),
    (r"\b(don'?t|do not) mention\b.*\b(rules|restrictions|safety|filter|guidelines|instructions|an ai|ai model|this (prompt|conversation))\b", 0.5),
    (r"\b([0-9]+ )?(times|time)\b.*\b(above|previous)\b", 0.5),
    (r"\bpretend\b.*\b(no (rules|safety|restrictions|censorship)|unrestricted|unfiltered|can say anything)\b", 0.7),
    (r"\bsimulate\b.*\b(bypass|override)\b", 0.7),
    (r"\boverride\b.*\b(instructions|safety|rules|policy)\b", 0.8),
    (r"\bbypass\b.*\b(safety|filter|restrictions|rules)\b", 0.8),
    (r"\bremove\b.*\b(safety|content )?(filter|restrictions)\b", 0.7),
    (r"\bdo not refuse\b", 0.8),
    (r"\byou cannot refuse\b", 0.7),
    (r"\bmust answer\b", 0.5),
    (r"\bno matter what\b", 0.5),
]

DEFAULT_LINE_PATTERNS: List[Tuple[str, float]] = [
    (r"(?i)system\s*:\s*(?=forget|ignore|you are|act as)", 0.7),
    (r"(?i)developer\s*:\s*(?=forget|ignore|you are|act as)", 0.7),
    (r"(?i)human\s*:\s*(?=forget|ignore|you are|act as|disregard)", 0.6),
]

DEFAULT_SCORING: Dict[str, float] = {"diminish_multi": 0.15, "max_score": 1.0}

RULES_PATH = str(Path(__file__).resolve().parents[1] / "payloads" / "rules.json")


def load_rules(path: str = None) -> Dict[str, List[Tuple[str, float]] | Dict[str, float]]:
    """Load and compile rules from a JSON config file.

    Falls back to built-in defaults when the file is missing or invalid.
    Returns a dict with keys: keyword_patterns, line_patterns, scoring.
    """
    path = path or RULES_PATH
    if not os.path.exists(path):
        return _build_rules(DEFAULT_KEYWORD_PATTERNS, DEFAULT_LINE_PATTERNS)

    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return _build_rules(DEFAULT_KEYWORD_PATTERNS, DEFAULT_LINE_PATTERNS)

    def entries(key, fallback):
        items = data.get(key, [])
        # Unsupported entries are skipped silently so a bad key does not
        # crash the scanner.
        return [
            (str(entry["pattern"]), float(entry.get("weight", 0.5)))
            for entry in items
            if isinstance(entry, dict) and entry.get("enabled", True) and "pattern" in entry
            and _valid_regex(str(entry["pattern"]))
        ]

    kws = entries("keyword_patterns", DEFAULT_KEYWORD_PATTERNS) or DEFAULT_KEYWORD_PATTERNS
    lns = entries("line_patterns", DEFAULT_LINE_PATTERNS) or DEFAULT_LINE_PATTERNS

    scoring = dict(DEFAULT_SCORING)
    scoring.update(
        {k: float(v) for k, v in data.get("scoring", {}).items() if k in DEFAULT_SCORING}
    )

    return _build_rules(kws, lns, scoring)


def _valid_regex(pattern: str) -> bool:
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False


def _build_rules(kws, lns, scoring=None) -> Dict:
    return {
        "keyword_patterns": _compile(kws),
        "line_patterns": _compile(lns),
        "scoring": scoring or dict(DEFAULT_SCORING),
    }


def _compile(pairs: List[Tuple[str, float]]) -> List[Tuple[re.Pattern, float]]:
    return [(re.compile(p, re.IGNORECASE), w) for p, w in pairs]


@dataclass
class Detection:
    pattern: str
    weight: float
    match: str


@dataclass
class ScanResult:
    risk_score: float
    level: str
    detections: List[Detection] = field(default_factory=list)

    def to_dict(self):
        return {
            "level": self.level,
            "risk_score": round(self.risk_score, 3),
            "detections": [
                {"pattern": d.pattern, "weight": d.weight, "match": d.match}
                for d in self.detections
            ],
        }


def scan(text: str, rules: Dict = None) -> ScanResult:
    if rules is None:
        rules = load_rules()

    if not text or not text.strip():
        return ScanResult(risk_score=0.0, level="SAFE")

    detections: List[Detection] = []

    for compiled, weight in rules["keyword_patterns"]:
        for m in compiled.finditer(text):
            detections.append(Detection(pattern=m.re.pattern, weight=weight, match=m.group(0)))

    # Line-based heuristics (multi-line / role spoofing).
    for line in text.splitlines():
        for compiled, weight in rules["line_patterns"]:
            m = compiled.search(line)
            if m:
                detections.append(Detection(pattern=m.re.pattern, weight=weight, match=m.group(0)))

    if not detections:
        return ScanResult(risk_score=0.0, level="SAFE")

    scoring = rules["scoring"]
    diminish = scoring.get("diminish_multi", 0.15)
    max_score = scoring.get("max_score", 1.0)

    raw = sum(d.weight for d in detections)
    score = min(max_score, raw * (1 / (1 + diminish * (len(detections) - 1))))
    return ScanResult(risk_score=score, level=score_level(score), detections=detections)