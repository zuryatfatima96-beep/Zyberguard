"""Password strength evaluation and SHA-256 hashing.

Pure logic, no GUI or I/O — easy to unit test on its own.
"""
from __future__ import annotations

import hashlib
import re
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict

SPECIAL_CHARS = r"!@#$%^&*"

# Compiled once at import time rather than per-call.
_SPECIAL_RE = re.compile(f"[{re.escape(SPECIAL_CHARS)}]")
_UPPER_RE = re.compile(r"[A-Z]")
_DIGIT_RE = re.compile(r"\d")

RATING_BY_SCORE = {
    4: "Strong",
    3: "Medium",
    2: "Weak",
    1: "Very Weak",
    0: "Very Weak",
}


@dataclass
class PasswordResult:
    score: int                                   # 0-4
    rating: str
    sha256_hash: str
    checks: "OrderedDict[str, bool]" = field(default_factory=OrderedDict)

    @property
    def is_strong(self) -> bool:
        return self.score == 4

    @property
    def missing(self) -> list:
        return [label for label, passed in self.checks.items() if not passed]


def check_password(password: str) -> PasswordResult:
    """Score a password against the four criteria from the proposal
    and return the full breakdown (used to render the checklist + hash)."""
    checks: Dict[str, bool] = OrderedDict([
        ("At least 8 characters", len(password) >= 8),
        ("At least one capital letter", bool(_UPPER_RE.search(password))),
        ("At least one number", bool(_DIGIT_RE.search(password))),
        (f"At least one special character ({SPECIAL_CHARS})",
         bool(_SPECIAL_RE.search(password))),
    ])
    score = sum(checks.values())
    digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return PasswordResult(
        score=score,
        rating=RATING_BY_SCORE[score],
        sha256_hash=digest,
        checks=checks,
    )
