"""File integrity checking: SHA-256 baselines stored in data/hashes.json.

Files are hashed in streamed 1 MB chunks rather than read fully into
memory, so checking a large file doesn't spike RAM usage.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

DEFAULT_HASH_STORE = Path(__file__).resolve().parent.parent / "data" / "hashes.json"
_CHUNK_SIZE = 1024 * 1024  # 1 MB


@dataclass
class IntegrityResult:
    file_path: str
    current_hash: str
    baseline_hash: Optional[str]
    status: str  # "saved" | "safe" | "tampered" | "no_baseline"


def compute_sha256(file_path: str) -> str:
    digest = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


class HashStore:
    """Thin wrapper around the hashes.json baseline file."""

    def __init__(self, path: Path = DEFAULT_HASH_STORE):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _load(self) -> Dict[str, dict]:
        if not self.path.exists():
            return {}
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}

    def _save(self, data: Dict[str, dict]) -> None:
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def save_hash(self, file_path: str) -> IntegrityResult:
        digest = compute_sha256(file_path)
        data = self._load()
        data[file_path] = {
            "hash": digest,
            "saved_on": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        self._save(data)
        return IntegrityResult(file_path, digest, digest, "saved")

    def verify(self, file_path: str) -> IntegrityResult:
        digest = compute_sha256(file_path)
        entry = self._load().get(file_path)
        if entry is None:
            return IntegrityResult(file_path, digest, None, "no_baseline")
        baseline = entry["hash"]
        status = "safe" if digest == baseline else "tampered"
        return IntegrityResult(file_path, digest, baseline, status)

    def all_entries(self) -> Dict[str, dict]:
        return self._load()
