"""Append-only, hash-chained backup log. Any edit, deletion or reordering breaks the chain."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

GENESIS = "0" * 64


def _digest(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class Ledger:
    def __init__(self, path: Path):
        self.path = Path(path)

    def entries(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text().splitlines() if line.strip()]

    def append(self, record: dict) -> dict:
        entries = self.entries()
        entry = dict(record)
        entry["seq"] = len(entries)
        entry["prev_hash"] = entries[-1]["entry_hash"] if entries else GENESIS
        entry["entry_hash"] = _digest(entry)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def verify(self) -> tuple[bool, str]:
        prev = GENESIS
        for i, e in enumerate(self.entries()):
            if e.get("seq") != i:
                return False, f"entry {i}: sequence mismatch"
            if e.get("prev_hash") != prev:
                return False, f"entry {i}: chain broken"
            if _digest(e) != e.get("entry_hash"):
                return False, f"entry {i}: contents altered"
            prev = e["entry_hash"]
        return True, f"{len(self.entries())} entries verified"
