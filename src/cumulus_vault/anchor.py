"""Anchor the ledger head in Bitcoin with OpenTimestamps.

`cvault anchor` writes a small checkpoint file containing the current ledger head hash and
submits its SHA-256 to public OpenTimestamps calendars. The result is a standard `.ots` proof,
so anyone can confirm with the official client (`ots upgrade` then `ots verify`) that the ledger
existed at that time, after the calendars commit to Bitcoin (usually within a few hours).
This proves the backup history was not rewritten later, without trusting Infinitum or a storage provider.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import requests

# Standard OpenTimestamps file header (magic + version 1) and the SHA-256 operation tag.
HEADER = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94" + b"\x01"
OP_SHA256 = b"\x08"
OP_FORK = b"\xff"
CALENDARS = (
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://a.pool.eternitywall.com",
)


def submit(digest: bytes, calendars=CALENDARS, timeout: int = 20) -> list[bytes]:
    """Send the digest to each calendar. Returns the pending timestamps that succeeded."""
    stamps = []
    for url in calendars:
        try:
            r = requests.post(
                url.rstrip("/") + "/digest",
                data=digest,
                headers={"Accept": "application/vnd.opentimestamps.v1", "User-Agent": "cumulus-vault"},
                timeout=timeout,
            )
            if r.ok and r.content:
                stamps.append(r.content)
        except requests.RequestException:
            continue
    if not stamps:
        raise RuntimeError("no OpenTimestamps calendar accepted the digest")
    return stamps


def build_ots(digest: bytes, stamps: list[bytes]) -> bytes:
    """Combine calendar responses into one detached .ots proof (fork before all but the last)."""
    body = b"".join(OP_FORK + s for s in stamps[:-1]) + stamps[-1]
    return HEADER + OP_SHA256 + digest + body


def anchor(ledger_entries: list[dict], out_dir: Path, calendars=CALENDARS) -> tuple[Path, Path]:
    if not ledger_entries:
        raise LookupError("ledger is empty; nothing to anchor")
    head = ledger_entries[-1]
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    checkpoint = out_dir / f"checkpoint-{head['seq']:06d}.json"
    checkpoint.write_text(json.dumps({"seq": head["seq"], "ledger_head": head["entry_hash"]}, sort_keys=True) + "\n")
    digest = hashlib.sha256(checkpoint.read_bytes()).digest()
    proof = checkpoint.with_suffix(checkpoint.suffix + ".ots")
    proof.write_bytes(build_ots(digest, submit(digest, calendars)))
    return checkpoint, proof
