"""Backup, restore and verification workflows."""
from __future__ import annotations

import io
import os
import tarfile
import tempfile
import time
from pathlib import Path

from . import crypto
from .ledger import Ledger
from .storage import Backend


class Vault:
    """A vault lives in a directory holding the key file and the hash-chained ledger."""

    def __init__(self, home: Path, backend: Backend):
        self.home = Path(home)
        self.backend = backend
        self.key_path = self.home / "vault.key"
        self.ledger = Ledger(self.home / "ledger.jsonl")

    # --- keys -------------------------------------------------------------
    def init(self) -> Path:
        self.home.mkdir(parents=True, exist_ok=True)
        if self.key_path.exists():
            raise FileExistsError(f"key already exists: {self.key_path}")
        self.key_path.write_bytes(crypto.generate_key())
        os.chmod(self.key_path, 0o600)
        return self.key_path

    def _key(self) -> bytes:
        return self.key_path.read_bytes()

    # --- backup -----------------------------------------------------------
    def backup(self, source: Path, label: str | None = None) -> dict:
        source = Path(source)
        with tempfile.TemporaryDirectory() as td:
            tar_path = Path(td) / "payload.tar"
            with tarfile.open(tar_path, "w") as tar:
                tar.add(source, arcname=source.name)
            enc_path = Path(td) / "payload.cvault"
            with open(tar_path, "rb") as src, open(enc_path, "wb") as dst:
                plain_sha = crypto.encrypt_stream(self._key(), src, dst)
            ref = self.backend.put(enc_path)
            size = enc_path.stat().st_size
        return self.ledger.append({
            "type": "backup",
            "label": label or source.name,
            "source": str(source.resolve()),
            "backend": self.backend.name,
            "ref": ref,
            "plaintext_sha256": plain_sha,
            "encrypted_bytes": size,
            "created_at": int(time.time()),
        })

    # --- restore ----------------------------------------------------------
    def _find(self, seq: int | None) -> dict:
        backups = [e for e in self.ledger.entries() if e["type"] == "backup"]
        if not backups:
            raise LookupError("no backups recorded")
        if seq is None:
            return backups[-1]
        for e in backups:
            if e["seq"] == seq:
                return e
        raise LookupError(f"no backup with seq {seq}")

    def _fetch_plain(self, entry: dict, td: Path) -> tuple[Path, str]:
        enc = td / "fetched.cvault"
        self.backend.get(entry["ref"], enc)
        plain = td / "payload.tar"
        with open(enc, "rb") as src, open(plain, "wb") as dst:
            sha = crypto.decrypt_stream(self._key(), src, dst)
        return plain, sha

    def restore(self, dest: Path, seq: int | None = None) -> dict:
        entry = self._find(seq)
        with tempfile.TemporaryDirectory() as td:
            plain, sha = self._fetch_plain(entry, Path(td))
            if sha != entry["plaintext_sha256"]:
                raise crypto.DecryptionError("restored data does not match the recorded digest")
            Path(dest).mkdir(parents=True, exist_ok=True)
            with tarfile.open(plain) as tar:
                tar.extractall(dest, filter="data")  # blocks path traversal and special files
        return entry

    # --- verification -----------------------------------------------------
    def verify(self, seq: int | None = None, record: bool = True) -> dict:
        ok_chain, msg = self.ledger.verify()
        result = {"ledger_ok": ok_chain, "ledger": msg}
        try:
            entry = self._find(seq)
            with tempfile.TemporaryDirectory() as td:
                _, sha = self._fetch_plain(entry, Path(td))
            result.update(restore_ok=sha == entry["plaintext_sha256"], backup_seq=entry["seq"])
        except Exception as e:  # noqa: BLE001 - report any failure as a failed check
            result.update(restore_ok=False, error=str(e))
        if record and ok_chain:
            self.ledger.append({"type": "verify", "result": result, "created_at": int(time.time())})
        return result
