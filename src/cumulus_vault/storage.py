"""Storage backends: a local directory (testing/offline) and Filecoin via Lighthouse."""
from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path

import requests


class Backend:
    name = "base"

    def put(self, path: Path) -> str:
        raise NotImplementedError

    def get(self, ref: str, dest: Path) -> None:
        raise NotImplementedError


class LocalBackend(Backend):
    """Content-addressed local store. Useful for tests and air-gapped copies."""

    name = "local"

    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, path: Path) -> str:
        h = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        shutil.copyfile(path, self.root / h)
        return h

    def get(self, ref: str, dest: Path) -> None:
        shutil.copyfile(self.root / ref, dest)


class LighthouseBackend(Backend):
    """Stores archives on Filecoin through the Lighthouse storage onramp.

    Requires LIGHTHOUSE_API_KEY. Returns the IPFS CID; Lighthouse makes the Filecoin deals.
    """

    name = "lighthouse"
    UPLOAD = "https://node.lighthouse.storage/api/v0/add"
    GATEWAY = "https://gateway.lighthouse.storage/ipfs/"

    def __init__(self, api_key: str | None = None, timeout: int = 600):
        self.api_key = api_key or os.environ.get("LIGHTHOUSE_API_KEY")
        if not self.api_key:
            raise RuntimeError("Set LIGHTHOUSE_API_KEY to use the Filecoin backend")
        self.timeout = timeout

    def put(self, path: Path) -> str:
        with open(path, "rb") as f:
            r = requests.post(
                self.UPLOAD,
                headers={"Authorization": f"Bearer {self.api_key}"},
                files={"file": (Path(path).name, f)},
                timeout=self.timeout,
            )
        r.raise_for_status()
        return r.json()["Hash"]

    def get(self, ref: str, dest: Path) -> None:
        with requests.get(self.GATEWAY + ref, stream=True, timeout=self.timeout) as r:
            r.raise_for_status()
            with open(dest, "wb") as out:
                for chunk in r.iter_content(1 << 20):
                    out.write(chunk)


def make_backend(kind: str, local_root: Path) -> Backend:
    if kind == "local":
        return LocalBackend(local_root)
    if kind == "lighthouse":
        return LighthouseBackend()
    raise ValueError(f"unknown backend: {kind}")
